#![forbid(unsafe_code)]

use std::fmt;
use std::time::Duration;

use reqwest::header::{AUTHORIZATION, CACHE_CONTROL, HeaderValue, PRAGMA};
use serde::{Deserialize, Serialize};
use url::Url;
use zeroize::Zeroizing;

const AUDIENCE_HEADER: &str = "x-b10x-audience";

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("invalid Identity client configuration: {0}")]
    Configuration(&'static str),
    #[error("Identity request could not be completed")]
    Transport(#[source] reqwest::Error),
    #[error("Identity refused the credential")]
    Unauthorized,
    #[error("Identity refused the relying party")]
    Forbidden,
    #[error("Identity returned an unexpected status {0}")]
    UnexpectedStatus(u16),
    #[error("Identity returned a cacheable credential response")]
    CacheableCredentialResponse,
}

/// Public discovery facts for Identity's authorization-code flow.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LoginMetadata {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub access_token_endpoint: String,
    pub cli_client_id: String,
    pub response_types_supported: [String; 1],
    pub grant_types_supported: [String; 1],
    pub code_challenge_methods_supported: [String; 1],
}

/// Non-secret authority returned after Identity resolves an opaque session.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SessionAuthority {
    #[serde(rename = "iss")]
    pub issuer: String,
    #[serde(rename = "sub")]
    pub subject: String,
    #[serde(rename = "aud")]
    pub audience: String,
    #[serde(rename = "exp")]
    pub expires_at: i64,
    pub email: Option<String>,
    pub tenant_id: String,
    pub groups: Vec<String>,
}

/// Non-secret authority returned after Identity resolves a short-lived access credential.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AccessAuthority {
    #[serde(rename = "iss")]
    pub issuer: String,
    #[serde(rename = "sub")]
    pub subject: String,
    #[serde(rename = "aud")]
    pub audience: String,
    #[serde(rename = "iat")]
    pub issued_at: i64,
    #[serde(rename = "nbf")]
    pub not_before: i64,
    #[serde(rename = "exp")]
    pub expires_at: i64,
    #[serde(rename = "jti")]
    pub token_id: String,
    #[serde(rename = "act")]
    pub actor: AccessActor,
    pub scope: String,
    pub principal_kind: String,
    pub tenant_id: String,
    pub email: Option<String>,
    pub groups: Vec<String>,
}

/// Actor carried by an access authority without exposing its credential.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AccessActor {
    #[serde(rename = "sub")]
    pub subject: String,
}

/// One upstream sign-in identity explicitly linked to the current person.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IdentityLink {
    pub provider_id: String,
    pub issuer: String,
    pub email: Option<String>,
    pub linked_at: i64,
}

/// Browser destination for completing an authenticated identity-link operation.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IdentityLinkStart {
    pub authorization_url: String,
}

/// An opaque Identity session credential. Its allocation is wiped on drop and diagnostics never
/// expose it.
#[derive(Clone)]
pub struct SessionCredential(Zeroizing<String>);

impl SessionCredential {
    #[must_use]
    pub fn expose_at_cookie_boundary(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Debug for SessionCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionCredential([REDACTED])")
    }
}

#[derive(Debug, Clone)]
pub struct SessionExchange {
    pub credential: SessionCredential,
    pub expires_in: i64,
    pub tenant_id: String,
    pub subject: String,
    pub email: Option<String>,
}

/// A short-lived opaque access credential. Its allocation is wiped on drop and diagnostics never
/// expose it.
#[derive(Clone)]
pub struct AccessCredential(Zeroizing<String>);

impl AccessCredential {
    #[must_use]
    pub fn expose_at_authorization_boundary(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Debug for AccessCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AccessCredential([REDACTED])")
    }
}

#[derive(Debug, Clone)]
pub struct AccessToken {
    pub credential: AccessCredential,
    pub expires_in: i64,
    pub audience: String,
    pub scope: String,
}

#[derive(Serialize)]
struct AccessTokenRequest<'a> {
    audience: &'a str,
    scope: &'a str,
}

#[derive(Serialize)]
struct AccessExchangeRequest<'a> {
    source_audience: &'a str,
    audience: &'a str,
    scope: &'a str,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AccessTokenResponse {
    access_token: String,
    token_type: String,
    expires_in: i64,
    audience: String,
    scope: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionExchangeResponse {
    session: String,
    session_type: String,
    expires_in: i64,
    tenant_id: String,
    subject: String,
    email: Option<String>,
}

#[derive(Serialize)]
struct CodeExchangeRequest<'a> {
    grant_type: &'static str,
    client_id: &'a str,
    code: &'a str,
    redirect_uri: &'a str,
    code_verifier: &'a str,
}

/// Credential-safe HTTP client for one exact Identity origin and relying-party audience.
#[derive(Debug, Clone)]
pub struct IdentityClient {
    origin: Url,
    audience: String,
    http: reqwest::Client,
}

impl IdentityClient {
    /// Creates a client with redirects disabled and bounded request deadlines.
    ///
    /// # Errors
    ///
    /// Refuses origins carrying paths or credentials, non-HTTPS remote origins, malformed
    /// audiences, or failure to construct the HTTP client.
    pub fn new(origin: &str, audience: &str) -> Result<Self, ClientError> {
        let origin = Url::parse(origin)
            .map_err(|_| ClientError::Configuration("origin must be an absolute URL"))?;
        let internal_http = origin.scheme() == "http"
            && origin.host_str().is_some_and(|host| {
                host == "127.0.0.1" || host == "localhost" || host.ends_with(".svc.cluster.local")
            });
        if !(origin.scheme() == "https" || internal_http)
            || origin.host_str().is_none()
            || !origin.username().is_empty()
            || origin.password().is_some()
            || origin.path() != "/"
            || origin.query().is_some()
            || origin.fragment().is_some()
        {
            return Err(ClientError::Configuration(
                "origin must be an HTTPS origin or an internal cluster HTTP origin",
            ));
        }
        if audience.trim() != audience
            || !(3..=256).contains(&audience.len())
            || !audience.is_ascii()
            || audience
                .bytes()
                .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
        {
            return Err(ClientError::Configuration("audience is malformed"));
        }
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(ClientError::Transport)?;
        Ok(Self {
            origin,
            audience: audience.to_owned(),
            http,
        })
    }

    /// Reads public login discovery.
    ///
    /// # Errors
    ///
    /// Returns a typed error for transport, status or malformed response failures.
    pub async fn login_metadata(&self) -> Result<LoginMetadata, ClientError> {
        let response = self
            .http
            .get(self.endpoint(".well-known/identity-cli-login")?)
            .send()
            .await
            .map_err(ClientError::Transport)?;
        decode_public(response).await
    }

    /// Exchanges an authorization code and S256 verifier for an opaque Identity session.
    ///
    /// # Errors
    ///
    /// Returns a typed error without exposing the code, verifier or returned session.
    pub async fn exchange_code(
        &self,
        client_id: &str,
        code: &str,
        redirect_uri: &str,
        code_verifier: &str,
    ) -> Result<SessionExchange, ClientError> {
        let response = self
            .http
            .post(self.endpoint("oauth/token")?)
            .form(&CodeExchangeRequest {
                grant_type: "authorization_code",
                client_id,
                code,
                redirect_uri,
                code_verifier,
            })
            .send()
            .await
            .map_err(ClientError::Transport)?;
        require_confidential(&response)?;
        let response: SessionExchangeResponse = decode_status(response).await?;
        if response.session_type != "opaque_server_session"
            || response.expires_in <= 0
            || response.session.is_empty()
        {
            return Err(ClientError::UnexpectedStatus(502));
        }
        Ok(SessionExchange {
            credential: SessionCredential(Zeroizing::new(response.session)),
            expires_in: response.expires_in,
            tenant_id: response.tenant_id,
            subject: response.subject,
            email: response.email,
        })
    }

    /// Resolves an opaque Identity session for this client's exact audience.
    ///
    /// # Errors
    ///
    /// Returns a typed refusal for expired, revoked, malformed and wrong-audience sessions without
    /// carrying the credential or Identity's response body into diagnostics.
    pub async fn resolve_session(
        &self,
        authorization: &str,
    ) -> Result<SessionAuthority, ClientError> {
        let authorization = HeaderValue::from_str(authorization)
            .map_err(|_| ClientError::Configuration("authorization header is malformed"))?;
        let response = self
            .http
            .get(self.endpoint("v1/session-authority")?)
            .header(AUTHORIZATION, authorization)
            .header(AUDIENCE_HEADER, &self.audience)
            .send()
            .await
            .map_err(ClientError::Transport)?;
        require_confidential(&response)?;
        let authority: SessionAuthority = decode_status(response).await?;
        if authority.audience != self.audience {
            return Err(ClientError::Forbidden);
        }
        Ok(authority)
    }

    /// Resolves a short-lived access credential for one exact resource audience.
    ///
    /// # Errors
    ///
    /// Returns a typed refusal for expired, revoked, malformed and wrong-audience credentials
    /// without carrying the credential or Identity's response body into diagnostics.
    pub async fn resolve_access_token(
        &self,
        authorization: &str,
        audience: &str,
    ) -> Result<AccessAuthority, ClientError> {
        let authorization = HeaderValue::from_str(authorization)
            .map_err(|_| ClientError::Configuration("authorization header is malformed"))?;
        if audience.trim() != audience || audience.is_empty() || audience.len() > 512 {
            return Err(ClientError::Configuration("audience is malformed"));
        }
        let response = self
            .http
            .get(self.endpoint("v1/access-authority")?)
            .header(AUTHORIZATION, authorization)
            .header(AUDIENCE_HEADER, audience)
            .send()
            .await
            .map_err(ClientError::Transport)?;
        require_confidential(&response)?;
        let authority: AccessAuthority = decode_status(response).await?;
        if authority.audience != audience {
            return Err(ClientError::Forbidden);
        }
        Ok(authority)
    }

    /// Exchanges a live Identity session for a short-lived exact-audience access credential.
    ///
    /// # Errors
    ///
    /// Returns a typed error without exposing the session or returned access credential.
    pub async fn issue_access_token(
        &self,
        session_authorization: &str,
        audience: &str,
        scope: &str,
    ) -> Result<AccessToken, ClientError> {
        let authorization = HeaderValue::from_str(session_authorization)
            .map_err(|_| ClientError::Configuration("authorization header is malformed"))?;
        let response = self
            .http
            .post(self.endpoint("v1/access-token")?)
            .header(AUTHORIZATION, authorization)
            .json(&AccessTokenRequest { audience, scope })
            .send()
            .await
            .map_err(ClientError::Transport)?;
        require_confidential(&response)?;
        let response: AccessTokenResponse = decode_status(response).await?;
        if response.token_type != "Bearer"
            || response.expires_in <= 0
            || response.access_token.is_empty()
            || response.audience != audience
            || response.scope != scope
        {
            return Err(ClientError::UnexpectedStatus(502));
        }
        Ok(AccessToken {
            credential: AccessCredential(Zeroizing::new(response.access_token)),
            expires_in: response.expires_in,
            audience: response.audience,
            scope: response.scope,
        })
    }

    /// Exchanges a live source access token through one deployment-admitted confidential caller.
    ///
    /// The returned credential remains exact-audience and short-lived. Callers should inject the
    /// caller secret from deployment-owned secret material and never expose it to a browser.
    ///
    /// # Errors
    ///
    /// Returns a typed refusal for malformed credentials, callers, audiences, or policy denials.
    pub async fn exchange_access_token(
        &self,
        source_authorization: &str,
        caller_id: &str,
        caller_secret: &str,
        source_audience: &str,
        audience: &str,
        scope: &str,
    ) -> Result<AccessToken, ClientError> {
        let authorization = HeaderValue::from_str(source_authorization)
            .map_err(|_| ClientError::Configuration("authorization header is malformed"))?;
        let caller_id = HeaderValue::from_str(caller_id)
            .map_err(|_| ClientError::Configuration("exchange caller id is malformed"))?;
        let caller_secret = HeaderValue::from_str(caller_secret)
            .map_err(|_| ClientError::Configuration("exchange caller secret is malformed"))?;
        let response = self
            .http
            .post(self.endpoint("v1/access-exchange")?)
            .header(AUTHORIZATION, authorization)
            .header("x-b10x-access-exchange-caller", caller_id)
            .header("x-b10x-access-exchange-secret", caller_secret)
            .json(&AccessExchangeRequest {
                source_audience,
                audience,
                scope,
            })
            .send()
            .await
            .map_err(ClientError::Transport)?;
        require_confidential(&response)?;
        let response: AccessTokenResponse = decode_status(response).await?;
        if response.token_type != "Bearer"
            || response.expires_in <= 0
            || response.access_token.is_empty()
            || response.audience != audience
            || response.scope != scope
        {
            return Err(ClientError::UnexpectedStatus(502));
        }
        Ok(AccessToken {
            credential: AccessCredential(Zeroizing::new(response.access_token)),
            expires_in: response.expires_in,
            audience: response.audience,
            scope: response.scope,
        })
    }

    /// Lists the upstream identities explicitly linked to this session's person.
    /// # Errors
    ///
    /// Returns [`ClientError`] when the authenticated request is refused or unavailable.
    pub async fn identity_links(
        &self,
        session_authorization: &str,
    ) -> Result<Vec<IdentityLink>, ClientError> {
        let authorization = HeaderValue::from_str(session_authorization)
            .map_err(|_| ClientError::Configuration("authorization header is malformed"))?;
        let response = self
            .http
            .get(self.endpoint("v1/identity-links")?)
            .header(AUTHORIZATION, authorization)
            .header(AUDIENCE_HEADER, &self.audience)
            .send()
            .await
            .map_err(ClientError::Transport)?;
        require_confidential(&response)?;
        decode_status(response).await
    }

    /// Starts an upstream browser flow that links one provider to the authenticated person.
    /// # Errors
    ///
    /// Returns [`ClientError`] when the provider or authenticated session is refused.
    pub async fn start_identity_link(
        &self,
        session_authorization: &str,
        provider_id: &str,
    ) -> Result<IdentityLinkStart, ClientError> {
        let authorization = HeaderValue::from_str(session_authorization)
            .map_err(|_| ClientError::Configuration("authorization header is malformed"))?;
        let path = format!("v1/identity-links/{provider_id}");
        let response = self
            .http
            .post(self.endpoint(&path)?)
            .header(AUTHORIZATION, authorization)
            .header(AUDIENCE_HEADER, &self.audience)
            .send()
            .await
            .map_err(ClientError::Transport)?;
        require_confidential(&response)?;
        decode_status(response).await
    }

    /// Removes one linked provider while refusing to remove the final login method.
    /// # Errors
    ///
    /// Returns [`ClientError`] when the link cannot be removed or is the final login method.
    pub async fn remove_identity_link(
        &self,
        session_authorization: &str,
        provider_id: &str,
    ) -> Result<(), ClientError> {
        let authorization = HeaderValue::from_str(session_authorization)
            .map_err(|_| ClientError::Configuration("authorization header is malformed"))?;
        let path = format!("v1/identity-links/{provider_id}");
        let response = self
            .http
            .delete(self.endpoint(&path)?)
            .header(AUTHORIZATION, authorization)
            .header(AUDIENCE_HEADER, &self.audience)
            .send()
            .await
            .map_err(ClientError::Transport)?;
        match response.status().as_u16() {
            204 => Ok(()),
            401 => Err(ClientError::Unauthorized),
            403 => Err(ClientError::Forbidden),
            status => Err(ClientError::UnexpectedStatus(status)),
        }
    }

    fn endpoint(&self, path: &str) -> Result<Url, ClientError> {
        self.origin
            .join(path)
            .map_err(|_| ClientError::Configuration("Identity endpoint path is invalid"))
    }
}

fn require_confidential(response: &reqwest::Response) -> Result<(), ClientError> {
    let no_store = response
        .headers()
        .get(CACHE_CONTROL)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.split(',').any(|part| part.trim() == "no-store"));
    let no_cache = response
        .headers()
        .get(PRAGMA)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.split(',').any(|part| part.trim() == "no-cache"));
    if no_store && no_cache {
        Ok(())
    } else {
        Err(ClientError::CacheableCredentialResponse)
    }
}

async fn decode_public<T: for<'de> Deserialize<'de>>(
    response: reqwest::Response,
) -> Result<T, ClientError> {
    decode_status(response).await
}

async fn decode_status<T: for<'de> Deserialize<'de>>(
    response: reqwest::Response,
) -> Result<T, ClientError> {
    match response.status().as_u16() {
        200 => response.json().await.map_err(ClientError::Transport),
        401 => Err(ClientError::Unauthorized),
        403 => Err(ClientError::Forbidden),
        status => Err(ClientError::UnexpectedStatus(status)),
    }
}

#[cfg(test)]
mod tests {
    use axum::Router;
    use axum::extract::Json;
    use axum::http::{HeaderMap, StatusCode, header};
    use axum::response::{IntoResponse, Response};
    use axum::routing::{get, post};
    use serde_json::json;

    use super::*;

    async fn authority(headers: HeaderMap) -> Response {
        if headers.get(AUDIENCE_HEADER) != Some(&HeaderValue::from_static("urn:example:console")) {
            return StatusCode::FORBIDDEN.into_response();
        }
        let mut response = axum::Json(json!({
            "iss":"https://identity.example.test",
            "sub":"subject-1",
            "aud":"urn:example:console",
            "exp":4_102_444_800_i64,
            "email":"person@example.test",
            "tenant_id":"tenant-1",
            "groups":["member"]
        }))
        .into_response();
        response
            .headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        response
            .headers_mut()
            .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
        response
    }

    async fn access(headers: HeaderMap) -> Response {
        assert_eq!(
            headers.get(header::AUTHORIZATION),
            Some(&HeaderValue::from_static("Bearer synthetic-session"))
        );
        let mut response = axum::Json(json!({
            "access_token":"synthetic-access",
            "token_type":"Bearer",
            "expires_in":300,
            "audience":"urn:example:resource-api",
            "scope":"resource.read"
        }))
        .into_response();
        response
            .headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        response
            .headers_mut()
            .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
        response
    }

    async fn access_exchange(
        headers: HeaderMap,
        Json(request): Json<serde_json::Value>,
    ) -> Response {
        assert_eq!(
            headers.get(header::AUTHORIZATION),
            Some(&HeaderValue::from_static("Bearer synthetic-source-access"))
        );
        assert_eq!(
            headers.get("x-b10x-access-exchange-caller"),
            Some(&HeaderValue::from_static("service-a"))
        );
        assert_eq!(
            headers.get("x-b10x-access-exchange-secret"),
            Some(&HeaderValue::from_static(
                "synthetic-secret-with-thirty-two-bytes"
            ))
        );
        assert_eq!(request["source_audience"], "urn:example:published");
        assert_eq!(request["audience"], "urn:example:resource-api");
        assert_eq!(request["scope"], "resource.read");
        let mut response = axum::Json(json!({
            "access_token":"synthetic-exchanged-access",
            "token_type":"Bearer",
            "expires_in":300,
            "audience":"urn:example:resource-api",
            "scope":"resource.read"
        }))
        .into_response();
        response
            .headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        response
            .headers_mut()
            .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
        response
    }

    async fn access_authority(headers: HeaderMap) -> Response {
        assert_eq!(
            headers.get(header::AUTHORIZATION),
            Some(&HeaderValue::from_static("Bearer synthetic-access"))
        );
        assert_eq!(
            headers.get(AUDIENCE_HEADER),
            Some(&HeaderValue::from_static("urn:example:resource-api"))
        );
        let mut response = axum::Json(json!({
            "iss":"https://identity.example.test",
            "sub":"subject-1",
            "aud":"urn:example:resource-api",
            "iat":4_102_444_500_i64,
            "nbf":4_102_444_500_i64,
            "exp":4_102_444_800_i64,
            "jti":"identity_jti_v1_synthetic",
            "act":{"sub":"subject-1"},
            "scope":"resource.read",
            "principal_kind":"human",
            "tenant_id":"tenant-1",
            "email":"person@example.test",
            "groups":["member"]
        }))
        .into_response();
        response
            .headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        response
            .headers_mut()
            .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
        response
    }

    async fn token(
        headers: HeaderMap,
        axum::Form(request): axum::Form<std::collections::HashMap<String, String>>,
    ) -> Response {
        assert_eq!(
            headers.get(header::CONTENT_TYPE),
            Some(&HeaderValue::from_static(
                "application/x-www-form-urlencoded",
            ))
        );
        assert_eq!(request["grant_type"], "authorization_code");
        assert_eq!(request["client_id"], "console-web");
        let mut response = axum::Json(json!({
            "session":"identity_session_v1_synthetic",
            "session_type":"opaque_server_session",
            "expires_in":3600,
            "tenant_id":"tenant-1",
            "subject":"subject-1",
            "email":"person@example.test"
        }))
        .into_response();
        response
            .headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        response
            .headers_mut()
            .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
        response
    }

    async fn test_origin() -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(
                listener,
                Router::new()
                    .route("/v1/session-authority", get(authority))
                    .route("/v1/access-token", post(access))
                    .route("/v1/access-exchange", post(access_exchange))
                    .route("/v1/access-authority", get(access_authority))
                    .route("/oauth/token", post(token)),
            )
            .await
            .unwrap();
        });
        format!("http://127.0.0.1:{}/", address.port())
    }

    #[tokio::test]
    async fn exact_audience_authority_is_decoded_without_the_credential_in_debug() {
        let client = IdentityClient::new(&test_origin().await, "urn:example:console").unwrap();
        let authority = client
            .resolve_session("Bearer synthetic-session-that-is-never-recorded")
            .await
            .unwrap();
        assert_eq!(authority.tenant_id, "tenant-1");
        assert_eq!(authority.subject, "subject-1");
        assert!(!format!("{client:?}").contains("synthetic-session"));
    }

    #[tokio::test]
    async fn short_lived_access_credentials_are_exact_and_redacted() {
        let client = IdentityClient::new(&test_origin().await, "urn:example:console").unwrap();
        let access = client
            .issue_access_token(
                "Bearer synthetic-session",
                "urn:example:resource-api",
                "resource.read",
            )
            .await
            .unwrap();
        assert_eq!(access.expires_in, 300);
        assert_eq!(access.audience, "urn:example:resource-api");
        assert_eq!(access.scope, "resource.read");
        assert_eq!(
            format!("{:?}", access.credential),
            "AccessCredential([REDACTED])"
        );
    }

    #[tokio::test]
    async fn confidential_access_exchange_keeps_both_credentials_redacted() {
        let client = IdentityClient::new(&test_origin().await, "urn:example:console").unwrap();
        let access = client
            .exchange_access_token(
                "Bearer synthetic-source-access",
                "service-a",
                "synthetic-secret-with-thirty-two-bytes",
                "urn:example:published",
                "urn:example:resource-api",
                "resource.read",
            )
            .await
            .unwrap();
        assert_eq!(access.audience, "urn:example:resource-api");
        assert_eq!(access.scope, "resource.read");
        assert_eq!(
            format!("{:?}", access.credential),
            "AccessCredential([REDACTED])"
        );
        assert!(!format!("{client:?}").contains("synthetic-secret"));
    }

    #[tokio::test]
    async fn short_lived_access_authority_is_exact_and_credential_free() {
        let client = IdentityClient::new(&test_origin().await, "urn:example:console").unwrap();
        let authority = client
            .resolve_access_token("Bearer synthetic-access", "urn:example:resource-api")
            .await
            .unwrap();
        assert_eq!(authority.tenant_id, "tenant-1");
        assert_eq!(authority.subject, "subject-1");
        assert_eq!(authority.actor.subject, "subject-1");
        assert_eq!(authority.scope, "resource.read");
        assert!(!format!("{authority:?}").contains("synthetic-access"));
    }

    #[tokio::test]
    async fn browser_code_exchange_accepts_the_servers_opaque_session_type() {
        let client = IdentityClient::new(&test_origin().await, "urn:example:console").unwrap();
        let exchange = client
            .exchange_code(
                "console-web",
                "synthetic-code",
                "https://console.example.test/auth/sso/callback",
                "synthetic-verifier-with-the-required-length-1234567890",
            )
            .await
            .unwrap();
        assert_eq!(exchange.tenant_id, "tenant-1");
        assert_eq!(exchange.subject, "subject-1");
        assert_eq!(
            exchange.credential.expose_at_cookie_boundary(),
            "identity_session_v1_synthetic"
        );
    }

    #[test]
    fn remote_plaintext_and_malformed_audiences_are_refused() {
        assert!(IdentityClient::new("http://identity.example.test/", "urn:b10x:test").is_err());
        assert!(
            IdentityClient::new("https://identity.example.test/", "urn:b10x:bad value").is_err()
        );
    }

    #[test]
    fn session_credential_debug_is_redacted() {
        let credential = SessionCredential(Zeroizing::new("synthetic-secret".to_owned()));
        assert_eq!(format!("{credential:?}"), "SessionCredential([REDACTED])");
    }
}
