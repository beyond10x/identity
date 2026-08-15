#![forbid(unsafe_code)]

use std::collections::{BTreeSet, HashMap, HashSet};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use axum::Router;
use axum::extract::{Form, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{Html, IntoResponse, Json, Redirect, Response};
use axum::routing::{get, post};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use openidconnect::core::{
    CoreAuthenticationFlow, CoreClient, CoreGenderClaim, CoreJweContentEncryptionAlgorithm,
    CoreJwsSigningAlgorithm, CoreProviderMetadata,
};
use openidconnect::{
    AdditionalClaims, AuthorizationCode, ClientId, ClientSecret, CsrfToken, IdToken, IssuerUrl,
    Nonce, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope, TokenResponse,
};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use url::Url;

const LOGIN_LIFETIME_SECONDS: i64 = 10 * 60;
const CODE_LIFETIME_SECONDS: i64 = 60;
const SESSION_IDLE_SECONDS: i64 = 24 * 60 * 60;
const SESSION_ABSOLUTE_SECONDS: i64 = 30 * 24 * 60 * 60;
const CONNECTORS_AUDIENCE: &str = "daemonloom.connectors";

#[derive(Debug, Clone)]
pub struct Config {
    pub listen: SocketAddr,
    pub public_origin: Url,
    pub tenant_id: String,
    pub cli_client_id: String,
    pub upstream_issuer: String,
    pub upstream_client_id: String,
    pub upstream_client_secret: String,
    pub organization_domain_policy: OrganizationDomainPolicy,
    pub database_url: Option<String>,
    pub database_path: PathBuf,
}

/// Restricts logins using a domain claim from the cryptographically verified upstream ID token.
#[derive(Debug, Clone, Default)]
pub struct OrganizationDomainPolicy {
    claim: Option<String>,
    allowed_base_domains: Vec<String>,
}

impl OrganizationDomainPolicy {
    /// Builds a policy. The claim and domain list must either both be configured or both omitted.
    ///
    /// A configured base domain admits the exact domain and its DNS-label-bound subdomains.
    ///
    /// # Errors
    ///
    /// Returns an error for incomplete policies, invalid claim names, or invalid DNS domains.
    pub fn new(claim: Option<String>, allowed_base_domains: Vec<String>) -> Result<Self> {
        let claim = claim
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty());
        let mut normalized_domains = BTreeSet::new();
        for domain in allowed_base_domains {
            normalized_domains.insert(normalize_base_domain(&domain)?);
        }

        match (&claim, normalized_domains.is_empty()) {
            (None, true) => Ok(Self::default()),
            (Some(_), true) => bail!("an organization domain claim requires allowed base domains"),
            (None, false) => bail!("allowed organization base domains require a claim name"),
            (Some(name), false) => {
                if name.len() > 512 || name.chars().any(char::is_whitespace) {
                    bail!("organization domain claim must be a non-whitespace JSON claim name");
                }
                Ok(Self {
                    claim,
                    allowed_base_domains: normalized_domains.into_iter().collect(),
                })
            }
        }
    }

    fn admits(&self, claims: &HashMap<String, Value>) -> bool {
        let Some(claim) = self.claim.as_deref() else {
            return true;
        };
        let Some(domain) = claims.get(claim).and_then(Value::as_str) else {
            return false;
        };
        let domain = domain.to_ascii_lowercase();
        self.allowed_base_domains.iter().any(|base| {
            domain == *base
                || domain
                    .strip_suffix(base)
                    .is_some_and(|prefix| prefix.ends_with('.'))
        })
    }
}

fn normalize_base_domain(value: &str) -> Result<String> {
    let domain = value.trim().to_ascii_lowercase();
    if domain.is_empty() || domain.len() > 253 || domain.ends_with('.') || !domain.is_ascii() {
        bail!("organization base domain must be an ASCII DNS name without a trailing dot");
    }
    for label in domain.split('.') {
        if label.is_empty()
            || label.len() > 63
            || !label
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphanumeric)
            || !label
                .as_bytes()
                .last()
                .is_some_and(u8::is_ascii_alphanumeric)
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            bail!("organization base domain contains an invalid DNS label");
        }
    }
    Ok(domain)
}

#[derive(Debug, Deserialize, Serialize)]
struct UpstreamAdditionalClaims(HashMap<String, Value>);

impl AdditionalClaims for UpstreamAdditionalClaims {}

type UpstreamIdToken = IdToken<
    UpstreamAdditionalClaims,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJwsSigningAlgorithm,
>;

#[derive(Clone)]
pub struct AppState {
    config: Arc<Config>,
    upstream: Arc<CoreProviderMetadata>,
    http_client: openidconnect::reqwest::Client,
    store: Store,
}

impl AppState {
    #[must_use]
    pub fn new(
        config: Arc<Config>,
        upstream: CoreProviderMetadata,
        http_client: openidconnect::reqwest::Client,
        store: Store,
    ) -> Self {
        Self {
            config,
            upstream: Arc::new(upstream),
            http_client,
            store,
        }
    }
}

#[derive(Clone)]
pub enum Store {
    Sqlite(Arc<Mutex<Connection>>),
    Postgres(Arc<tokio_postgres::Client>),
}

impl Store {
    /// Opens or creates the identity database and applies the local schema.
    ///
    /// # Errors
    ///
    /// Returns an error when the parent directory, database, or schema cannot be created.
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create identity data directory {}", parent.display()))?;
        }
        let connection = Connection::open(path)
            .with_context(|| format!("open identity database {}", path.display()))?;
        Self::from_sqlite_connection(connection)
    }

    /// Connects to `PostgreSQL` and applies the identity schema.
    ///
    /// # Errors
    ///
    /// Returns an error when the database cannot be connected or initialized.
    pub async fn connect_postgres(url: &str) -> Result<Self> {
        let tls = tokio_postgres_rustls::MakeRustlsConnect::with_webpki_roots();
        let (client, connection) = tokio_postgres::connect(url, tls)
            .await
            .context("connect to identity PostgreSQL database")?;
        tokio::spawn(async move {
            if let Err(error) = connection.await {
                tracing::error!(%error, "identity PostgreSQL connection failed");
            }
        });
        client
            .batch_execute(
                "CREATE TABLE IF NOT EXISTS login_transactions (
                   upstream_state TEXT PRIMARY KEY,
                   created_at BIGINT NOT NULL,
                   client_id TEXT NOT NULL,
                   redirect_uri TEXT NOT NULL,
                   client_state TEXT NOT NULL,
                   client_nonce TEXT NOT NULL,
                   client_code_challenge TEXT NOT NULL,
                   upstream_nonce TEXT NOT NULL,
                   upstream_pkce_verifier TEXT NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS authorization_codes (
                   code_hash BYTEA PRIMARY KEY,
                   created_at BIGINT NOT NULL,
                   client_id TEXT NOT NULL,
                   redirect_uri TEXT NOT NULL,
                   code_challenge TEXT NOT NULL,
                   subject TEXT NOT NULL,
                   email TEXT
                 );
                 CREATE TABLE IF NOT EXISTS sessions (
                   verifier_hash BYTEA PRIMARY KEY,
                   tenant_id TEXT NOT NULL,
                   subject TEXT NOT NULL,
                   email TEXT,
                   created_at BIGINT NOT NULL,
                   last_used_at BIGINT NOT NULL,
                   idle_expires_at BIGINT NOT NULL,
                   absolute_expires_at BIGINT NOT NULL,
                   revoked_at BIGINT
                 );",
            )
            .await
            .context("initialize identity PostgreSQL schema")?;
        Ok(Self::Postgres(Arc::new(client)))
    }

    /// Creates an isolated in-memory store for tests.
    ///
    /// # Errors
    ///
    /// Returns an error when `SQLite` cannot create or initialize the database.
    pub fn in_memory() -> Result<Self> {
        Self::from_sqlite_connection(Connection::open_in_memory()?)
    }

    fn from_sqlite_connection(connection: Connection) -> Result<Self> {
        connection.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA foreign_keys=ON;
             CREATE TABLE IF NOT EXISTS login_transactions (
               upstream_state TEXT PRIMARY KEY,
               created_at INTEGER NOT NULL,
               client_id TEXT NOT NULL,
               redirect_uri TEXT NOT NULL,
               client_state TEXT NOT NULL,
               client_nonce TEXT NOT NULL,
               client_code_challenge TEXT NOT NULL,
               upstream_nonce TEXT NOT NULL,
               upstream_pkce_verifier TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS authorization_codes (
               code_hash BLOB PRIMARY KEY,
               created_at INTEGER NOT NULL,
               client_id TEXT NOT NULL,
               redirect_uri TEXT NOT NULL,
               code_challenge TEXT NOT NULL,
               subject TEXT NOT NULL,
               email TEXT
             );
             CREATE TABLE IF NOT EXISTS sessions (
               verifier_hash BLOB PRIMARY KEY,
               tenant_id TEXT NOT NULL,
               subject TEXT NOT NULL,
               email TEXT,
               created_at INTEGER NOT NULL,
               last_used_at INTEGER NOT NULL,
               idle_expires_at INTEGER NOT NULL,
               absolute_expires_at INTEGER NOT NULL,
               revoked_at INTEGER
             );",
        )?;
        Ok(Self::Sqlite(Arc::new(Mutex::new(connection))))
    }

    async fn put_login(&self, login: &LoginTransaction) -> Result<()> {
        match self {
            Self::Sqlite(_) => {
                self.sqlite_connection()?.execute(
                    "INSERT INTO login_transactions (
                       upstream_state, created_at, client_id, redirect_uri, client_state, client_nonce,
                       client_code_challenge, upstream_nonce, upstream_pkce_verifier
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                    params![
                        login.upstream_state,
                        login.created_at,
                        login.client_id,
                        login.redirect_uri,
                        login.client_state,
                        login.client_nonce,
                        login.client_code_challenge,
                        login.upstream_nonce,
                        login.upstream_pkce_verifier,
                    ],
                )?;
            }
            Self::Postgres(client) => {
                client
                    .execute(
                        "INSERT INTO login_transactions (
                           upstream_state, created_at, client_id, redirect_uri, client_state,
                           client_nonce, client_code_challenge, upstream_nonce, upstream_pkce_verifier
                         ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
                        &[
                            &login.upstream_state,
                            &login.created_at,
                            &login.client_id,
                            &login.redirect_uri,
                            &login.client_state,
                            &login.client_nonce,
                            &login.client_code_challenge,
                            &login.upstream_nonce,
                            &login.upstream_pkce_verifier,
                        ],
                    )
                    .await?;
            }
        }
        Ok(())
    }

    async fn take_login(&self, state: &str) -> Result<Option<LoginTransaction>> {
        match self {
            Self::Sqlite(_) => self
                .sqlite_connection()?
                .query_row(
                    "DELETE FROM login_transactions WHERE upstream_state = ?1
                     RETURNING upstream_state, created_at, client_id, redirect_uri, client_state,
                               client_nonce, client_code_challenge, upstream_nonce, upstream_pkce_verifier",
                    [state],
                    |row| {
                        Ok(LoginTransaction {
                            upstream_state: row.get(0)?,
                            created_at: row.get(1)?,
                            client_id: row.get(2)?,
                            redirect_uri: row.get(3)?,
                            client_state: row.get(4)?,
                            client_nonce: row.get(5)?,
                            client_code_challenge: row.get(6)?,
                            upstream_nonce: row.get(7)?,
                            upstream_pkce_verifier: row.get(8)?,
                        })
                    },
                )
                .optional()
                .map_err(Into::into),
            Self::Postgres(client) => client
                .query_opt(
                    "DELETE FROM login_transactions WHERE upstream_state = $1
                     RETURNING upstream_state, created_at, client_id, redirect_uri, client_state,
                               client_nonce, client_code_challenge, upstream_nonce, upstream_pkce_verifier",
                    &[&state],
                )
                .await
                .map(|row| {
                    row.map(|row| LoginTransaction {
                        upstream_state: row.get(0),
                        created_at: row.get(1),
                        client_id: row.get(2),
                        redirect_uri: row.get(3),
                        client_state: row.get(4),
                        client_nonce: row.get(5),
                        client_code_challenge: row.get(6),
                        upstream_nonce: row.get(7),
                        upstream_pkce_verifier: row.get(8),
                    })
                })
                .map_err(Into::into),
        }
    }

    async fn put_code(&self, code: &str, authorization: &PendingAuthorization) -> Result<()> {
        let digest = hash(code);
        match self {
            Self::Sqlite(_) => {
                self.sqlite_connection()?.execute(
                    "INSERT INTO authorization_codes (
                       code_hash, created_at, client_id, redirect_uri, code_challenge, subject, email
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    params![
                        digest,
                        authorization.created_at,
                        authorization.client_id,
                        authorization.redirect_uri,
                        authorization.code_challenge,
                        authorization.subject,
                        authorization.email,
                    ],
                )?;
            }
            Self::Postgres(client) => {
                client
                    .execute(
                        "INSERT INTO authorization_codes (
                           code_hash, created_at, client_id, redirect_uri, code_challenge, subject, email
                         ) VALUES ($1, $2, $3, $4, $5, $6, $7)",
                        &[
                            &digest,
                            &authorization.created_at,
                            &authorization.client_id,
                            &authorization.redirect_uri,
                            &authorization.code_challenge,
                            &authorization.subject,
                            &authorization.email,
                        ],
                    )
                    .await?;
            }
        }
        Ok(())
    }

    async fn take_code(&self, code: &str) -> Result<Option<PendingAuthorization>> {
        let digest = hash(code);
        match self {
            Self::Sqlite(_) => self
                .sqlite_connection()?
                .query_row(
                    "DELETE FROM authorization_codes WHERE code_hash = ?1
                     RETURNING created_at, client_id, redirect_uri, code_challenge, subject, email",
                    [digest.as_slice()],
                    |row| {
                        Ok(PendingAuthorization {
                            created_at: row.get(0)?,
                            client_id: row.get(1)?,
                            redirect_uri: row.get(2)?,
                            code_challenge: row.get(3)?,
                            subject: row.get(4)?,
                            email: row.get(5)?,
                        })
                    },
                )
                .optional()
                .map_err(Into::into),
            Self::Postgres(client) => client
                .query_opt(
                    "DELETE FROM authorization_codes WHERE code_hash = $1
                     RETURNING created_at, client_id, redirect_uri, code_challenge, subject, email",
                    &[&digest],
                )
                .await
                .map(|row| {
                    row.map(|row| PendingAuthorization {
                        created_at: row.get(0),
                        client_id: row.get(1),
                        redirect_uri: row.get(2),
                        code_challenge: row.get(3),
                        subject: row.get(4),
                        email: row.get(5),
                    })
                })
                .map_err(Into::into),
        }
    }

    async fn put_session(
        &self,
        credential: &str,
        config: &Config,
        identity: &Identity,
    ) -> Result<()> {
        let now = unix_time()?;
        let digest = hash(credential);
        let idle_expires_at = now + SESSION_IDLE_SECONDS;
        let absolute_expires_at = now + SESSION_ABSOLUTE_SECONDS;
        match self {
            Self::Sqlite(_) => {
                self.sqlite_connection()?.execute(
                    "INSERT INTO sessions (
                       verifier_hash, tenant_id, subject, email, created_at, last_used_at,
                       idle_expires_at, absolute_expires_at, revoked_at
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?5, ?6, ?7, NULL)",
                    params![
                        digest.as_slice(),
                        config.tenant_id,
                        identity.subject,
                        identity.email,
                        now,
                        idle_expires_at,
                        absolute_expires_at,
                    ],
                )?;
            }
            Self::Postgres(client) => {
                client
                    .execute(
                        "INSERT INTO sessions (
                           verifier_hash, tenant_id, subject, email, created_at, last_used_at,
                           idle_expires_at, absolute_expires_at, revoked_at
                         ) VALUES ($1, $2, $3, $4, $5, $5, $6, $7, NULL)",
                        &[
                            &digest,
                            &config.tenant_id,
                            &identity.subject,
                            &identity.email,
                            &now,
                            &idle_expires_at,
                            &absolute_expires_at,
                        ],
                    )
                    .await?;
            }
        }
        Ok(())
    }

    async fn resolve_session(&self, credential: &str) -> Result<Option<AdmittedSession>> {
        let now = unix_time()?;
        let digest = hash(credential);
        let idle_expires_at = now + SESSION_IDLE_SECONDS;
        match self {
            Self::Sqlite(_) => self
                .sqlite_connection()?
                .query_row(
                    "UPDATE sessions
                     SET last_used_at = ?2,
                         idle_expires_at = min(?3, absolute_expires_at)
                     WHERE verifier_hash = ?1
                       AND revoked_at IS NULL
                       AND idle_expires_at > ?2
                       AND absolute_expires_at > ?2
                     RETURNING tenant_id, subject, email, idle_expires_at",
                    params![digest.as_slice(), now, idle_expires_at],
                    |row| {
                        Ok(AdmittedSession {
                            tenant_id: row.get(0)?,
                            subject: row.get(1)?,
                            email: row.get(2)?,
                            expires_at: row.get(3)?,
                        })
                    },
                )
                .optional()
                .map_err(Into::into),
            Self::Postgres(client) => client
                .query_opt(
                    "UPDATE sessions
                     SET last_used_at = $2,
                         idle_expires_at = LEAST($3, absolute_expires_at)
                     WHERE verifier_hash = $1
                       AND revoked_at IS NULL
                       AND idle_expires_at > $2
                       AND absolute_expires_at > $2
                     RETURNING tenant_id, subject, email, idle_expires_at",
                    &[&digest, &now, &idle_expires_at],
                )
                .await
                .map(|row| {
                    row.map(|row| AdmittedSession {
                        tenant_id: row.get(0),
                        subject: row.get(1),
                        email: row.get(2),
                        expires_at: row.get(3),
                    })
                })
                .map_err(Into::into),
        }
    }

    fn sqlite_connection(&self) -> Result<std::sync::MutexGuard<'_, Connection>> {
        match self {
            Self::Sqlite(connection) => connection
                .lock()
                .map_err(|_| anyhow::anyhow!("identity database lock poisoned")),
            Self::Postgres(_) => Err(anyhow::anyhow!("identity store is not SQLite")),
        }
    }
}

#[derive(Debug)]
struct LoginTransaction {
    upstream_state: String,
    created_at: i64,
    client_id: String,
    redirect_uri: String,
    client_state: String,
    client_nonce: String,
    client_code_challenge: String,
    upstream_nonce: String,
    upstream_pkce_verifier: String,
}

#[derive(Debug)]
struct PendingAuthorization {
    created_at: i64,
    client_id: String,
    redirect_uri: String,
    code_challenge: String,
    subject: String,
    email: Option<String>,
}

#[derive(Debug)]
struct Identity {
    subject: String,
    email: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AuthorizeQuery {
    response_type: String,
    client_id: String,
    redirect_uri: String,
    scope: String,
    state: String,
    nonce: String,
    code_challenge: String,
    code_challenge_method: String,
}

#[derive(Debug, Deserialize)]
struct UpstreamCallback {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TokenRequest {
    grant_type: String,
    client_id: String,
    code: String,
    redirect_uri: String,
    code_verifier: String,
}

#[derive(Debug, Serialize)]
struct LoginMetadata {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    cli_client_id: String,
    response_types_supported: [&'static str; 1],
    grant_types_supported: [&'static str; 1],
    code_challenge_methods_supported: [&'static str; 1],
}

#[derive(Debug, Serialize)]
struct SessionResponse {
    session: String,
    session_type: &'static str,
    expires_in: i64,
    tenant_id: String,
    subject: String,
    email: Option<String>,
}

#[derive(Debug)]
struct AdmittedSession {
    tenant_id: String,
    subject: String,
    email: Option<String>,
    expires_at: i64,
}

#[derive(Debug, Serialize)]
struct SessionVerificationResponse {
    active: bool,
    audience: &'static str,
    tenant_id: String,
    subject: String,
    email: Option<String>,
    expires_in: i64,
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    error: &'static str,
    error_description: String,
}

#[derive(Debug)]
struct HttpError {
    status: StatusCode,
    code: &'static str,
    message: String,
}

impl HttpError {
    fn invalid(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code: "invalid_request",
            message: message.into(),
        }
    }

    fn denied(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            code: "access_denied",
            message: message.into(),
        }
    }

    fn internal(error: impl std::fmt::Display) -> Self {
        tracing::error!(error = %error, "identity request failed");
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: "server_error",
            message: "identity service could not complete the request".to_owned(),
        }
    }
}

impl IntoResponse for HttpError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(ErrorBody {
                error: self.code,
                error_description: self.message,
            }),
        )
            .into_response()
    }
}

/// Discovers and validates the configured upstream `OpenID Connect` issuer metadata.
///
/// # Errors
///
/// Returns an error for an invalid issuer URL, failed discovery request, or invalid metadata.
pub async fn discover_upstream(
    config: &Config,
    client: &openidconnect::reqwest::Client,
) -> Result<CoreProviderMetadata> {
    CoreProviderMetadata::discover_async(
        IssuerUrl::new(config.upstream_issuer.clone()).context("upstream issuer URL")?,
        client,
    )
    .await
    .context("discover upstream OpenID Connect issuer")
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(health))
        .route("/.well-known/daemonloom-cli-login", get(login_metadata))
        .route("/oauth/authorize", get(authorize))
        .route("/oauth/callback/upstream", get(upstream_callback))
        .route("/oauth/token", post(exchange_token))
        .route("/v1/session", get(verify_session))
        .with_state(state)
}

async fn health() -> &'static str {
    "ok\n"
}

async fn login_metadata(State(state): State<AppState>) -> Json<LoginMetadata> {
    let origin = state.config.public_origin.as_str().trim_end_matches('/');
    Json(LoginMetadata {
        issuer: origin.to_owned(),
        authorization_endpoint: format!("{origin}/oauth/authorize"),
        token_endpoint: format!("{origin}/oauth/token"),
        cli_client_id: state.config.cli_client_id.clone(),
        response_types_supported: ["code"],
        grant_types_supported: ["authorization_code"],
        code_challenge_methods_supported: ["S256"],
    })
}

async fn verify_session(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<SessionVerificationResponse>, HttpError> {
    let audience = headers
        .get("x-daemonloom-audience")
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| HttpError::denied("an exact Daemonloom audience is required"))?;
    if audience != CONNECTORS_AUDIENCE {
        return Err(HttpError::denied("the requested audience is not admitted"));
    }
    let credential = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .filter(|value| valid_session_credential(value))
        .ok_or_else(|| HttpError::denied("a valid Identity session is required"))?;
    let admitted = state
        .store
        .resolve_session(credential)
        .await
        .map_err(HttpError::internal)?
        .ok_or_else(|| HttpError::denied("the Identity session is expired or revoked"))?;
    let now = unix_time().map_err(HttpError::internal)?;
    Ok(Json(SessionVerificationResponse {
        active: true,
        audience: CONNECTORS_AUDIENCE,
        tenant_id: admitted.tenant_id,
        subject: admitted.subject,
        email: admitted.email,
        expires_in: admitted.expires_at.saturating_sub(now),
    }))
}

async fn authorize(
    State(state): State<AppState>,
    Query(query): Query<AuthorizeQuery>,
) -> Result<Redirect, HttpError> {
    validate_authorization_request(&state.config, &query)?;
    let upstream_state = random_token(32).map_err(HttpError::internal)?;
    let upstream_nonce = random_token(32).map_err(HttpError::internal)?;
    let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
    let callback = state
        .config
        .public_origin
        .join("oauth/callback/upstream")
        .map_err(HttpError::internal)?;
    let client = CoreClient::from_provider_metadata(
        (*state.upstream).clone(),
        ClientId::new(state.config.upstream_client_id.clone()),
        Some(ClientSecret::new(
            state.config.upstream_client_secret.clone(),
        )),
    )
    .set_redirect_uri(RedirectUrl::new(callback.to_string()).map_err(HttpError::internal)?);
    let (authorization_url, _, _) = client
        .authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            {
                let value = upstream_state.clone();
                move || CsrfToken::new(value)
            },
            {
                let value = upstream_nonce.clone();
                move || Nonce::new(value)
            },
        )
        .add_scope(Scope::new("email".to_owned()))
        .add_scope(Scope::new("profile".to_owned()))
        .set_pkce_challenge(challenge)
        .url();
    state
        .store
        .put_login(&LoginTransaction {
            upstream_state,
            created_at: unix_time().map_err(HttpError::internal)?,
            client_id: query.client_id,
            redirect_uri: query.redirect_uri,
            client_state: query.state,
            client_nonce: query.nonce,
            client_code_challenge: query.code_challenge,
            upstream_nonce,
            upstream_pkce_verifier: verifier.secret().clone(),
        })
        .await
        .map_err(HttpError::internal)?;
    Ok(Redirect::temporary(authorization_url.as_str()))
}

async fn upstream_callback(
    State(state): State<AppState>,
    Query(query): Query<UpstreamCallback>,
) -> Result<Response, HttpError> {
    if let Some(error) = query.error {
        return Ok((
            StatusCode::UNAUTHORIZED,
            Html(format!(
                "<!doctype html><title>Login refused</title><h1>Login refused</h1><p>{}</p>",
                html_escape(&error)
            )),
        )
            .into_response());
    }
    let returned_state = query
        .state
        .ok_or_else(|| HttpError::invalid("missing state"))?;
    let login = state
        .store
        .take_login(&returned_state)
        .await
        .map_err(HttpError::internal)?
        .ok_or_else(|| HttpError::denied("unknown or already-used login state"))?;
    if unix_time().map_err(HttpError::internal)? - login.created_at > LOGIN_LIFETIME_SECONDS {
        return Err(HttpError::denied("login state expired"));
    }
    let code = query
        .code
        .ok_or_else(|| HttpError::invalid("missing authorization code"))?;
    let callback = state
        .config
        .public_origin
        .join("oauth/callback/upstream")
        .map_err(HttpError::internal)?;
    let client = CoreClient::from_provider_metadata(
        (*state.upstream).clone(),
        ClientId::new(state.config.upstream_client_id.clone()),
        Some(ClientSecret::new(
            state.config.upstream_client_secret.clone(),
        )),
    )
    .set_redirect_uri(RedirectUrl::new(callback.to_string()).map_err(HttpError::internal)?);
    let response = client
        .exchange_code(AuthorizationCode::new(code))
        .map_err(HttpError::internal)?
        .set_pkce_verifier(PkceCodeVerifier::new(login.upstream_pkce_verifier))
        .request_async(&state.http_client)
        .await
        .map_err(HttpError::internal)?;
    let core_id_token = response
        .id_token()
        .ok_or_else(|| HttpError::denied("upstream issuer returned no OpenID Connect ID token"))?;
    // Reparse the token with catch-all additional claims, then verify the same signed JWT before
    // consulting a deployment-selected organization claim such as Google's `hd` claim.
    let id_token = core_id_token
        .to_string()
        .parse::<UpstreamIdToken>()
        .map_err(|_| HttpError::denied("upstream ID token could not be decoded"))?;
    let claims = id_token
        .claims(
            &client.id_token_verifier(),
            &Nonce::new(login.upstream_nonce),
        )
        .map_err(|_| HttpError::denied("upstream ID token validation failed"))?;
    if !state
        .config
        .organization_domain_policy
        .admits(&claims.additional_claims().0)
    {
        return Err(HttpError::denied(
            "upstream organization is not admitted by this deployment",
        ));
    }
    if claims.email().is_some() && claims.email_verified() != Some(true) {
        return Err(HttpError::denied("upstream email address is not verified"));
    }
    let identity = Identity {
        subject: claims.subject().as_str().to_owned(),
        email: claims.email().map(|email| email.as_str().to_owned()),
    };
    let client_code = random_token(32).map_err(HttpError::internal)?;
    state
        .store
        .put_code(
            &client_code,
            &PendingAuthorization {
                created_at: unix_time().map_err(HttpError::internal)?,
                client_id: login.client_id,
                redirect_uri: login.redirect_uri.clone(),
                code_challenge: login.client_code_challenge,
                subject: identity.subject,
                email: identity.email,
            },
        )
        .await
        .map_err(HttpError::internal)?;
    let mut redirect = Url::parse(&login.redirect_uri).map_err(HttpError::internal)?;
    redirect
        .query_pairs_mut()
        .append_pair("code", &client_code)
        .append_pair("state", &login.client_state);
    Ok(Redirect::to(redirect.as_str()).into_response())
}

async fn exchange_token(
    State(state): State<AppState>,
    Form(request): Form<TokenRequest>,
) -> Result<Json<SessionResponse>, HttpError> {
    if request.grant_type != "authorization_code" {
        return Err(HttpError::invalid("grant_type must be authorization_code"));
    }
    if !valid_pkce_verifier(&request.code_verifier) {
        return Err(HttpError::invalid("invalid PKCE code_verifier"));
    }
    let authorization = state
        .store
        .take_code(&request.code)
        .await
        .map_err(HttpError::internal)?
        .ok_or_else(|| HttpError::denied("unknown or already-used authorization code"))?;
    let now = unix_time().map_err(HttpError::internal)?;
    if now - authorization.created_at > CODE_LIFETIME_SECONDS
        || request.client_id != authorization.client_id
        || request.redirect_uri != authorization.redirect_uri
        || pkce_challenge(&request.code_verifier) != authorization.code_challenge
    {
        return Err(HttpError::denied("authorization code binding failed"));
    }
    let credential = format!(
        "dl_session_v1_{}",
        random_token(32).map_err(HttpError::internal)?
    );
    let identity = Identity {
        subject: authorization.subject,
        email: authorization.email,
    };
    state
        .store
        .put_session(&credential, &state.config, &identity)
        .await
        .map_err(HttpError::internal)?;
    Ok(Json(SessionResponse {
        session: credential,
        session_type: "opaque_server_session",
        expires_in: SESSION_IDLE_SECONDS,
        tenant_id: state.config.tenant_id.clone(),
        subject: identity.subject,
        email: identity.email,
    }))
}

fn validate_authorization_request(
    config: &Config,
    query: &AuthorizeQuery,
) -> Result<(), HttpError> {
    if query.response_type != "code" {
        return Err(HttpError::invalid("response_type must be code"));
    }
    if query.client_id != config.cli_client_id {
        return Err(HttpError::denied("unknown client_id"));
    }
    validate_loopback_redirect(&query.redirect_uri)?;
    let scopes = query.scope.split_ascii_whitespace().collect::<HashSet<_>>();
    if !scopes.contains("openid") {
        return Err(HttpError::invalid("scope must contain openid"));
    }
    if query.code_challenge_method != "S256" || !valid_b64_token(&query.code_challenge, 43, 43) {
        return Err(HttpError::invalid(
            "a valid S256 PKCE challenge is required",
        ));
    }
    if !valid_b64_token(&query.state, 32, 512) || !valid_b64_token(&query.nonce, 32, 512) {
        return Err(HttpError::invalid(
            "state and nonce must carry at least 192 bits",
        ));
    }
    Ok(())
}

fn validate_loopback_redirect(value: &str) -> Result<(), HttpError> {
    let url = Url::parse(value).map_err(|_| HttpError::invalid("redirect_uri is not a URL"))?;
    let loopback = matches!(url.host_str(), Some("127.0.0.1" | "::1"));
    if url.scheme() != "http"
        || !loopback
        || url.port().is_none()
        || url.path() != "/callback"
        || url.query().is_some()
        || url.fragment().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(HttpError::invalid(
            "redirect_uri must be the exact http loopback /callback URI with an ephemeral port",
        ));
    }
    Ok(())
}

fn valid_pkce_verifier(value: &str) -> bool {
    let valid =
        |byte: &u8| byte.is_ascii_alphanumeric() || matches!(*byte, b'-' | b'.' | b'_' | b'~');
    (43..=128).contains(&value.len()) && value.as_bytes().iter().all(valid)
}

fn valid_b64_token(value: &str, minimum: usize, maximum: usize) -> bool {
    (minimum..=maximum).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn valid_session_credential(value: &str) -> bool {
    value
        .strip_prefix("dl_session_v1_")
        .is_some_and(|token| valid_b64_token(token, 43, 43))
}

fn pkce_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(hash(verifier))
}

fn random_token(bytes: usize) -> Result<String> {
    let mut value = vec![0_u8; bytes];
    getrandom::fill(&mut value)
        .map_err(|error| anyhow::anyhow!("obtain operating-system randomness: {error}"))?;
    Ok(URL_SAFE_NO_PAD.encode(value))
}

fn hash(value: &str) -> Vec<u8> {
    Sha256::digest(value.as_bytes()).to_vec()
}

fn unix_time() -> Result<i64> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before Unix epoch")?
        .as_secs();
    i64::try_from(seconds).context("system time does not fit in i64")
}

fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> Config {
        Config {
            listen: "127.0.0.1:0".parse().unwrap(),
            public_origin: Url::parse("http://127.0.0.1:8080/").unwrap(),
            tenant_id: "tenant-dev".to_owned(),
            cli_client_id: "daemonloom-harness-cli".to_owned(),
            upstream_issuer: "https://accounts.example.test".to_owned(),
            upstream_client_id: "upstream-client".to_owned(),
            upstream_client_secret: "not-a-real-secret".to_owned(),
            organization_domain_policy: OrganizationDomainPolicy::default(),
            database_url: None,
            database_path: PathBuf::new(),
        }
    }

    fn authorization_query() -> AuthorizeQuery {
        AuthorizeQuery {
            response_type: "code".to_owned(),
            client_id: "daemonloom-harness-cli".to_owned(),
            redirect_uri: "http://127.0.0.1:43123/callback".to_owned(),
            scope: "openid profile email".to_owned(),
            state: random_token(32).unwrap(),
            nonce: random_token(32).unwrap(),
            code_challenge: pkce_challenge(&"a".repeat(64)),
            code_challenge_method: "S256".to_owned(),
        }
    }

    #[test]
    fn authorization_requires_exact_loopback_pkce_binding() {
        let mut query = authorization_query();
        validate_authorization_request(&config(), &query).unwrap();

        query.redirect_uri = "https://attacker.example/callback".to_owned();
        assert!(validate_authorization_request(&config(), &query).is_err());

        query = authorization_query();
        query.code_challenge_method = "plain".to_owned();
        assert!(validate_authorization_request(&config(), &query).is_err());
    }

    #[test]
    fn organization_policy_uses_exact_dns_label_boundaries() {
        let policy = OrganizationDomainPolicy::new(
            Some("tenant_domain".to_owned()),
            vec!["Example.Test".to_owned()],
        )
        .unwrap();

        for domain in ["example.test", "engineering.example.test"] {
            let claims =
                HashMap::from([("tenant_domain".to_owned(), Value::String(domain.to_owned()))]);
            assert!(policy.admits(&claims), "expected {domain} to be admitted");
        }

        for domain in ["evilexample.test", "example.test.evil"] {
            let claims =
                HashMap::from([("tenant_domain".to_owned(), Value::String(domain.to_owned()))]);
            assert!(!policy.admits(&claims), "expected {domain} to be denied");
        }
    }

    #[test]
    fn organization_policy_denies_missing_or_non_string_claims() {
        let policy = OrganizationDomainPolicy::new(
            Some("tenant_domain".to_owned()),
            vec!["example.test".to_owned()],
        )
        .unwrap();

        assert!(!policy.admits(&HashMap::new()));
        assert!(!policy.admits(&HashMap::from([(
            "tenant_domain".to_owned(),
            Value::Array(Vec::new()),
        )])));
    }

    #[test]
    fn organization_policy_requires_a_complete_valid_configuration() {
        assert!(OrganizationDomainPolicy::new(None, Vec::new()).is_ok());
        assert!(OrganizationDomainPolicy::new(Some("hd".to_owned()), Vec::new()).is_err());
        assert!(OrganizationDomainPolicy::new(None, vec!["example.test".to_owned()]).is_err());
        assert!(
            OrganizationDomainPolicy::new(
                Some("hd".to_owned()),
                vec!["*.example.test".to_owned()],
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn authorization_code_is_single_use_and_stored_as_a_hash() {
        let store = Store::in_memory().unwrap();
        let authorization = PendingAuthorization {
            created_at: unix_time().unwrap(),
            client_id: "daemonloom-harness-cli".to_owned(),
            redirect_uri: "http://127.0.0.1:43123/callback".to_owned(),
            code_challenge: pkce_challenge(&"b".repeat(64)),
            subject: "google-subject".to_owned(),
            email: Some("developer@example.test".to_owned()),
        };
        store.put_code("secret-code", &authorization).await.unwrap();
        let raw_count: i64 = store
            .sqlite_connection()
            .unwrap()
            .query_row(
                "SELECT count(*) FROM authorization_codes WHERE code_hash = ?1",
                [b"secret-code".as_slice()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(raw_count, 0);
        assert!(store.take_code("secret-code").await.unwrap().is_some());
        assert!(store.take_code("secret-code").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn session_store_never_persists_the_plaintext_credential() {
        let store = Store::in_memory().unwrap();
        let identity = Identity {
            subject: "google-subject".to_owned(),
            email: Some("developer@example.test".to_owned()),
        };
        store
            .put_session("dl_session_v1_secret", &config(), &identity)
            .await
            .unwrap();
        let raw_count: i64 = store
            .sqlite_connection()
            .unwrap()
            .query_row(
                "SELECT count(*) FROM sessions WHERE verifier_hash = ?1",
                [b"dl_session_v1_secret".as_slice()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(raw_count, 0);
    }

    #[tokio::test]
    async fn session_resolution_is_bearer_bound_and_refreshes_only_live_sessions() {
        let store = Store::in_memory().unwrap();
        let identity = Identity {
            subject: "google-subject".to_owned(),
            email: Some("developer@example.test".to_owned()),
        };
        let credential = format!("dl_session_v1_{}", "a".repeat(43));
        store
            .put_session(&credential, &config(), &identity)
            .await
            .unwrap();

        let admitted = store.resolve_session(&credential).await.unwrap().unwrap();
        assert_eq!(admitted.tenant_id, "tenant-dev");
        assert_eq!(admitted.subject, "google-subject");
        assert!(
            store
                .resolve_session("dl_session_v1_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn session_credential_shape_is_closed() {
        assert!(valid_session_credential(&format!(
            "dl_session_v1_{}",
            "a".repeat(43)
        )));
        assert!(!valid_session_credential("dl_session_v1_short"));
        assert!(!valid_session_credential(&format!(
            "dl_session_v2_{}",
            "a".repeat(43)
        )));
    }
}
