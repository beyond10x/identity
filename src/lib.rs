#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::{self, Write as _};
use std::net::SocketAddr;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use axum::Router;
use axum::extract::{DefaultBodyLimit, Form, Path as AxumPath, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{Html, IntoResponse, Json, Redirect, Response};
use axum::routing::{delete, get, post, put};
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
use zeroize::Zeroizing;

mod directory;
#[cfg(feature = "local-login")]
mod local_login;
mod profile;
mod screening;

// A hosted Identity that mints a session for a mailbox somebody typed authenticates nobody. The
// facility is therefore not a flag a deployment leaves off: enabling it in the profile every
// deployment builds is this error, so no released binary can contain the code at all.
//
// Two independent predicates raise the error, because the first alone is forgeable. A release
// profile clears `debug_assertions`, but `RUSTFLAGS='-C debug-assertions=yes' cargo build
// --release` forces it back on, and that combination once compiled the route into an optimized
// artifact. The second predicate closes that hole: `build.rs` reads the profile's `OPT_LEVEL`,
// which `RUSTFLAGS` cannot reach, and sets `optimized_build` for every profile that optimizes.
#[cfg(all(feature = "local-login", not(debug_assertions)))]
compile_error!(
    "feature `local-login` mints an Identity session for a typed mailbox with no upstream identity \
     provider, which is a complete authentication bypass for every product that trusts this \
     service. It is admitted only in a debug-profile build serving a loopback listener and origin. \
     A deployment builds --release, where enabling it is this compile error."
);
#[cfg(all(feature = "local-login", optimized_build))]
compile_error!(
    "feature `local-login` was combined with an optimizing profile (`opt-level` is not 0), so it \
     would compile the loopback development login into a shipped artifact. Unlike \
     `debug_assertions`, the optimization level cannot be forced back on from `RUSTFLAGS` \
     (`-C debug-assertions=yes` leaves it untouched); `build.rs` reads it from the resolved \
     profile. Build the feature only in an unoptimized development profile on this machine."
);

const LOGIN_LIFETIME_SECONDS: i64 = 10 * 60;
const CODE_LIFETIME_SECONDS: i64 = 60;
const SESSION_IDLE_SECONDS: i64 = 24 * 60 * 60;
const SESSION_ABSOLUTE_SECONDS: i64 = 30 * 24 * 60 * 60;
const ACCESS_TOKEN_LIFETIME_SECONDS: i64 = 5 * 60;
const MAX_LOGIN_TRANSACTIONS: i64 = 4_096;
const MAX_AUTHORIZATION_CODES: i64 = 4_096;
const MAX_SESSIONS: i64 = 100_000;
const MAX_ACCESS_TOKENS: i64 = 100_000;
const MAX_HTTP_BODY_BYTES: usize = 64 * 1024;
const POSTGRES_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
#[cfg(test)]
pub(crate) const TEST_ACCESS_AUDIENCE: &str = "urn:example:resource-api";
#[cfg(test)]
pub(crate) const TEST_STATUS_AUDIENCE: &str = "urn:b10x:status";
#[cfg(test)]
const TEST_ZWIRN_AUDIENCE: &str = "urn:b10x:zwirn";

/// A credential-bearing value whose backing allocation is cleared on drop and whose
/// diagnostic representation never includes the value.
#[derive(Clone)]
pub struct SecretValue(Zeroizing<String>);

impl SecretValue {
    #[must_use]
    pub fn new(value: String) -> Self {
        Self(Zeroizing::new(value))
    }

    /// Deliberately exposes the value at the protocol boundary that consumes it.
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        self.0.as_str()
    }

    /// Copies the value into a library type that must own its protocol input.
    #[must_use]
    pub fn expose_secret_owned(&self) -> String {
        self.0.as_str().to_owned()
    }
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretValue([REDACTED])")
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    pub listen: SocketAddr,
    pub public_origin: Url,
    pub tenant_id: String,
    pub cli_client_id: String,
    /// Exact browser clients admitted by this Identity deployment.
    pub web_clients: Vec<WebClient>,
    /// Exact relying-party audiences admitted by this deployment.
    pub audience_registry: AudienceRegistry,
    /// Exact upstream `OpenID Connect` providers admitted by this deployment.
    pub upstream_providers: Vec<UpstreamProvider>,
    /// Deployment-owned, immediately effective human-to-group assignments.
    pub static_group_memberships: StaticGroupMemberships,
    /// Confidential service callers admitted to perform one exact access-token exchange.
    pub trusted_access_callers: Vec<TrustedAccessCaller>,
    /// Deployment-owned source-to-target exchange policy. Empty keeps the seam disabled.
    pub access_exchange_policies: Vec<AccessExchangePolicy>,
    pub database_url: Option<SecretValue>,
    pub database_path: PathBuf,
}

impl Config {
    fn issuer(&self) -> &str {
        self.public_origin.as_str().trim_end_matches('/')
    }

    /// A deterministic identity configuration binding for durable login sessions.
    ///
    /// A deployment must require users to authenticate again after any authority-defining
    /// configuration changes. Secrets are deliberately excluded from this digest.
    fn configuration_generation(&self) -> String {
        let mut digest = Sha256::new();
        for field in [self.issuer(), &self.tenant_id, &self.cli_client_id] {
            digest.update((field.len() as u64).to_be_bytes());
            digest.update(field.as_bytes());
        }
        for provider in &self.upstream_providers {
            for field in [
                provider.id.as_str(),
                provider.label.as_str(),
                provider.issuer.as_str(),
                provider.client_id.as_str(),
                provider
                    .organization_domain_policy
                    .claim
                    .as_deref()
                    .unwrap_or(""),
            ] {
                digest.update((field.len() as u64).to_be_bytes());
                digest.update(field.as_bytes());
            }
            for domain in &provider.organization_domain_policy.allowed_base_domains {
                digest.update((domain.len() as u64).to_be_bytes());
                digest.update(domain.as_bytes());
            }
            let mut tenant_mappings = provider
                .organization_domain_policy
                .tenant_by_claim_value
                .iter()
                .collect::<Vec<_>>();
            tenant_mappings.sort();
            for (claim_value, tenant_id) in tenant_mappings {
                for field in [claim_value.as_str(), tenant_id.as_str()] {
                    digest.update((field.len() as u64).to_be_bytes());
                    digest.update(field.as_bytes());
                }
            }
        }
        for client in &self.web_clients {
            for field in [client.client_id.as_str(), client.redirect_uri.as_str()] {
                digest.update((field.len() as u64).to_be_bytes());
                digest.update(field.as_bytes());
            }
        }
        self.audience_registry.update_generation(&mut digest);
        let mut policies = self.access_exchange_policies.clone();
        policies.sort();
        for policy in policies {
            for field in [
                policy.caller_id.as_str(),
                policy.source_audience.as_str(),
                policy.target_audience.as_str(),
            ] {
                update_generation_field(&mut digest, field);
            }
            for scope in policy.required_source_scopes {
                update_generation_field(&mut digest, "exchange-source-scope");
                update_generation_field(&mut digest, &scope);
            }
            for scope in policy.allowed_target_scopes {
                update_generation_field(&mut digest, "exchange-target-scope");
                update_generation_field(&mut digest, &scope);
            }
        }
        hex_digest(&digest.finalize()[..])
    }
}

/// One confidential service caller. The secret is deployment material and is never serialized.
#[derive(Debug, Clone)]
pub struct TrustedAccessCaller {
    id: String,
    secret: SecretValue,
}

impl TrustedAccessCaller {
    /// Validates a bounded caller identifier and a high-entropy deployment secret.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed identifiers or secrets shorter than 32 bytes.
    pub fn new(id: String, secret: SecretValue) -> Result<Self> {
        if !(3..=128).contains(&id.len())
            || !id.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':')
            })
            || !(32..=1024).contains(&secret.expose_secret().len())
        {
            bail!("Identity trusted access caller is malformed");
        }
        Ok(Self { id, secret })
    }
}

/// One exact, confidentially invoked source-to-target access exchange policy.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct AccessExchangePolicy {
    caller_id: String,
    source_audience: String,
    required_source_scopes: BTreeSet<String>,
    target_audience: String,
    allowed_target_scopes: BTreeSet<String>,
}

impl AccessExchangePolicy {
    /// Builds a policy from exact audiences and scope names.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed identifiers, audiences, or empty scope sets.
    pub fn new(
        caller_id: String,
        source_audience: String,
        required_source_scopes: Vec<String>,
        target_audience: String,
        allowed_target_scopes: Vec<String>,
    ) -> Result<Self> {
        if !(3..=128).contains(&caller_id.len())
            || !caller_id.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':')
            })
        {
            bail!("Identity access exchange caller id is malformed");
        }
        let source_audience = validate_audience(source_audience)?;
        let target_audience = validate_audience(target_audience)?;
        let required_source_scopes = normalize_registered_scopes(required_source_scopes)?;
        let allowed_target_scopes = normalize_registered_scopes(allowed_target_scopes)?;
        if required_source_scopes.is_empty() || allowed_target_scopes.is_empty() {
            bail!("Identity access exchange scope sets cannot be empty");
        }
        Ok(Self {
            caller_id,
            source_audience,
            required_source_scopes,
            target_audience,
            allowed_target_scopes,
        })
    }
}

/// One deployment-admitted upstream `OpenID Connect` provider.
#[derive(Debug, Clone)]
pub struct UpstreamProvider {
    pub id: String,
    pub label: String,
    pub issuer: String,
    pub client_id: String,
    pub client_secret: SecretValue,
    pub organization_domain_policy: OrganizationDomainPolicy,
}

impl UpstreamProvider {
    fn validate(&self) -> Result<()> {
        if self.id.is_empty()
            || self.id.len() > 64
            || !self
                .id
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            || self.label.trim().is_empty()
            || self.label.len() > 128
            || self.client_id.trim().is_empty()
            || self.client_id.len() > 512
        {
            bail!("upstream provider id, label, or client id is invalid");
        }
        IssuerUrl::new(self.issuer.clone()).context("upstream provider issuer URL")?;
        Ok(())
    }
}

fn hex_digest(bytes: &[u8]) -> String {
    let mut rendered = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(rendered, "{byte:02x}").expect("writing to a String cannot fail");
    }
    rendered
}

/// One exact browser authorization client. Browser clients remain public clients and must use
/// S256 PKCE; this registration only expands redirect admission beyond the native loopback flow.
#[derive(Debug, Clone)]
pub struct WebClient {
    client_id: String,
    redirect_uri: Url,
}

impl WebClient {
    /// Validates a public browser client and its one exact HTTPS callback.
    ///
    /// # Errors
    ///
    /// Returns an error when the client ID is malformed or the redirect is not one exact,
    /// credential-free HTTPS callback URL.
    pub fn new(client_id: &str, redirect_uri: &str) -> Result<Self> {
        let client_id = client_id.trim().to_owned();
        if !(3..=128).contains(&client_id.len())
            || !client_id.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':')
            })
        {
            bail!("Identity web client IDs must use 3-128 URL-safe ASCII characters");
        }
        let redirect_uri = Url::parse(redirect_uri)
            .context("Identity web client redirect URI must be an absolute URL")?;
        if redirect_uri.scheme() != "https"
            || redirect_uri.host_str().is_none()
            || !redirect_uri.username().is_empty()
            || redirect_uri.password().is_some()
            || redirect_uri.path() == "/"
            || redirect_uri.query().is_some()
            || redirect_uri.fragment().is_some()
        {
            bail!(
                "Identity web client redirect URI must be an exact HTTPS path without credentials, query, or fragment"
            );
        }
        Ok(Self {
            client_id,
            redirect_uri,
        })
    }
}

const AUDIENCE_REGISTRY_VERSION: &str = "identity.audiences/2";

/// Generic deployment-owned issuance constraints for one opaque relying-party audience.
///
/// Scope bytes are opaque to Identity. The base set is available to every authenticated subject;
/// exact group rules may expand it. The relying party remains responsible for interpreting each
/// scope and making the final authorization decision.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct AccessAudiencePolicy {
    base_scopes: BTreeSet<String>,
    group_scopes: BTreeMap<String, BTreeSet<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct AccessAudience {
    audience: String,
    policy: AccessAudiencePolicy,
}

impl AccessAudiencePolicy {
    /// Builds one generic exact-scope policy.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, duplicated, empty, or ambiguous group/scope rules.
    pub fn new(base_scopes: Vec<String>, group_scopes: Vec<(String, Vec<String>)>) -> Result<Self> {
        let base_scopes = normalize_registered_scopes(base_scopes)?;
        let mut registered_group_scopes = BTreeMap::new();
        for (group, scopes) in group_scopes {
            let Some(group) = normalize_groups(vec![group])?.into_iter().next() else {
                bail!("Identity access policy group cannot be empty");
            };
            let scopes = normalize_registered_scopes(scopes)?;
            if registered_group_scopes
                .insert(group.clone(), scopes)
                .is_some()
            {
                bail!("Identity access policy repeats group {group}");
            }
        }
        if base_scopes.is_empty() && registered_group_scopes.is_empty() {
            bail!("Identity access policy must register at least one scope");
        }
        Ok(Self {
            base_scopes,
            group_scopes: registered_group_scopes,
        })
    }

    fn admit(&self, requested: &str, groups: &[String]) -> Result<String, HttpError> {
        let requested = canonical_requested_scopes(requested)?;
        let admitted = self
            .base_scopes
            .iter()
            .map(String::as_str)
            .chain(
                groups
                    .iter()
                    .filter_map(|group| self.group_scopes.get(group))
                    .flatten()
                    .map(String::as_str),
            )
            .collect::<BTreeSet<_>>();
        if requested.iter().any(|scope| !admitted.contains(*scope)) {
            return Err(HttpError::denied(
                "the requested scope set is not admitted for this subject",
            ));
        }
        Ok(requested.into_iter().collect::<Vec<_>>().join(" "))
    }

    fn update_generation(&self, digest: &mut Sha256) {
        for scope in &self.base_scopes {
            update_generation_field(digest, "base-scope");
            update_generation_field(digest, scope);
        }
        for (group, scopes) in &self.group_scopes {
            for scope in scopes {
                update_generation_field(digest, "group-scope");
                update_generation_field(digest, group);
                update_generation_field(digest, scope);
            }
        }
    }
}

/// Versioned, deployment-owned registry of exact relying-party audiences.
///
/// Route-owned audiences such as the directory and profile remain at those routes. This registry
/// owns the extensible downstream seams: session resolution and short-lived access authorities.
#[derive(Debug, Clone)]
pub struct AudienceRegistry {
    session: BTreeSet<String>,
    access: BTreeSet<AccessAudience>,
}

impl AudienceRegistry {
    /// Builds one exact audience registry.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed or duplicate audience identifiers, including an identifier
    /// repeated across the session and access-token classes.
    pub fn new(session: Vec<String>, access: Vec<(String, AccessAudiencePolicy)>) -> Result<Self> {
        let mut session_registry = BTreeSet::new();
        for audience in session {
            let audience = validate_audience(audience)?;
            if !session_registry.insert(audience.clone()) {
                bail!("Identity audience registry repeats audience {audience}");
            }
        }
        let mut access_registry: BTreeSet<AccessAudience> = BTreeSet::new();
        for (audience, policy) in access {
            let audience = validate_audience(audience)?;
            if session_registry.contains(&audience)
                || access_registry
                    .iter()
                    .any(|entry| entry.audience == audience)
            {
                bail!("Identity audience registry repeats audience {audience}");
            }
            access_registry.insert(AccessAudience { audience, policy });
        }
        if session_registry.is_empty() && access_registry.is_empty() {
            bail!("Identity audience registry cannot be empty");
        }
        Ok(Self {
            session: session_registry,
            access: access_registry,
        })
    }

    fn admits_session(&self, audience: &str) -> bool {
        self.session.contains(audience)
    }

    fn access_policy(&self, audience: &str) -> Option<AccessAudiencePolicy> {
        self.access
            .iter()
            .find(|entry| entry.audience == audience)
            .map(|entry| entry.policy.clone())
    }

    fn advertised_access_scopes(&self) -> Vec<String> {
        let mut scopes = BTreeSet::from([
            "openid".to_owned(),
            "profile".to_owned(),
            "email".to_owned(),
        ]);
        for audience in &self.access {
            scopes.extend(audience.policy.base_scopes.iter().cloned());
            for group_scopes in audience.policy.group_scopes.values() {
                scopes.extend(group_scopes.iter().cloned());
            }
        }
        scopes.into_iter().collect()
    }

    fn update_generation(&self, digest: &mut Sha256) {
        update_generation_field(digest, AUDIENCE_REGISTRY_VERSION);
        for audience in &self.session {
            update_generation_field(digest, "session");
            update_generation_field(digest, audience);
        }
        for entry in &self.access {
            update_generation_field(digest, "access");
            update_generation_field(digest, &entry.audience);
            entry.policy.update_generation(digest);
        }
    }
}

fn validate_audience(audience: String) -> Result<String> {
    if audience.trim() != audience
        || !(3..=256).contains(&audience.len())
        || !audience.is_ascii()
        || audience.bytes().any(|byte| {
            byte.is_ascii_whitespace() || byte.is_ascii_control() || matches!(byte, b',' | b'"')
        })
    {
        bail!(
            "Identity audiences must be 3-256 exact printable ASCII characters without whitespace, comma, or quote"
        );
    }
    Ok(audience)
}

fn update_generation_field(digest: &mut Sha256, field: &str) {
    digest.update((field.len() as u64).to_be_bytes());
    digest.update(field.as_bytes());
}

/// Static deployment configuration that maps verified upstream emails into authorization groups.
/// Group resolution is performed for every authority request, so a configuration rollout takes
/// effect without persisting roles in an application database.
#[derive(Debug, Clone, Default)]
pub struct StaticGroupMemberships {
    by_tenant_and_email: HashMap<(String, String), Vec<String>>,
    defaults_by_tenant: HashMap<String, Vec<String>>,
}

impl StaticGroupMemberships {
    /// Validates exact email-to-group assignments and rejects ambiguous duplicate identities.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed emails, malformed or empty groups, or duplicate normalized
    /// email assignments.
    pub fn new(entries: Vec<(String, String, Vec<String>)>) -> Result<Self> {
        Self::new_with_tenant_defaults(entries, Vec::new())
    }

    /// Validates exact email assignments plus groups granted to every verified member of an
    /// admitted tenant.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed tenant IDs, groups, emails, or duplicate assignments.
    pub fn new_with_tenant_defaults(
        entries: Vec<(String, String, Vec<String>)>,
        tenant_defaults: Vec<(String, Vec<String>)>,
    ) -> Result<Self> {
        let mut by_tenant_and_email = HashMap::new();
        for (tenant_id, email, groups) in entries {
            let tenant_id = normalize_group_tenant_id(&tenant_id)?;
            let email = normalize_email(&email)?;
            let groups = normalize_groups(groups)?;
            if by_tenant_and_email
                .insert(
                    (tenant_id.clone(), email.clone()),
                    groups.into_iter().collect(),
                )
                .is_some()
            {
                bail!(
                    "Identity static group membership repeats tenant {tenant_id} and email {email}"
                );
            }
        }
        let mut defaults_by_tenant = HashMap::new();
        for (tenant_id, groups) in tenant_defaults {
            let tenant_id = normalize_group_tenant_id(&tenant_id)?;
            let groups = normalize_groups(groups)?;
            if defaults_by_tenant
                .insert(tenant_id.clone(), groups)
                .is_some()
            {
                bail!("Identity default groups repeat tenant {tenant_id}");
            }
        }
        Ok(Self {
            by_tenant_and_email,
            defaults_by_tenant,
        })
    }

    fn groups_for(&self, tenant_id: &str, email: Option<&str>) -> Vec<String> {
        let Some(email) = email.and_then(|email| normalize_email(email).ok()) else {
            return Vec::new();
        };
        self.defaults_by_tenant
            .get(tenant_id)
            .into_iter()
            .flatten()
            .chain(
                self.by_tenant_and_email
                    .get(&(tenant_id.to_owned(), email))
                    .into_iter()
                    .flatten(),
            )
            .cloned()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }
}

fn normalize_group_tenant_id(value: &str) -> Result<String> {
    let tenant_id = value.trim().to_owned();
    if !(1..=128).contains(&tenant_id.len())
        || !tenant_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        bail!("Identity static group tenant IDs must be bounded URL-safe ASCII");
    }
    Ok(tenant_id)
}

fn normalize_groups(groups: Vec<String>) -> Result<Vec<String>> {
    let groups = groups
        .into_iter()
        .map(|group| group.trim().to_ascii_lowercase())
        .collect::<BTreeSet<_>>();
    if groups.is_empty()
        || groups.iter().any(|group| {
            !(1..=64).contains(&group.len())
                || !group.bytes().enumerate().all(|(index, byte)| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit() && index > 0
                        || matches!(byte, b'-' | b'_') && index > 0
                })
        })
    {
        bail!("Identity static groups must be non-empty lowercase names of at most 64 characters");
    }
    Ok(groups.into_iter().collect())
}

fn normalize_email(value: &str) -> Result<String> {
    let email = value.trim().to_ascii_lowercase();
    let mut parts = email.split('@');
    let local = parts.next().unwrap_or_default();
    let domain = parts.next().unwrap_or_default();
    if email.len() > 254
        || local.is_empty()
        || domain.is_empty()
        || parts.next().is_some()
        || email.chars().any(char::is_whitespace)
        || !email.is_ascii()
    {
        bail!("Identity static group emails must be bounded ASCII mailbox addresses");
    }
    Ok(email)
}

/// Restricts logins using a domain claim from the cryptographically verified upstream ID token.
#[derive(Debug, Clone, Default)]
pub struct OrganizationDomainPolicy {
    claim: Option<String>,
    allowed_base_domains: Vec<String>,
    tenant_by_claim_value: HashMap<String, String>,
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
                    tenant_by_claim_value: HashMap::new(),
                })
            }
        }
    }

    /// Builds an exact verified-claim-to-tenant registry. Claim values cannot overlap and tenant
    /// identifiers are never inferred from email or request parameters.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid claim name, an empty registry, duplicate claim values, or
    /// malformed tenant identifiers.
    pub fn exact_tenant_mapping(claim: &str, mappings: Vec<(String, String)>) -> Result<Self> {
        let claim = claim.trim().to_owned();
        if claim.is_empty() || claim.len() > 512 || claim.chars().any(char::is_whitespace) {
            bail!("organization claim must be a bounded non-whitespace JSON claim name");
        }
        let mut tenant_by_claim_value = HashMap::new();
        for (value, tenant_id) in mappings {
            let value = value.trim().to_ascii_lowercase();
            let tenant_id = tenant_id.trim().to_owned();
            if value.is_empty()
                || value.len() > 512
                || value.chars().any(char::is_whitespace)
                || !(1..=128).contains(&tenant_id.len())
                || !tenant_id.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':')
                })
                || tenant_by_claim_value.insert(value, tenant_id).is_some()
            {
                bail!("organization tenant mappings must be exact, unique, and bounded");
            }
        }
        if tenant_by_claim_value.is_empty() {
            bail!("organization tenant mapping cannot be empty");
        }
        Ok(Self {
            claim: Some(claim),
            allowed_base_domains: Vec::new(),
            tenant_by_claim_value,
        })
    }

    fn resolve_tenant(
        &self,
        claims: &HashMap<String, Value>,
        legacy_tenant: &str,
    ) -> Option<String> {
        let Some(claim) = self.claim.as_deref() else {
            return Some(legacy_tenant.to_owned());
        };
        let value = claims.get(claim)?.as_str()?.to_ascii_lowercase();
        if !self.tenant_by_claim_value.is_empty() {
            return self.tenant_by_claim_value.get(&value).cloned();
        }
        self.allowed_base_domains
            .iter()
            .any(|base| {
                value == *base
                    || value
                        .strip_suffix(base)
                        .is_some_and(|prefix| prefix.ends_with('.'))
            })
            .then(|| legacy_tenant.to_owned())
    }

    #[cfg(test)]
    fn admits(&self, claims: &HashMap<String, Value>) -> bool {
        let Some(claim) = self.claim.as_deref() else {
            return true;
        };
        let Some(domain) = claims.get(claim).and_then(Value::as_str) else {
            return false;
        };
        let domain = domain.to_ascii_lowercase();
        self.tenant_by_claim_value.contains_key(&domain)
            || self.allowed_base_domains.iter().any(|base| {
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
    upstreams: Arc<BTreeMap<String, CoreProviderMetadata>>,
    http_client: openidconnect::reqwest::Client,
    store: Store,
}

impl AppState {
    #[must_use]
    pub fn new(
        config: Arc<Config>,
        upstreams: BTreeMap<String, CoreProviderMetadata>,
        http_client: openidconnect::reqwest::Client,
        store: Store,
    ) -> Self {
        Self {
            config,
            upstreams: Arc::new(upstreams),
            http_client,
            store,
        }
    }
}

#[derive(Clone)]
pub enum Store {
    Sqlite(Arc<Mutex<Connection>>),
    Postgres(Arc<PostgresStore>),
}

/// Reconnectable PostgreSQL state. Public only because it is carried by the public `Store` enum;
/// callers construct stores through `Store::connect_postgres`.
#[doc(hidden)]
pub struct PostgresStore {
    url: String,
    client: tokio::sync::Mutex<Option<Arc<tokio_postgres::Client>>>,
    capacity_admission: tokio::sync::Mutex<()>,
}

impl PostgresStore {
    async fn client(&self) -> Result<Arc<tokio_postgres::Client>> {
        let mut slot = self.client.lock().await;
        if let Some(client) = slot.as_ref().filter(|client| !client.is_closed()) {
            return Ok(client.clone());
        }

        let tls = tokio_postgres_rustls::MakeRustlsConnect::with_webpki_roots();
        let (client, connection) = tokio::time::timeout(
            POSTGRES_CONNECT_TIMEOUT,
            tokio_postgres::connect(&self.url, tls),
        )
        .await
        .context("identity PostgreSQL connection deadline elapsed")?
        .context("connect to identity PostgreSQL database")?;
        tokio::spawn(async move {
            if let Err(error) = connection.await {
                tracing::error!(%error, "identity PostgreSQL connection failed");
            }
        });
        initialize_postgres(&client).await?;
        let client = Arc::new(client);
        *slot = Some(client.clone());
        Ok(client)
    }
}

async fn initialize_postgres(client: &tokio_postgres::Client) -> Result<()> {
    client
        .batch_execute(
            "CREATE TABLE IF NOT EXISTS login_transactions (
               upstream_state TEXT PRIMARY KEY,
               provider_id TEXT NOT NULL DEFAULT 'default',
               created_at BIGINT NOT NULL,
               client_id TEXT NOT NULL,
               redirect_uri TEXT NOT NULL,
               client_state TEXT NOT NULL,
               client_nonce TEXT NOT NULL,
               client_code_challenge TEXT NOT NULL,
               requested_audience TEXT,
               requested_scope TEXT,
               upstream_nonce TEXT NOT NULL,
               upstream_pkce_verifier TEXT NOT NULL
             );
             ALTER TABLE login_transactions ADD COLUMN IF NOT EXISTS provider_id TEXT NOT NULL DEFAULT 'default';
             ALTER TABLE login_transactions ADD COLUMN IF NOT EXISTS link_subject TEXT;
             ALTER TABLE login_transactions ADD COLUMN IF NOT EXISTS link_tenant_id TEXT;
             ALTER TABLE login_transactions ADD COLUMN IF NOT EXISTS requested_audience TEXT;
             ALTER TABLE login_transactions ADD COLUMN IF NOT EXISTS requested_scope TEXT;
             CREATE TABLE IF NOT EXISTS identity_links (
               tenant_id TEXT NOT NULL,
               provider_id TEXT NOT NULL,
               issuer TEXT NOT NULL,
               upstream_subject TEXT NOT NULL,
               canonical_subject TEXT NOT NULL,
               email TEXT,
               created_at BIGINT NOT NULL,
               PRIMARY KEY (tenant_id, provider_id, issuer, upstream_subject),
               UNIQUE (tenant_id, provider_id, canonical_subject)
             );
             CREATE INDEX IF NOT EXISTS identity_links_canonical
               ON identity_links (tenant_id, canonical_subject);
             CREATE TABLE IF NOT EXISTS authorization_codes (
               code_hash BYTEA PRIMARY KEY,
               created_at BIGINT NOT NULL,
               client_id TEXT NOT NULL,
               redirect_uri TEXT NOT NULL,
               code_challenge TEXT NOT NULL,
               subject TEXT NOT NULL,
               tenant_id TEXT NOT NULL,
               email TEXT,
               requested_audience TEXT,
               requested_scope TEXT
             );
             CREATE TABLE IF NOT EXISTS sessions (
               verifier_hash BYTEA PRIMARY KEY,
               issuer TEXT NOT NULL,
               configuration_generation TEXT NOT NULL,
               tenant_id TEXT NOT NULL,
               subject TEXT NOT NULL,
               email TEXT,
               created_at BIGINT NOT NULL,
               last_used_at BIGINT NOT NULL,
               idle_expires_at BIGINT NOT NULL,
               absolute_expires_at BIGINT NOT NULL,
               revoked_at BIGINT
             );
             ALTER TABLE sessions ADD COLUMN IF NOT EXISTS issuer TEXT NOT NULL DEFAULT '';
             ALTER TABLE sessions ADD COLUMN IF NOT EXISTS configuration_generation TEXT NOT NULL DEFAULT '';
             ALTER TABLE authorization_codes ADD COLUMN IF NOT EXISTS tenant_id TEXT NOT NULL DEFAULT '';
             ALTER TABLE authorization_codes ADD COLUMN IF NOT EXISTS requested_audience TEXT;
             ALTER TABLE authorization_codes ADD COLUMN IF NOT EXISTS requested_scope TEXT;
             CREATE TABLE IF NOT EXISTS access_tokens (
               verifier_hash BYTEA PRIMARY KEY,
               issuer TEXT NOT NULL,
               subject TEXT NOT NULL,
               audience TEXT NOT NULL,
               issued_at BIGINT NOT NULL,
               not_before BIGINT NOT NULL,
               expires_at BIGINT NOT NULL,
               token_id TEXT NOT NULL UNIQUE,
               actor_subject TEXT NOT NULL,
               scope TEXT NOT NULL,
               principal_kind TEXT NOT NULL,
               tenant_id TEXT NOT NULL,
               email TEXT,
               groups TEXT NOT NULL DEFAULT '',
               revoked_at BIGINT
             );
             ALTER TABLE access_tokens ADD COLUMN IF NOT EXISTS groups TEXT NOT NULL DEFAULT '';
             ALTER TABLE access_tokens ADD COLUMN IF NOT EXISTS email TEXT;",
        )
        .await
        .context("initialize identity PostgreSQL schema")?;
    // Additive-only directory and profile tables. Every statement creates a table or index that
    // did not exist before; no existing table, column, index, or row is altered, rewritten, or
    // dropped, so applying this to a live database takes no lock on a credential table and an
    // older binary keeps running unchanged against it.
    for schema in [directory::POSTGRES_SCHEMA, profile::POSTGRES_SCHEMA] {
        client
            .batch_execute(schema)
            .await
            .context("extend identity PostgreSQL schema")?;
    }
    Ok(())
}

impl Store {
    /// Opens or creates the identity database and applies the local schema.
    ///
    /// # Errors
    ///
    /// Returns an error when the parent directory, database, or schema cannot be created.
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            let existed = parent.exists();
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create identity data directory {}", parent.display()))?;
            if !existed {
                std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))
                    .with_context(|| {
                        format!("protect identity data directory {}", parent.display())
                    })?;
            }
            validate_private_state_path(parent, true)?;
        }
        if path.exists() {
            validate_private_state_path(path, false)?;
        }
        let connection = Connection::open(path)
            .with_context(|| format!("open identity database {}", path.display()))?;
        let store = Self::from_sqlite_connection(connection)?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("protect identity database {}", path.display()))?;
        Ok(store)
    }

    /// Connects to `PostgreSQL` and applies the identity schema.
    ///
    /// # Errors
    ///
    /// Returns an error when the database cannot be connected or initialized.
    pub async fn connect_postgres(url: &str) -> Result<Self> {
        let store = Arc::new(PostgresStore {
            url: url.to_owned(),
            client: tokio::sync::Mutex::new(None),
            capacity_admission: tokio::sync::Mutex::new(()),
        });
        store.client().await?;
        Ok(Self::Postgres(store))
    }

    /// Creates an isolated in-memory store for tests.
    ///
    /// # Errors
    ///
    /// Returns an error when `SQLite` cannot create or initialize the database.
    pub fn in_memory() -> Result<Self> {
        Self::from_sqlite_connection(Connection::open_in_memory()?)
    }

    #[allow(clippy::too_many_lines)]
    fn from_sqlite_connection(connection: Connection) -> Result<Self> {
        connection.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA foreign_keys=ON;
             CREATE TABLE IF NOT EXISTS login_transactions (
               upstream_state TEXT PRIMARY KEY,
               provider_id TEXT NOT NULL DEFAULT 'default',
               created_at INTEGER NOT NULL,
               client_id TEXT NOT NULL,
               redirect_uri TEXT NOT NULL,
               client_state TEXT NOT NULL,
               client_nonce TEXT NOT NULL,
               client_code_challenge TEXT NOT NULL,
               requested_audience TEXT,
               requested_scope TEXT,
               upstream_nonce TEXT NOT NULL,
               upstream_pkce_verifier TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS identity_links (
               tenant_id TEXT NOT NULL,
               provider_id TEXT NOT NULL,
               issuer TEXT NOT NULL,
               upstream_subject TEXT NOT NULL,
               canonical_subject TEXT NOT NULL,
               email TEXT,
               created_at INTEGER NOT NULL,
               PRIMARY KEY (tenant_id, provider_id, issuer, upstream_subject),
               UNIQUE (tenant_id, provider_id, canonical_subject)
             );
             CREATE INDEX IF NOT EXISTS identity_links_canonical
               ON identity_links (tenant_id, canonical_subject);
             CREATE TABLE IF NOT EXISTS authorization_codes (
               code_hash BLOB PRIMARY KEY,
               created_at INTEGER NOT NULL,
               client_id TEXT NOT NULL,
               redirect_uri TEXT NOT NULL,
               code_challenge TEXT NOT NULL,
               subject TEXT NOT NULL,
               tenant_id TEXT NOT NULL,
               email TEXT,
               requested_audience TEXT,
               requested_scope TEXT
             );
             CREATE TABLE IF NOT EXISTS sessions (
               verifier_hash BLOB PRIMARY KEY,
               issuer TEXT NOT NULL,
               configuration_generation TEXT NOT NULL,
               tenant_id TEXT NOT NULL,
               subject TEXT NOT NULL,
               email TEXT,
               created_at INTEGER NOT NULL,
               last_used_at INTEGER NOT NULL,
               idle_expires_at INTEGER NOT NULL,
               absolute_expires_at INTEGER NOT NULL,
               revoked_at INTEGER
             );
             CREATE TABLE IF NOT EXISTS access_tokens (
               verifier_hash BLOB PRIMARY KEY,
               issuer TEXT NOT NULL,
               subject TEXT NOT NULL,
               audience TEXT NOT NULL,
               issued_at INTEGER NOT NULL,
               not_before INTEGER NOT NULL,
               expires_at INTEGER NOT NULL,
               token_id TEXT NOT NULL UNIQUE,
               actor_subject TEXT NOT NULL,
               scope TEXT NOT NULL,
               principal_kind TEXT NOT NULL,
               tenant_id TEXT NOT NULL,
               email TEXT,
               groups TEXT NOT NULL DEFAULT '',
               revoked_at INTEGER
             );",
        )?;
        ensure_sqlite_column(
            &connection,
            "login_transactions",
            "provider_id",
            "TEXT NOT NULL DEFAULT 'default'",
        )?;
        ensure_sqlite_column(&connection, "login_transactions", "link_subject", "TEXT")?;
        ensure_sqlite_column(&connection, "login_transactions", "link_tenant_id", "TEXT")?;
        ensure_sqlite_column(
            &connection,
            "login_transactions",
            "requested_audience",
            "TEXT",
        )?;
        ensure_sqlite_column(&connection, "login_transactions", "requested_scope", "TEXT")?;
        ensure_sqlite_column(
            &connection,
            "authorization_codes",
            "tenant_id",
            "TEXT NOT NULL DEFAULT ''",
        )?;
        ensure_sqlite_column(
            &connection,
            "authorization_codes",
            "requested_audience",
            "TEXT",
        )?;
        ensure_sqlite_column(
            &connection,
            "authorization_codes",
            "requested_scope",
            "TEXT",
        )?;
        ensure_sqlite_column(
            &connection,
            "sessions",
            "issuer",
            "TEXT NOT NULL DEFAULT ''",
        )?;
        ensure_sqlite_column(
            &connection,
            "sessions",
            "configuration_generation",
            "TEXT NOT NULL DEFAULT ''",
        )?;
        ensure_sqlite_column(
            &connection,
            "access_tokens",
            "groups",
            "TEXT NOT NULL DEFAULT ''",
        )?;
        ensure_sqlite_column(&connection, "access_tokens", "email", "TEXT")?;
        connection.execute_batch(directory::SQLITE_SCHEMA)?;
        connection.execute_batch(profile::SQLITE_SCHEMA)?;
        Ok(Self::Sqlite(Arc::new(Mutex::new(connection))))
    }

    async fn put_login(&self, login: &LoginTransaction) -> Result<()> {
        let _capacity_admission = self.capacity_admission().await;
        self.prepare_insert(
            login.created_at,
            "login_transactions",
            MAX_LOGIN_TRANSACTIONS,
        )
        .await?;
        match self {
            Self::Sqlite(_) => {
                self.sqlite_connection()?.execute(
                    "INSERT INTO login_transactions (
                       upstream_state, provider_id, created_at, client_id, redirect_uri, client_state,
                       client_nonce, client_code_challenge, requested_audience, requested_scope,
                       upstream_nonce, upstream_pkce_verifier, link_subject, link_tenant_id
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
                    params![
                        login.upstream_state,
                        login.provider_id,
                        login.created_at,
                        login.client_id,
                        login.redirect_uri,
                        login.client_state,
                        login.client_nonce,
                        login.client_code_challenge,
                        login.requested_audience,
                        login.requested_scope,
                        login.upstream_nonce,
                        login.upstream_pkce_verifier,
                        login.link_subject,
                        login.link_tenant_id,
                    ],
                )?;
            }
            Self::Postgres(store) => {
                let client = store.client().await?;
                client
                    .execute(
                        "INSERT INTO login_transactions (
                           upstream_state, provider_id, created_at, client_id, redirect_uri,
                           client_state, client_nonce, client_code_challenge, requested_audience,
                           requested_scope, upstream_nonce, upstream_pkce_verifier, link_subject,
                           link_tenant_id
                         ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)",
                        &[
                            &login.upstream_state,
                            &login.provider_id,
                            &login.created_at,
                            &login.client_id,
                            &login.redirect_uri,
                            &login.client_state,
                            &login.client_nonce,
                            &login.client_code_challenge,
                            &login.requested_audience,
                            &login.requested_scope,
                            &login.upstream_nonce,
                            &login.upstream_pkce_verifier,
                            &login.link_subject,
                            &login.link_tenant_id,
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
                     RETURNING upstream_state, provider_id, created_at, client_id, redirect_uri,
                               client_state, client_nonce, client_code_challenge,
                               requested_audience, requested_scope, upstream_nonce,
                               upstream_pkce_verifier, link_subject, link_tenant_id",
                    [state],
                    |row| {
                        Ok(LoginTransaction {
                            upstream_state: row.get(0)?,
                            provider_id: row.get(1)?,
                            created_at: row.get(2)?,
                            client_id: row.get(3)?,
                            redirect_uri: row.get(4)?,
                            client_state: row.get(5)?,
                            client_nonce: row.get(6)?,
                            client_code_challenge: row.get(7)?,
                            requested_audience: row.get(8)?,
                            requested_scope: row.get(9)?,
                            upstream_nonce: row.get(10)?,
                            upstream_pkce_verifier: row.get(11)?,
                            link_subject: row.get(12)?,
                            link_tenant_id: row.get(13)?,
                        })
                    },
                )
                .optional()
                .map_err(Into::into),
            Self::Postgres(store) => {
                let client = store.client().await?;
                client
                    .query_opt(
                        "DELETE FROM login_transactions WHERE upstream_state = $1
                     RETURNING upstream_state, provider_id, created_at, client_id, redirect_uri,
                               client_state, client_nonce, client_code_challenge,
                               requested_audience, requested_scope, upstream_nonce,
                               upstream_pkce_verifier, link_subject, link_tenant_id",
                        &[&state],
                    )
                    .await
                    .map(|row| {
                        row.map(|row| LoginTransaction {
                            upstream_state: row.get(0),
                            provider_id: row.get(1),
                            created_at: row.get(2),
                            client_id: row.get(3),
                            redirect_uri: row.get(4),
                            client_state: row.get(5),
                            client_nonce: row.get(6),
                            client_code_challenge: row.get(7),
                            requested_audience: row.get(8),
                            requested_scope: row.get(9),
                            upstream_nonce: row.get(10),
                            upstream_pkce_verifier: row.get(11),
                            link_subject: row.get(12),
                            link_tenant_id: row.get(13),
                        })
                    })
                    .map_err(Into::into)
            }
        }
    }

    async fn resolve_identity_link(
        &self,
        tenant_id: &str,
        provider_id: &str,
        issuer: &str,
        upstream_subject: &str,
    ) -> Result<Option<Identity>> {
        match self {
            Self::Sqlite(_) => self
                .sqlite_connection()?
                .query_row(
                    "SELECT canonical_subject, email FROM identity_links
                     WHERE tenant_id = ?1 AND provider_id = ?2 AND issuer = ?3
                       AND upstream_subject = ?4",
                    params![tenant_id, provider_id, issuer, upstream_subject],
                    |row| {
                        Ok(Identity {
                            subject: row.get(0)?,
                            email: row.get(1)?,
                        })
                    },
                )
                .optional()
                .map_err(Into::into),
            Self::Postgres(store) => {
                let client = store.client().await?;
                client
                    .query_opt(
                        "SELECT canonical_subject, email FROM identity_links
                         WHERE tenant_id = $1 AND provider_id = $2 AND issuer = $3
                           AND upstream_subject = $4",
                        &[&tenant_id, &provider_id, &issuer, &upstream_subject],
                    )
                    .await
                    .map(|row| {
                        row.map(|row| Identity {
                            subject: row.get(0),
                            email: row.get(1),
                        })
                    })
                    .map_err(Into::into)
            }
        }
    }

    async fn put_identity_link(
        &self,
        tenant_id: &str,
        provider_id: &str,
        issuer: &str,
        upstream_subject: &str,
        identity: &Identity,
        created_at: i64,
    ) -> Result<bool> {
        let _capacity_admission = self.capacity_admission().await;
        match self {
            Self::Sqlite(_) => self
                .sqlite_connection()?
                .execute(
                    "INSERT INTO identity_links (
                       tenant_id, provider_id, issuer, upstream_subject, canonical_subject, email,
                       created_at
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                     ON CONFLICT DO NOTHING",
                    params![
                        tenant_id,
                        provider_id,
                        issuer,
                        upstream_subject,
                        identity.subject,
                        identity.email,
                        created_at,
                    ],
                )
                .map(|changed| changed == 1)
                .map_err(Into::into),
            Self::Postgres(store) => {
                let client = store.client().await?;
                client
                    .execute(
                        "INSERT INTO identity_links (
                           tenant_id, provider_id, issuer, upstream_subject, canonical_subject,
                           email, created_at
                         ) VALUES ($1, $2, $3, $4, $5, $6, $7)
                         ON CONFLICT DO NOTHING",
                        &[
                            &tenant_id,
                            &provider_id,
                            &issuer,
                            &upstream_subject,
                            &identity.subject,
                            &identity.email,
                            &created_at,
                        ],
                    )
                    .await
                    .map(|changed| changed == 1)
                    .map_err(Into::into)
            }
        }
    }

    async fn identity_links_for(
        &self,
        tenant_id: &str,
        canonical_subject: &str,
    ) -> Result<Vec<IdentityLink>> {
        match self {
            Self::Sqlite(_) => {
                let connection = self.sqlite_connection()?;
                let mut statement = connection.prepare(
                    "SELECT provider_id, issuer, email, created_at FROM identity_links
                     WHERE tenant_id = ?1 AND canonical_subject = ?2 ORDER BY provider_id",
                )?;
                let rows = statement.query_map(params![tenant_id, canonical_subject], |row| {
                    Ok(IdentityLink {
                        provider_id: row.get(0)?,
                        issuer: row.get(1)?,
                        email: row.get(2)?,
                        linked_at: row.get(3)?,
                    })
                })?;
                rows.collect::<rusqlite::Result<Vec<_>>>()
                    .map_err(Into::into)
            }
            Self::Postgres(store) => {
                let client = store.client().await?;
                let rows = client
                    .query(
                        "SELECT provider_id, issuer, email, created_at FROM identity_links
                         WHERE tenant_id = $1 AND canonical_subject = $2 ORDER BY provider_id",
                        &[&tenant_id, &canonical_subject],
                    )
                    .await?;
                Ok(rows
                    .into_iter()
                    .map(|row| IdentityLink {
                        provider_id: row.get(0),
                        issuer: row.get(1),
                        email: row.get(2),
                        linked_at: row.get(3),
                    })
                    .collect())
            }
        }
    }

    async fn remove_identity_link(
        &self,
        tenant_id: &str,
        canonical_subject: &str,
        provider_id: &str,
    ) -> Result<bool> {
        let _capacity_admission = self.capacity_admission().await;
        let links = self
            .identity_links_for(tenant_id, canonical_subject)
            .await?;
        if links.len() <= 1 {
            return Ok(false);
        }
        match self {
            Self::Sqlite(_) => self
                .sqlite_connection()?
                .execute(
                    "DELETE FROM identity_links
                     WHERE tenant_id = ?1 AND canonical_subject = ?2 AND provider_id = ?3",
                    params![tenant_id, canonical_subject, provider_id],
                )
                .map(|changed| changed == 1)
                .map_err(Into::into),
            Self::Postgres(store) => {
                let client = store.client().await?;
                client
                    .execute(
                        "DELETE FROM identity_links
                         WHERE tenant_id = $1 AND canonical_subject = $2 AND provider_id = $3",
                        &[&tenant_id, &canonical_subject, &provider_id],
                    )
                    .await
                    .map(|changed| changed == 1)
                    .map_err(Into::into)
            }
        }
    }

    async fn put_code(&self, code: &str, authorization: &PendingAuthorization) -> Result<()> {
        let _capacity_admission = self.capacity_admission().await;
        self.prepare_insert(
            authorization.created_at,
            "authorization_codes",
            MAX_AUTHORIZATION_CODES,
        )
        .await?;
        let digest = hash(code);
        match self {
            Self::Sqlite(_) => {
                self.sqlite_connection()?.execute(
                    "INSERT INTO authorization_codes (
                       code_hash, created_at, client_id, redirect_uri, code_challenge, subject,
                       tenant_id, email, requested_audience, requested_scope
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                    params![
                        digest,
                        authorization.created_at,
                        authorization.client_id,
                        authorization.redirect_uri,
                        authorization.code_challenge,
                        authorization.subject,
                        authorization.tenant_id,
                        authorization.email,
                        authorization.requested_audience,
                        authorization.requested_scope,
                    ],
                )?;
            }
            Self::Postgres(store) => {
                let client = store.client().await?;
                client
                    .execute(
                        "INSERT INTO authorization_codes (
                           code_hash, created_at, client_id, redirect_uri, code_challenge, subject,
                           tenant_id, email, requested_audience, requested_scope
                         ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
                        &[
                            &digest,
                            &authorization.created_at,
                            &authorization.client_id,
                            &authorization.redirect_uri,
                            &authorization.code_challenge,
                            &authorization.subject,
                            &authorization.tenant_id,
                            &authorization.email,
                            &authorization.requested_audience,
                            &authorization.requested_scope,
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
                     RETURNING created_at, client_id, redirect_uri, code_challenge, subject,
                               tenant_id, email, requested_audience, requested_scope",
                    [digest.as_slice()],
                    |row| {
                        Ok(PendingAuthorization {
                            created_at: row.get(0)?,
                            client_id: row.get(1)?,
                            redirect_uri: row.get(2)?,
                            code_challenge: row.get(3)?,
                            subject: row.get(4)?,
                            tenant_id: row.get(5)?,
                            email: row.get(6)?,
                            requested_audience: row.get(7)?,
                            requested_scope: row.get(8)?,
                        })
                    },
                )
                .optional()
                .map_err(Into::into),
            Self::Postgres(store) => {
                let client = store.client().await?;
                client
                    .query_opt(
                        "DELETE FROM authorization_codes WHERE code_hash = $1
                     RETURNING created_at, client_id, redirect_uri, code_challenge, subject,
                               tenant_id, email, requested_audience, requested_scope",
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
                            tenant_id: row.get(5),
                            email: row.get(6),
                            requested_audience: row.get(7),
                            requested_scope: row.get(8),
                        })
                    })
                    .map_err(Into::into)
            }
        }
    }

    async fn put_session(
        &self,
        credential: &str,
        config: &Config,
        tenant_id: &str,
        identity: &Identity,
    ) -> Result<()> {
        let now = unix_time()?;
        let _capacity_admission = self.capacity_admission().await;
        self.prepare_insert(now, "sessions", MAX_SESSIONS).await?;
        let digest = hash(credential);
        let idle_expires_at = now + SESSION_IDLE_SECONDS;
        let absolute_expires_at = now + SESSION_ABSOLUTE_SECONDS;
        match self {
            Self::Sqlite(_) => {
                self.sqlite_connection()?.execute(
                    "INSERT INTO sessions (
                       verifier_hash, issuer, configuration_generation, tenant_id, subject, email,
                       created_at, last_used_at, idle_expires_at, absolute_expires_at, revoked_at
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7, ?8, ?9, NULL)",
                    params![
                        digest.as_slice(),
                        config.issuer(),
                        config.configuration_generation(),
                        tenant_id,
                        identity.subject,
                        identity.email,
                        now,
                        idle_expires_at,
                        absolute_expires_at,
                    ],
                )?;
            }
            Self::Postgres(store) => {
                let client = store.client().await?;
                client
                    .execute(
                        "INSERT INTO sessions (
                           verifier_hash, issuer, configuration_generation, tenant_id, subject,
                           email, created_at, last_used_at, idle_expires_at, absolute_expires_at,
                           revoked_at
                         ) VALUES ($1, $2, $3, $4, $5, $6, $7, $7, $8, $9, NULL)",
                        &[
                            &digest,
                            &config.issuer(),
                            &config.configuration_generation(),
                            &tenant_id,
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

    async fn resolve_session(
        &self,
        credential: &str,
        config: &Config,
    ) -> Result<Option<AdmittedSession>> {
        let now = unix_time()?;
        let digest = hash(credential);
        let idle_expires_at = now + SESSION_IDLE_SECONDS;
        let generation = config.configuration_generation();
        match self {
            Self::Sqlite(_) => self
                .sqlite_connection()?
                .query_row(
                    "UPDATE sessions
                     SET last_used_at = ?2,
                         idle_expires_at = min(?3, absolute_expires_at)
                     WHERE verifier_hash = ?1
                       AND issuer = ?4
                       AND configuration_generation = ?5
                       AND revoked_at IS NULL
                       AND idle_expires_at > ?2
                       AND absolute_expires_at > ?2
                     RETURNING tenant_id, subject, email, idle_expires_at",
                    params![
                        digest.as_slice(),
                        now,
                        idle_expires_at,
                        config.issuer(),
                        generation,
                    ],
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
            Self::Postgres(store) => {
                let client = store.client().await?;
                client
                    .query_opt(
                        "UPDATE sessions
                     SET last_used_at = $2,
                         idle_expires_at = LEAST($3, absolute_expires_at)
                     WHERE verifier_hash = $1
                       AND issuer = $4
                       AND configuration_generation = $5
                       AND revoked_at IS NULL
                       AND idle_expires_at > $2
                       AND absolute_expires_at > $2
                     RETURNING tenant_id, subject, email, idle_expires_at",
                        &[
                            &digest,
                            &now,
                            &idle_expires_at,
                            &config.issuer(),
                            &generation,
                        ],
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
                    .map_err(Into::into)
            }
        }
    }

    async fn put_access_token(&self, credential: &str, authority: &AccessAuthority) -> Result<()> {
        let _capacity_admission = self.capacity_admission().await;
        self.prepare_insert(authority.iat, "access_tokens", MAX_ACCESS_TOKENS)
            .await?;
        let digest = hash(credential);
        let groups = authority.groups.join(" ");
        match self {
            Self::Sqlite(_) => {
                self.sqlite_connection()?.execute(
                    "INSERT INTO access_tokens (
                       verifier_hash, issuer, subject, audience, issued_at, not_before, expires_at,
                       token_id, actor_subject, scope, principal_kind, tenant_id, email, groups,
                       revoked_at
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, NULL)",
                    params![
                        digest.as_slice(),
                        authority.iss,
                        authority.sub,
                        authority.aud,
                        authority.iat,
                        authority.nbf,
                        authority.exp,
                        authority.jti,
                        authority.act.sub,
                        authority.scope,
                        authority.principal_kind,
                        authority.tenant_id,
                        authority.email,
                        groups,
                    ],
                )?;
            }
            Self::Postgres(store) => {
                let client = store.client().await?;
                client
                    .execute(
                        "INSERT INTO access_tokens (
                           verifier_hash, issuer, subject, audience, issued_at, not_before,
                           expires_at, token_id, actor_subject, scope, principal_kind, tenant_id,
                           email, groups, revoked_at
                         ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, NULL)",
                        &[
                            &digest,
                            &authority.iss,
                            &authority.sub,
                            &authority.aud,
                            &authority.iat,
                            &authority.nbf,
                            &authority.exp,
                            &authority.jti,
                            &authority.act.sub,
                            &authority.scope,
                            &authority.principal_kind,
                            &authority.tenant_id,
                            &authority.email,
                            &groups,
                        ],
                    )
                    .await?;
            }
        }
        Ok(())
    }

    async fn resolve_access_token(
        &self,
        credential: &str,
        audience: &str,
    ) -> Result<Option<AccessAuthority>> {
        let now = unix_time()?;
        let digest = hash(credential);
        match self {
            Self::Sqlite(_) => self
                .sqlite_connection()?
                .query_row(
                    "SELECT issuer, subject, audience, issued_at, not_before, expires_at, token_id,
                            actor_subject, scope, principal_kind, tenant_id, email, groups
                     FROM access_tokens
                     WHERE verifier_hash = ?1 AND audience = ?2 AND revoked_at IS NULL
                       AND not_before <= ?3 AND expires_at > ?3",
                    params![digest.as_slice(), audience, now],
                    access_authority_from_sqlite_row,
                )
                .optional()
                .map_err(Into::into),
            Self::Postgres(store) => {
                let client = store.client().await?;
                client.query_opt(
                    "SELECT issuer, subject, audience, issued_at, not_before, expires_at, token_id,
                            actor_subject, scope, principal_kind, tenant_id, email, groups
                     FROM access_tokens
                     WHERE verifier_hash = $1 AND audience = $2 AND revoked_at IS NULL
                       AND not_before <= $3 AND expires_at > $3",
                    &[&digest, &audience, &now],
                )
                .await
                .map(|row| {
                    row.map(|row| AccessAuthority {
                        iss: row.get(0),
                        sub: row.get(1),
                        aud: row.get(2),
                        iat: row.get(3),
                        nbf: row.get(4),
                        exp: row.get(5),
                        jti: row.get(6),
                        act: Actor { sub: row.get(7) },
                        scope: row.get(8),
                        principal_kind: row.get(9),
                        tenant_id: row.get(10),
                        email: row.get(11),
                        groups: groups_from_storage(&row.get::<_, String>(12)),
                    })
                })
                .map_err(Into::into)
            }
        }
    }

    async fn revoke_session_and_subject_tokens(
        &self,
        credential: &str,
        subject: &str,
    ) -> Result<bool> {
        let now = unix_time()?;
        let digest = hash(credential);
        let changed = match self {
            Self::Sqlite(_) => {
                let connection = self.sqlite_connection()?;
                let changed = connection.execute(
                    "UPDATE sessions SET revoked_at = ?2
                     WHERE verifier_hash = ?1 AND revoked_at IS NULL",
                    params![digest.as_slice(), now],
                )?;
                connection.execute(
                    "UPDATE access_tokens SET revoked_at = ?2
                     WHERE subject = ?1 AND revoked_at IS NULL",
                    params![subject, now],
                )?;
                changed
            }
            Self::Postgres(store) => {
                let client = store.client().await?;
                let changed = client
                    .execute(
                        "UPDATE sessions SET revoked_at = $2
                         WHERE verifier_hash = $1 AND revoked_at IS NULL",
                        &[&digest, &now],
                    )
                    .await?;
                client
                    .execute(
                        "UPDATE access_tokens SET revoked_at = $2
                         WHERE subject = $1 AND revoked_at IS NULL",
                        &[&subject, &now],
                    )
                    .await?;
                usize::try_from(changed).unwrap_or(usize::MAX)
            }
        };
        Ok(changed > 0)
    }

    async fn ready(&self) -> Result<()> {
        match self {
            Self::Sqlite(_) => {
                self.sqlite_connection()?
                    .query_row("SELECT 1", [], |_| Ok(()))?;
            }
            Self::Postgres(store) => {
                let client = store.client().await?;
                client.simple_query("SELECT 1").await?;
            }
        }
        Ok(())
    }

    async fn prepare_insert(&self, now: i64, table: &str, maximum: i64) -> Result<()> {
        let (sqlite_count, postgres_count) = match table {
            "login_transactions" => (
                "SELECT count(*) FROM login_transactions",
                "SELECT count(*)::BIGINT FROM login_transactions",
            ),
            "authorization_codes" => (
                "SELECT count(*) FROM authorization_codes",
                "SELECT count(*)::BIGINT FROM authorization_codes",
            ),
            "sessions" => (
                "SELECT count(*) FROM sessions",
                "SELECT count(*)::BIGINT FROM sessions",
            ),
            "access_tokens" => (
                "SELECT count(*) FROM access_tokens",
                "SELECT count(*)::BIGINT FROM access_tokens",
            ),
            _ => bail!("unknown identity capacity table"),
        };
        let count = match self {
            Self::Sqlite(_) => {
                let connection = self.sqlite_connection()?;
                connection.execute(
                    "DELETE FROM login_transactions WHERE created_at <= ?1",
                    [now - LOGIN_LIFETIME_SECONDS],
                )?;
                connection.execute(
                    "DELETE FROM authorization_codes WHERE created_at <= ?1",
                    [now - CODE_LIFETIME_SECONDS],
                )?;
                connection.execute(
                    "DELETE FROM sessions
                     WHERE absolute_expires_at <= ?1 OR revoked_at IS NOT NULL",
                    [now],
                )?;
                connection.execute(
                    "DELETE FROM access_tokens WHERE expires_at <= ?1 OR revoked_at IS NOT NULL",
                    [now],
                )?;
                connection.query_row(sqlite_count, [], |row| row.get::<_, i64>(0))?
            }
            Self::Postgres(store) => {
                let client = store.client().await?;
                client
                    .execute(
                        "DELETE FROM login_transactions WHERE created_at <= $1",
                        &[&(now - LOGIN_LIFETIME_SECONDS)],
                    )
                    .await?;
                client
                    .execute(
                        "DELETE FROM authorization_codes WHERE created_at <= $1",
                        &[&(now - CODE_LIFETIME_SECONDS)],
                    )
                    .await?;
                client
                    .execute(
                        "DELETE FROM sessions
                         WHERE absolute_expires_at <= $1 OR revoked_at IS NOT NULL",
                        &[&now],
                    )
                    .await?;
                client
                    .execute(
                        "DELETE FROM access_tokens WHERE expires_at <= $1 OR revoked_at IS NOT NULL",
                        &[&now],
                    )
                    .await?;
                client
                    .query_one(postgres_count, &[])
                    .await?
                    .get::<_, i64>(0)
            }
        };
        if count >= maximum {
            bail!("identity {table} capacity of {maximum} records is exhausted");
        }
        Ok(())
    }

    /// Refuses a write that would exceed a finite row cap and returns the process-wide admission
    /// guard, so the caller's insert is serialized against a concurrent check exactly as the
    /// credential tables are.
    async fn enforce_row_caps(
        &self,
        caps: &[RowCap<'_>],
    ) -> Result<Option<tokio::sync::MutexGuard<'_, ()>>, HttpError> {
        let admission = self.capacity_admission().await;
        for cap in caps {
            let count = self
                .count_rows(cap.sqlite_count, cap.postgres_count, cap.arguments)
                .await
                .map_err(HttpError::internal)?;
            if count >= cap.maximum {
                return Err(HttpError::unprocessable(format!(
                    "identity {} capacity of {} records is exhausted",
                    cap.label, cap.maximum
                )));
            }
        }
        Ok(admission)
    }

    async fn count_rows(
        &self,
        sqlite_count: &str,
        postgres_count: &str,
        arguments: &[&str],
    ) -> Result<i64> {
        match self {
            Self::Sqlite(_) => self
                .sqlite_connection()?
                .query_row(sqlite_count, rusqlite::params_from_iter(arguments), |row| {
                    row.get(0)
                })
                .map_err(Into::into),
            Self::Postgres(store) => {
                let client = store.client().await?;
                let parameters = arguments
                    .iter()
                    .map(|value| value as &(dyn tokio_postgres::types::ToSql + Sync))
                    .collect::<Vec<_>>();
                Ok(client.query_one(postgres_count, &parameters).await?.get(0))
            }
        }
    }

    async fn capacity_admission(&self) -> Option<tokio::sync::MutexGuard<'_, ()>> {
        match self {
            Self::Sqlite(_) => None,
            Self::Postgres(store) => Some(store.capacity_admission.lock().await),
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

fn access_authority_from_sqlite_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<AccessAuthority> {
    Ok(AccessAuthority {
        iss: row.get(0)?,
        sub: row.get(1)?,
        aud: row.get(2)?,
        iat: row.get(3)?,
        nbf: row.get(4)?,
        exp: row.get(5)?,
        jti: row.get(6)?,
        act: Actor { sub: row.get(7)? },
        scope: row.get(8)?,
        principal_kind: row.get(9)?,
        tenant_id: row.get(10)?,
        email: row.get(11)?,
        groups: groups_from_storage(&row.get::<_, String>(12)?),
    })
}

fn groups_from_storage(value: &str) -> Vec<String> {
    value
        .split_ascii_whitespace()
        .map(ToOwned::to_owned)
        .collect()
}

/// One finite row cap on a durable, non-expiring table. Credential tables keep their own
/// expiry-plus-cap path; a directory or profile row is not a credential and never expires, so it
/// is bounded rather than collected.
struct RowCap<'a> {
    sqlite_count: &'a str,
    postgres_count: &'a str,
    arguments: &'a [&'a str],
    maximum: i64,
    label: &'a str,
}

#[derive(Debug)]
struct LoginTransaction {
    upstream_state: String,
    provider_id: String,
    created_at: i64,
    client_id: String,
    redirect_uri: String,
    client_state: String,
    client_nonce: String,
    client_code_challenge: String,
    requested_audience: Option<String>,
    requested_scope: Option<String>,
    upstream_nonce: String,
    upstream_pkce_verifier: String,
    link_subject: Option<String>,
    link_tenant_id: Option<String>,
}

#[derive(Debug)]
struct PendingAuthorization {
    created_at: i64,
    client_id: String,
    redirect_uri: String,
    code_challenge: String,
    subject: String,
    tenant_id: String,
    email: Option<String>,
    requested_audience: Option<String>,
    requested_scope: Option<String>,
}

#[derive(Debug)]
struct Identity {
    subject: String,
    email: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(deny_unknown_fields)]
struct IdentityLink {
    provider_id: String,
    issuer: String,
    email: Option<String>,
    linked_at: i64,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct IdentityLinkStart {
    authorization_url: String,
}

#[derive(Debug, Deserialize)]
struct AuthorizeQuery {
    response_type: String,
    client_id: String,
    redirect_uri: String,
    scope: String,
    state: String,
    #[serde(default)]
    nonce: Option<String>,
    code_challenge: String,
    code_challenge_method: String,
    /// Deployment-configured upstream provider id. Required when more than one is configured.
    #[serde(default)]
    identity_provider: Option<String>,
    /// RFC 8707 resource indicator. When present, the authorization code yields a short-lived
    /// access token for this exact registered audience rather than an Identity browser session.
    #[serde(default)]
    resource: Option<String>,
    /// The mailbox to sign in as, read only by a loopback development build. A deployed Identity
    /// does not have this field, so the standard parameter is ignored there as any unknown one is.
    #[cfg(feature = "local-login")]
    login_hint: Option<String>,
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
    #[serde(default)]
    resource: Option<String>,
    #[serde(default)]
    scope: Option<String>,
}

#[derive(Debug, Serialize)]
struct LoginMetadata {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    access_token_endpoint: String,
    cli_client_id: String,
    response_types_supported: [&'static str; 1],
    grant_types_supported: [&'static str; 1],
    code_challenge_methods_supported: [&'static str; 1],
}

#[derive(Debug, Serialize)]
struct AuthorizationServerMetadata {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    response_types_supported: [&'static str; 1],
    grant_types_supported: [&'static str; 1],
    code_challenge_methods_supported: [&'static str; 1],
    token_endpoint_auth_methods_supported: [&'static str; 1],
    scopes_supported: Vec<String>,
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

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct SessionAuthority {
    iss: String,
    sub: String,
    aud: String,
    exp: i64,
    email: Option<String>,
    tenant_id: String,
    groups: Vec<String>,
}

#[derive(Debug)]
struct AdmittedSession {
    tenant_id: String,
    subject: String,
    email: Option<String>,
    expires_at: i64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AccessTokenRequest {
    audience: String,
    scope: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AccessExchangeRequest {
    source_audience: String,
    audience: String,
    scope: String,
}

#[derive(Debug, Serialize)]
struct AccessTokenResponse {
    access_token: String,
    token_type: &'static str,
    expires_in: i64,
    audience: String,
    scope: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
struct Actor {
    sub: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
struct AccessAuthority {
    iss: String,
    sub: String,
    aud: String,
    iat: i64,
    nbf: i64,
    exp: i64,
    jti: String,
    act: Actor,
    scope: String,
    principal_kind: String,
    tenant_id: String,
    email: Option<String>,
    groups: Vec<String>,
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

    fn forbidden(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            code: "access_denied",
            message: message.into(),
        }
    }

    fn missing(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            code: "not_found",
            message: message.into(),
        }
    }

    /// A syntactically valid request refused by a durable rule such as a closed epistemic state,
    /// a screened value, or an exhausted row cap.
    fn unprocessable(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::UNPROCESSABLE_ENTITY,
            code: "invalid_request",
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
pub async fn discover_upstreams(
    config: &Config,
    client: &openidconnect::reqwest::Client,
) -> Result<BTreeMap<String, CoreProviderMetadata>> {
    if config.upstream_providers.is_empty() {
        bail!("at least one upstream OpenID Connect provider is required");
    }
    let mut discovered = BTreeMap::new();
    for provider in &config.upstream_providers {
        provider.validate()?;
        let metadata = CoreProviderMetadata::discover_async(
            IssuerUrl::new(provider.issuer.clone()).context("upstream issuer URL")?,
            client,
        )
        .await
        .with_context(|| format!("discover upstream OpenID Connect provider {}", provider.id))?;
        if discovered.insert(provider.id.clone(), metadata).is_some() {
            bail!("upstream provider ids must be unique");
        }
    }
    Ok(discovered)
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/livez", get(liveness))
        .route("/readyz", get(readiness))
        .route("/healthz", get(readiness))
        .route("/.well-known/identity-cli-login", get(login_metadata))
        .route(
            "/.well-known/oauth-authorization-server",
            get(authorization_server_metadata),
        )
        .route("/oauth/authorize", get(authorize))
        .route("/oauth/callback/upstream", get(upstream_callback))
        .route("/oauth/token", post(exchange_token))
        .route("/v1/session-authority", get(session_authority))
        .route("/v1/access-token", post(issue_access_token))
        .route("/v1/access-exchange", post(exchange_access_token))
        .route("/v1/access-authority", get(verify_access_token))
        .route("/v1/logout", post(logout))
        .route("/v1/identity-links", get(list_identity_links))
        .route(
            "/v1/identity-links/{provider_id}",
            post(start_identity_link).delete(remove_identity_link),
        )
        .merge(directory_router())
        .merge(profile_router())
        .layer(DefaultBodyLimit::max(MAX_HTTP_BODY_BYTES))
        .with_state(state)
}

/// Organization membership and group routes. Reads require an exact directory audience and an
/// Identity session; writes additionally require the deployment-configured directory
/// administration static group.
fn directory_router() -> Router<AppState> {
    Router::new()
        .route(
            "/v1/directory/membership",
            get(directory::read_own_membership),
        )
        .route(
            "/v1/directory/members/{subject}",
            put(directory::upsert_member),
        )
        .route(
            "/v1/directory/groups/{group_key}",
            get(directory::read_group_view).put(directory::upsert_group),
        )
        .route(
            "/v1/directory/groups/{group_key}/members/{subject}",
            put(directory::add_group_member).delete(directory::remove_group_member),
        )
}

/// Personal collaboration profile routes. Every one of them is self-scoped: the subject of the
/// presented session is the subject of the profile, and no route reaches another principal.
fn profile_router() -> Router<AppState> {
    Router::new()
        .route("/v1/profile", get(profile::read_profile))
        .route("/v1/profile/consent", put(profile::put_consent))
        .route("/v1/profile/snapshot", get(profile::read_snapshot))
        .route("/v1/profile/statements", post(profile::create_statement))
        .route(
            "/v1/profile/statements/{statement_id}",
            delete(profile::forget_statement),
        )
        .route(
            "/v1/profile/statements/{statement_id}/confirm",
            post(profile::confirm_statement),
        )
        .route(
            "/v1/profile/statements/{statement_id}/revoke",
            post(profile::revoke_statement),
        )
        .route(
            "/v1/profile/statements/{statement_id}/correct",
            post(profile::correct_statement),
        )
}

/// Resolves the presented Identity session for one exact internal audience.
///
/// This is the same admission the status authority endpoint performs: an allowlisted in-cluster
/// caller presents the person's own session together with the exact audience it was sent to. It
/// never turns a session into an independently reusable token and never reaches another subject.
async fn admitted_session_for_audience(
    state: &AppState,
    headers: &HeaderMap,
    audience: &str,
) -> Result<AdmittedSession, HttpError> {
    admitted_session_for_audiences(state, headers, &[audience]).await
}

/// The same admission for a route reachable from more than one exact audience. The route's
/// audience set is the boundary: a caller presenting a different admitted audience is refused
/// here rather than inside the handler.
async fn admitted_session_for_audiences(
    state: &AppState,
    headers: &HeaderMap,
    audiences: &[&str],
) -> Result<AdmittedSession, HttpError> {
    if !audiences
        .iter()
        .any(|audience| audience_matches(headers, audience))
    {
        return Err(HttpError::denied("an exact admitted audience is required"));
    }
    let credential = bearer(headers, valid_session_credential)
        .ok_or_else(|| HttpError::denied("a valid Identity session is required"))?;
    state
        .store
        .resolve_session(credential, &state.config)
        .await
        .map_err(HttpError::internal)?
        .ok_or_else(|| HttpError::denied("the Identity session is expired or revoked"))
}

fn audience_matches(headers: &HeaderMap, audience: &str) -> bool {
    requested_audience(headers).is_some_and(|value| value == audience)
}

fn requested_audience(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("x-b10x-audience")
        .and_then(|value| value.to_str().ok())
}

async fn liveness() -> &'static str {
    "ok\n"
}

async fn readiness(State(state): State<AppState>) -> Response {
    match state.store.ready().await {
        Ok(()) => (StatusCode::OK, "ok\n").into_response(),
        Err(error) => {
            tracing::warn!(%error, "identity readiness check failed");
            (StatusCode::SERVICE_UNAVAILABLE, "not ready\n").into_response()
        }
    }
}

async fn login_metadata(State(state): State<AppState>) -> Json<LoginMetadata> {
    let origin = state.config.public_origin.as_str().trim_end_matches('/');
    Json(LoginMetadata {
        issuer: origin.to_owned(),
        authorization_endpoint: format!("{origin}/oauth/authorize"),
        token_endpoint: format!("{origin}/oauth/token"),
        access_token_endpoint: format!("{origin}/v1/access-token"),
        cli_client_id: state.config.cli_client_id.clone(),
        response_types_supported: ["code"],
        grant_types_supported: ["authorization_code"],
        code_challenge_methods_supported: ["S256"],
    })
}

async fn authorization_server_metadata(
    State(state): State<AppState>,
) -> Json<AuthorizationServerMetadata> {
    let origin = state.config.public_origin.as_str().trim_end_matches('/');
    Json(AuthorizationServerMetadata {
        issuer: origin.to_owned(),
        authorization_endpoint: format!("{origin}/oauth/authorize"),
        token_endpoint: format!("{origin}/oauth/token"),
        response_types_supported: ["code"],
        grant_types_supported: ["authorization_code"],
        code_challenge_methods_supported: ["S256"],
        token_endpoint_auth_methods_supported: ["none"],
        scopes_supported: state.config.audience_registry.advertised_access_scopes(),
    })
}

async fn issue_access_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<AccessTokenRequest>,
) -> Result<Response, HttpError> {
    let credential = bearer(&headers, valid_session_credential)
        .ok_or_else(|| HttpError::denied("a valid Identity session is required"))?;
    let admitted = state
        .store
        .resolve_session(credential, &state.config)
        .await
        .map_err(HttpError::internal)?
        .ok_or_else(|| HttpError::denied("the Identity session is expired or revoked"))?;
    let _ = admitted.expires_at;
    mint_access_token(
        &state,
        request.audience,
        &request.scope,
        admitted.tenant_id,
        admitted.subject,
        admitted.email,
    )
    .await
}

async fn exchange_access_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<AccessExchangeRequest>,
) -> Result<Response, HttpError> {
    let caller_id = headers
        .get("x-b10x-access-exchange-caller")
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| HttpError::denied("a confidential exchange caller is required"))?;
    let supplied_secret = headers
        .get("x-b10x-access-exchange-secret")
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| HttpError::denied("a confidential exchange caller is required"))?;
    let caller = state
        .config
        .trusted_access_callers
        .iter()
        .find(|caller| caller.id == caller_id)
        .filter(|caller| constant_time_secret_eq(caller.secret.expose_secret(), supplied_secret))
        .ok_or_else(|| HttpError::denied("the confidential exchange caller was refused"))?;

    let requested_target_scopes = canonical_requested_scopes(&request.scope)?;
    let policy = state
        .config
        .access_exchange_policies
        .iter()
        .find(|policy| {
            policy.caller_id == caller.id
                && policy.source_audience == request.source_audience
                && policy.target_audience == request.audience
                && requested_target_scopes
                    .iter()
                    .all(|scope| policy.allowed_target_scopes.contains(*scope))
        })
        .ok_or_else(|| HttpError::forbidden("the requested access exchange is not admitted"))?;
    if state
        .config
        .audience_registry
        .access_policy(&request.source_audience)
        .is_none()
        || state
            .config
            .audience_registry
            .access_policy(&request.audience)
            .is_none()
    {
        return Err(HttpError::forbidden(
            "the requested access exchange audiences are not registered",
        ));
    }
    let source_credential = bearer(&headers, valid_access_credential)
        .ok_or_else(|| HttpError::denied("a valid source access token is required"))?;
    let source = state
        .store
        .resolve_access_token(source_credential, &request.source_audience)
        .await
        .map_err(HttpError::internal)?
        .ok_or_else(|| HttpError::denied("the source access token is expired or revoked"))?;
    let source_scopes = canonical_requested_scopes(&source.scope)?;
    if source.principal_kind != "human"
        || source.act.sub != source.sub
        || !policy
            .required_source_scopes
            .iter()
            .all(|scope| source_scopes.contains(scope.as_str()))
    {
        return Err(HttpError::forbidden(
            "the source authority does not admit this exchange",
        ));
    }
    mint_access_token(
        &state,
        request.audience,
        &request.scope,
        source.tenant_id,
        source.sub,
        source.email,
    )
    .await
}

async fn mint_access_token(
    state: &AppState,
    audience: String,
    requested_scope: &str,
    tenant_id: String,
    subject: String,
    email: Option<String>,
) -> Result<Response, HttpError> {
    let policy = state
        .config
        .audience_registry
        .access_policy(&audience)
        .ok_or_else(|| HttpError::denied("the requested audience is not admitted"))?;
    let groups = state
        .config
        .static_group_memberships
        .groups_for(&tenant_id, email.as_deref());
    let scope = policy.admit(requested_scope, &groups)?;
    let now = unix_time().map_err(HttpError::internal)?;
    let credential = format!(
        "identity_access_v1_{}",
        random_token(32).map_err(HttpError::internal)?
    );
    let authority = AccessAuthority {
        iss: state
            .config
            .public_origin
            .as_str()
            .trim_end_matches('/')
            .to_owned(),
        sub: subject.clone(),
        aud: audience,
        iat: now,
        nbf: now,
        exp: now + ACCESS_TOKEN_LIFETIME_SECONDS,
        jti: format!(
            "identity_jti_v1_{}",
            random_token(16).map_err(HttpError::internal)?
        ),
        act: Actor { sub: subject },
        scope: scope.clone(),
        principal_kind: "human".to_owned(),
        tenant_id,
        email,
        groups,
    };
    state
        .store
        .put_access_token(&credential, &authority)
        .await
        .map_err(HttpError::internal)?;
    Ok(confidential_json(AccessTokenResponse {
        access_token: credential,
        token_type: "Bearer",
        expires_in: ACCESS_TOKEN_LIFETIME_SECONDS,
        audience: authority.aud,
        scope,
    }))
}

async fn session_authority(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, HttpError> {
    let audience = requested_audience(&headers)
        .filter(|audience| state.config.audience_registry.admits_session(audience))
        .ok_or_else(|| HttpError::denied("an exact admitted audience is required"))?;
    let admitted = admitted_session_for_audience(&state, &headers, audience).await?;
    let groups = state
        .config
        .static_group_memberships
        .groups_for(&admitted.tenant_id, admitted.email.as_deref());
    Ok(confidential_json(SessionAuthority {
        iss: state.config.issuer().to_owned(),
        sub: admitted.subject,
        aud: audience.to_owned(),
        exp: admitted.expires_at,
        email: admitted.email,
        tenant_id: admitted.tenant_id,
        groups,
    }))
}

async fn verify_access_token(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, HttpError> {
    let audience = requested_audience(&headers)
        .filter(|audience| {
            state
                .config
                .audience_registry
                .access_policy(audience)
                .is_some()
        })
        .ok_or_else(|| HttpError::denied("an exact admitted audience is required"))?;
    let credential = bearer(&headers, valid_access_credential)
        .ok_or_else(|| HttpError::denied("a valid short-lived access token is required"))?;
    let authority = state
        .store
        .resolve_access_token(credential, audience)
        .await
        .map_err(HttpError::internal)?
        .ok_or_else(|| HttpError::denied("the access token is expired or revoked"))?;
    Ok(confidential_json(authority))
}

async fn logout(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<StatusCode, HttpError> {
    let credential = bearer(&headers, valid_session_credential)
        .ok_or_else(|| HttpError::denied("a valid Identity session is required"))?;
    let admitted = state
        .store
        .resolve_session(credential, &state.config)
        .await
        .map_err(HttpError::internal)?
        .ok_or_else(|| HttpError::denied("the Identity session is expired or revoked"))?;
    if !state
        .store
        .revoke_session_and_subject_tokens(credential, &admitted.subject)
        .await
        .map_err(HttpError::internal)?
    {
        return Err(HttpError::denied(
            "the Identity session is expired or revoked",
        ));
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn admitted_session_for_link_management(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<AdmittedSession, HttpError> {
    let audience = requested_audience(headers)
        .filter(|audience| state.config.audience_registry.admits_session(audience))
        .ok_or_else(|| HttpError::denied("an exact admitted session audience is required"))?;
    admitted_session_for_audience(state, headers, audience).await
}

async fn list_identity_links(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, HttpError> {
    let admitted = admitted_session_for_link_management(&state, &headers).await?;
    let links = state
        .store
        .identity_links_for(&admitted.tenant_id, &admitted.subject)
        .await
        .map_err(HttpError::internal)?;
    Ok(confidential_json(links))
}

async fn start_identity_link(
    State(state): State<AppState>,
    AxumPath(provider_id): AxumPath<String>,
    headers: HeaderMap,
) -> Result<Response, HttpError> {
    let admitted = admitted_session_for_link_management(&state, &headers).await?;
    let provider = selected_upstream_provider(&state.config, Some(&provider_id))?;
    if state
        .store
        .identity_links_for(&admitted.tenant_id, &admitted.subject)
        .await
        .map_err(HttpError::internal)?
        .iter()
        .any(|link| link.provider_id == provider.id)
    {
        return Err(HttpError::unprocessable(
            "this provider is already linked to the current person",
        ));
    }
    let metadata = state
        .upstreams
        .get(&provider.id)
        .ok_or_else(|| HttpError::internal("selected upstream provider was not discovered"))?;
    let upstream_state = random_token(32).map_err(HttpError::internal)?;
    let upstream_nonce = random_token(32).map_err(HttpError::internal)?;
    let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
    let callback = state
        .config
        .public_origin
        .join("oauth/callback/upstream")
        .map_err(HttpError::internal)?;
    let client = CoreClient::from_provider_metadata(
        metadata.clone(),
        ClientId::new(provider.client_id.clone()),
        Some(ClientSecret::new(
            provider.client_secret.expose_secret_owned(),
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
            provider_id: provider.id.clone(),
            created_at: unix_time().map_err(HttpError::internal)?,
            client_id: String::new(),
            redirect_uri: String::new(),
            client_state: String::new(),
            client_nonce: String::new(),
            client_code_challenge: String::new(),
            requested_audience: None,
            requested_scope: None,
            upstream_nonce,
            upstream_pkce_verifier: verifier.secret().clone(),
            link_subject: Some(admitted.subject),
            link_tenant_id: Some(admitted.tenant_id),
        })
        .await
        .map_err(HttpError::internal)?;
    Ok(confidential_json(IdentityLinkStart {
        authorization_url: authorization_url.to_string(),
    }))
}

async fn remove_identity_link(
    State(state): State<AppState>,
    AxumPath(provider_id): AxumPath<String>,
    headers: HeaderMap,
) -> Result<StatusCode, HttpError> {
    let admitted = admitted_session_for_link_management(&state, &headers).await?;
    if !state
        .store
        .remove_identity_link(&admitted.tenant_id, &admitted.subject, &provider_id)
        .await
        .map_err(HttpError::internal)?
    {
        return Err(HttpError::unprocessable(
            "the provider is not linked or is the final login method",
        ));
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn authorize(
    State(state): State<AppState>,
    Query(query): Query<AuthorizeQuery>,
) -> Result<Response, HttpError> {
    validate_authorization_request(&state.config, &query)?;
    if query.identity_provider.is_none() && state.config.upstream_providers.len() > 1 {
        return Ok(provider_selection(&state.config, &query));
    }
    // A loopback development build has no provider to redirect to, and signs the request in itself.
    #[cfg(feature = "local-login")]
    if local_login::admitted(&state.config) {
        return local_login::complete(&state.config, &state.store, &query).await;
    }
    let provider = selected_upstream_provider(&state.config, query.identity_provider.as_deref())?;
    let metadata = state
        .upstreams
        .get(&provider.id)
        .ok_or_else(|| HttpError::internal("selected upstream provider was not discovered"))?;
    let upstream_state = random_token(32).map_err(HttpError::internal)?;
    let upstream_nonce = random_token(32).map_err(HttpError::internal)?;
    let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
    let callback = state
        .config
        .public_origin
        .join("oauth/callback/upstream")
        .map_err(HttpError::internal)?;
    let client = CoreClient::from_provider_metadata(
        metadata.clone(),
        ClientId::new(provider.client_id.clone()),
        Some(ClientSecret::new(
            provider.client_secret.expose_secret_owned(),
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
            provider_id: provider.id.clone(),
            created_at: unix_time().map_err(HttpError::internal)?,
            client_id: query.client_id,
            redirect_uri: query.redirect_uri,
            client_state: query.state,
            client_nonce: query.nonce.unwrap_or_default(),
            client_code_challenge: query.code_challenge,
            requested_audience: query.resource,
            requested_scope: Some(query.scope),
            upstream_nonce,
            upstream_pkce_verifier: verifier.secret().clone(),
            link_subject: None,
            link_tenant_id: None,
        })
        .await
        .map_err(HttpError::internal)?;
    Ok(Redirect::temporary(authorization_url.as_str()).into_response())
}

fn provider_selection(config: &Config, query: &AuthorizeQuery) -> Response {
    let mut hidden = String::new();
    for (name, value) in [
        ("response_type", Some(query.response_type.as_str())),
        ("client_id", Some(query.client_id.as_str())),
        ("redirect_uri", Some(query.redirect_uri.as_str())),
        ("scope", Some(query.scope.as_str())),
        ("state", Some(query.state.as_str())),
        ("nonce", query.nonce.as_deref()),
        ("code_challenge", Some(query.code_challenge.as_str())),
        (
            "code_challenge_method",
            Some(query.code_challenge_method.as_str()),
        ),
        ("resource", query.resource.as_deref()),
    ] {
        if let Some(value) = value {
            let _ = write!(
                hidden,
                "<input type=\"hidden\" name=\"{name}\" value=\"{}\">",
                html_escape(value)
            );
        }
    }
    let mut choices = String::new();
    for provider in &config.upstream_providers {
        let _ = write!(
            choices,
            "<button name=\"identity_provider\" value=\"{}\" type=\"submit\">{}</button>",
            html_escape(&provider.id),
            html_escape(&provider.label)
        );
    }
    let mut response = Html(format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Choose a sign-in provider</title><style>body{{font:16px/1.5 system-ui,sans-serif;margin:4rem auto;max-width:34rem;padding:0 1rem}}form{{display:grid;gap:.75rem}}button{{font:inherit;padding:.7rem 1rem;text-align:left}}</style></head><body><h1>Choose a sign-in provider</h1><p>Continue with one of the identities configured for this deployment.</p><form method=\"get\" action=\"/oauth/authorize\">{hidden}{choices}</form></body></html>"
    ))
    .into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// Whether a loopback development build may complete a sign-in without an upstream provider.
///
/// Exists so `main.rs` refuses to serve at all when this binary carries the local development
/// login and the configuration is not a loopback one.
#[cfg(feature = "local-login")]
#[must_use]
pub fn local_login_admitted(config: &Config) -> bool {
    local_login::admitted(config)
}

#[allow(clippy::too_many_lines)]
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
    let provider = state
        .config
        .upstream_providers
        .iter()
        .find(|provider| provider.id == login.provider_id)
        .ok_or_else(|| HttpError::denied("login provider is no longer configured"))?;
    let metadata = state
        .upstreams
        .get(&provider.id)
        .ok_or_else(|| HttpError::internal("login provider was not discovered"))?;
    let callback = state
        .config
        .public_origin
        .join("oauth/callback/upstream")
        .map_err(HttpError::internal)?;
    let client = CoreClient::from_provider_metadata(
        metadata.clone(),
        ClientId::new(provider.client_id.clone()),
        Some(ClientSecret::new(
            provider.client_secret.expose_secret_owned(),
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
    // consulting a deployment-selected organization claim.
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
    let tenant_id = state
        .config
        .upstream_providers
        .iter()
        .find(|candidate| candidate.id == login.provider_id)
        .ok_or_else(|| HttpError::denied("login provider is no longer configured"))?
        .organization_domain_policy
        .resolve_tenant(&claims.additional_claims().0, &state.config.tenant_id)
        .ok_or_else(|| {
            HttpError::denied("upstream organization is not admitted by this deployment")
        })?;
    if claims.email().is_some() && claims.email_verified() != Some(true) {
        return Err(HttpError::denied("upstream email address is not verified"));
    }
    let upstream_subject = claims.subject().as_str().to_owned();
    let upstream_email = claims.email().map(|email| email.as_str().to_owned());
    if let (Some(link_subject), Some(link_tenant_id)) = (
        login.link_subject.as_deref(),
        login.link_tenant_id.as_deref(),
    ) {
        if link_tenant_id != tenant_id {
            return Err(HttpError::denied(
                "the linked identity resolved to a different tenant",
            ));
        }
        if let Some(existing) = state
            .store
            .resolve_identity_link(
                &tenant_id,
                &provider.id,
                &provider.issuer,
                &upstream_subject,
            )
            .await
            .map_err(HttpError::internal)?
        {
            if existing.subject != link_subject {
                return Err(HttpError::denied(
                    "this upstream identity is already linked to another person",
                ));
            }
        } else {
            let linked = state
                .store
                .put_identity_link(
                    &tenant_id,
                    &provider.id,
                    &provider.issuer,
                    &upstream_subject,
                    &Identity {
                        subject: link_subject.to_owned(),
                        email: upstream_email,
                    },
                    unix_time().map_err(HttpError::internal)?,
                )
                .await
                .map_err(HttpError::internal)?;
            if !linked {
                return Err(HttpError::denied(
                    "this provider is already linked or belongs to another person",
                ));
            }
        }
        return Ok(Html(
            "<!doctype html><title>Identity linked</title><h1>Identity linked</h1><p>You can return to Devcenter.</p>"
                .to_owned(),
        )
        .into_response());
    }
    let identity = if let Some(linked) = state
        .store
        .resolve_identity_link(
            &tenant_id,
            &provider.id,
            &provider.issuer,
            &upstream_subject,
        )
        .await
        .map_err(HttpError::internal)?
    {
        linked
    } else {
        let subject = if state
            .config
            .upstream_providers
            .first()
            .map(|entry| &entry.id)
            == Some(&provider.id)
        {
            // The first configured provider is the legacy provider. Retaining its upstream
            // subject preserves every resource already keyed by (tenant, subject).
            upstream_subject.clone()
        } else {
            format!(
                "identity_person_v1_{}",
                random_token(24).map_err(HttpError::internal)?
            )
        };
        let identity = Identity {
            subject,
            email: upstream_email,
        };
        if state
            .store
            .put_identity_link(
                &tenant_id,
                &provider.id,
                &provider.issuer,
                &upstream_subject,
                &identity,
                unix_time().map_err(HttpError::internal)?,
            )
            .await
            .map_err(HttpError::internal)?
        {
            identity
        } else {
            state
                .store
                .resolve_identity_link(
                    &tenant_id,
                    &provider.id,
                    &provider.issuer,
                    &upstream_subject,
                )
                .await
                .map_err(HttpError::internal)?
                .ok_or_else(|| HttpError::denied("upstream identity could not be linked"))?
        }
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
                tenant_id,
                email: identity.email,
                requested_audience: login.requested_audience,
                requested_scope: login.requested_scope,
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
) -> Result<Response, HttpError> {
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
    if let Some(audience) = authorization.requested_audience {
        if request.resource.as_deref() != Some(audience.as_str()) {
            return Err(HttpError::denied("authorization resource binding failed"));
        }
        let scope = authorization
            .requested_scope
            .ok_or_else(|| HttpError::internal("authorization scope is absent"))?;
        if request
            .scope
            .as_deref()
            .is_some_and(|requested| requested != scope)
        {
            return Err(HttpError::denied("authorization scope binding failed"));
        }
        return mint_access_token(
            &state,
            audience,
            &scope,
            authorization.tenant_id,
            authorization.subject,
            authorization.email,
        )
        .await;
    }
    if request.resource.is_some() {
        return Err(HttpError::denied("authorization resource binding failed"));
    }
    let credential = format!(
        "identity_session_v1_{}",
        random_token(32).map_err(HttpError::internal)?
    );
    let identity = Identity {
        subject: authorization.subject,
        email: authorization.email,
    };
    state
        .store
        .put_session(
            &credential,
            &state.config,
            &authorization.tenant_id,
            &identity,
        )
        .await
        .map_err(HttpError::internal)?;
    Ok(confidential_json(SessionResponse {
        session: credential,
        session_type: "opaque_server_session",
        expires_in: SESSION_IDLE_SECONDS,
        tenant_id: authorization.tenant_id,
        subject: identity.subject,
        email: identity.email,
    }))
}

fn confidential_json<T: Serialize>(value: T) -> Response {
    (
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::PRAGMA, "no-cache"),
        ],
        Json(value),
    )
        .into_response()
}

fn validate_authorization_request(
    config: &Config,
    query: &AuthorizeQuery,
) -> Result<(), HttpError> {
    if query.response_type != "code" {
        return Err(HttpError::invalid("response_type must be code"));
    }
    if query.client_id == config.cli_client_id {
        validate_loopback_redirect(&query.redirect_uri)?;
    } else {
        let admitted = config.web_clients.iter().any(|client| {
            client.client_id == query.client_id
                && client.redirect_uri.as_str() == query.redirect_uri
        });
        if !admitted {
            return Err(HttpError::denied("unknown client_id or redirect_uri"));
        }
    }
    let scopes = canonical_requested_scopes(&query.scope)?;
    if let Some(resource) = query.resource.as_deref() {
        if config.audience_registry.access_policy(resource).is_none() {
            return Err(HttpError::denied("the requested resource is not admitted"));
        }
    } else if !scopes.contains("openid") {
        return Err(HttpError::invalid("scope must contain openid"));
    }
    if query.code_challenge_method != "S256" || !valid_b64_token(&query.code_challenge, 43, 43) {
        return Err(HttpError::invalid(
            "a valid S256 PKCE challenge is required",
        ));
    }
    if !valid_b64_token(&query.state, 32, 512) {
        return Err(HttpError::invalid("state must carry at least 192 bits"));
    }
    if query.resource.is_none()
        && !query
            .nonce
            .as_deref()
            .is_some_and(|nonce| valid_b64_token(nonce, 32, 512))
    {
        return Err(HttpError::invalid("nonce must carry at least 192 bits"));
    }
    Ok(())
}

fn selected_upstream_provider<'a>(
    config: &'a Config,
    requested: Option<&str>,
) -> Result<&'a UpstreamProvider, HttpError> {
    if let Some(requested) = requested {
        return config
            .upstream_providers
            .iter()
            .find(|provider| provider.id == requested)
            .ok_or_else(|| HttpError::invalid("identity_provider is not configured"));
    }
    match config.upstream_providers.as_slice() {
        [provider] => Ok(provider),
        [] => Err(HttpError::internal("no upstream provider is configured")),
        _ => Err(HttpError::invalid(
            "identity_provider is required when multiple providers are configured",
        )),
    }
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
        .strip_prefix("identity_session_v1_")
        .is_some_and(|token| valid_b64_token(token, 43, 43))
}

fn valid_access_credential(value: &str) -> bool {
    value
        .strip_prefix("identity_access_v1_")
        .is_some_and(|token| valid_b64_token(token, 43, 43))
}

fn bearer(headers: &HeaderMap, validator: fn(&str) -> bool) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .filter(|credential| validator(credential))
}

fn normalize_registered_scopes(scopes: Vec<String>) -> Result<BTreeSet<String>> {
    let mut normalized = BTreeSet::new();
    for scope in scopes {
        if !valid_scope_name(&scope) || !normalized.insert(scope.clone()) {
            bail!("Identity access scopes must be unique bounded printable ASCII names");
        }
    }
    Ok(normalized)
}

fn canonical_requested_scopes(value: &str) -> Result<BTreeSet<&str>, HttpError> {
    if value.is_empty() || value.len() > 1024 {
        return Err(HttpError::invalid("a bounded scope set is required"));
    }
    let requested = value.split_ascii_whitespace().collect::<Vec<_>>();
    if requested.is_empty()
        || requested.join(" ") != value
        || requested.iter().any(|scope| !valid_scope_name(scope))
    {
        return Err(HttpError::invalid(
            "scopes must be canonical bounded printable ASCII names",
        ));
    }
    let scopes = requested.iter().copied().collect::<BTreeSet<_>>();
    if scopes.len() != requested.len() {
        return Err(HttpError::invalid("scopes must not repeat"));
    }
    Ok(scopes)
}

fn valid_scope_name(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b':' | b'/' | b'_' | b'-')
        })
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

fn constant_time_secret_eq(expected: &str, supplied: &str) -> bool {
    let expected = Sha256::digest(expected.as_bytes());
    let supplied = Sha256::digest(supplied.as_bytes());
    expected
        .iter()
        .zip(supplied.iter())
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

fn ensure_sqlite_column(
    connection: &Connection,
    table: &str,
    column: &str,
    declaration: &str,
) -> Result<()> {
    let mut statement = connection.prepare(&format!("PRAGMA table_info({table})"))?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        if row.get::<_, String>(1)? == column {
            return Ok(());
        }
    }
    connection.execute_batch(&format!(
        "ALTER TABLE {table} ADD COLUMN {column} {declaration}"
    ))?;
    Ok(())
}

#[cfg(unix)]
fn validate_private_state_path(path: &Path, directory: bool) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("inspect identity state path {}", path.display()))?;
    if metadata.file_type().is_symlink()
        || (directory && !metadata.is_dir())
        || (!directory && !metadata.is_file())
    {
        bail!(
            "identity state path {} must be a non-symlink {}",
            path.display(),
            if directory {
                "directory"
            } else {
                "regular file"
            }
        );
    }
    if metadata.uid() != nix::unistd::getuid().as_raw() {
        bail!("identity state path {} has the wrong owner", path.display());
    }
    let forbidden = if directory { 0o077 } else { 0o177 };
    if metadata.permissions().mode() & forbidden != 0 {
        bail!(
            "identity state path {} grants access outside its owner",
            path.display()
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_private_state_path(_path: &Path, _directory: bool) -> Result<()> {
    bail!("filesystem-backed Identity state requires Unix ownership enforcement")
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

    fn access_policy() -> AccessAudiencePolicy {
        AccessAudiencePolicy::new(
            vec!["resource.read".to_owned()],
            vec![("operator".to_owned(), vec!["resource.write".to_owned()])],
        )
        .unwrap()
    }

    fn audience_registry() -> AudienceRegistry {
        AudienceRegistry::new(
            vec![
                TEST_STATUS_AUDIENCE.to_owned(),
                TEST_ZWIRN_AUDIENCE.to_owned(),
            ],
            vec![(TEST_ACCESS_AUDIENCE.to_owned(), access_policy())],
        )
        .unwrap()
    }

    fn config() -> Config {
        Config {
            listen: "127.0.0.1:0".parse().unwrap(),
            public_origin: Url::parse("http://127.0.0.1:8080/").unwrap(),
            tenant_id: "tenant-dev".to_owned(),
            cli_client_id: "harness-cli".to_owned(),
            web_clients: vec![
                WebClient::new(
                    "status-web",
                    "https://code.example.test/status/oauth/callback",
                )
                .unwrap(),
            ],
            audience_registry: audience_registry(),
            upstream_providers: vec![UpstreamProvider {
                id: "default".to_owned(),
                label: "Example".to_owned(),
                issuer: "https://accounts.example.test".to_owned(),
                client_id: "upstream-client".to_owned(),
                client_secret: SecretValue::new("not-a-real-secret".to_owned()),
                organization_domain_policy: OrganizationDomainPolicy::default(),
            }],
            static_group_memberships: StaticGroupMemberships::new(vec![(
                "tenant-dev".to_owned(),
                "operator@example.test".to_owned(),
                vec!["operator".to_owned()],
            )])
            .unwrap(),
            trusted_access_callers: Vec::new(),
            access_exchange_policies: Vec::new(),
            database_url: None,
            database_path: PathBuf::new(),
        }
    }

    #[test]
    fn configuration_debug_redacts_secret_values() {
        let rendered = format!("{:?}", config());
        assert!(!rendered.contains("not-a-real-secret"));
        assert!(rendered.contains("[REDACTED]"));
    }

    #[test]
    fn audience_registry_is_exact_disjoint_and_part_of_session_generation() {
        for malformed in [
            " urn:b10x:status",
            "urn:b10x:status ",
            "urn:b10x:bad audience",
            "urn:b10x:bad,audience",
            "",
        ] {
            assert!(
                AudienceRegistry::new(vec![malformed.to_owned()], Vec::new()).is_err(),
                "malformed audience was accepted: {malformed:?}"
            );
        }
        assert!(
            AudienceRegistry::new(
                vec![TEST_STATUS_AUDIENCE.to_owned()],
                vec![(TEST_STATUS_AUDIENCE.to_owned(), access_policy(),)],
            )
            .is_err()
        );

        let original = config();
        let mut changed = config();
        changed.audience_registry = AudienceRegistry::new(
            vec![
                TEST_STATUS_AUDIENCE.to_owned(),
                "urn:example:console".to_owned(),
            ],
            vec![(TEST_ACCESS_AUDIENCE.to_owned(), access_policy())],
        )
        .unwrap();
        assert_ne!(
            original.configuration_generation(),
            changed.configuration_generation(),
            "changing admitted audiences must invalidate existing sessions"
        );
        assert!(
            changed
                .audience_registry
                .admits_session("urn:example:console")
        );
        assert!(!changed.audience_registry.admits_session("urn:b10x:other"));
    }

    fn authorization_query() -> AuthorizeQuery {
        AuthorizeQuery {
            response_type: "code".to_owned(),
            client_id: "harness-cli".to_owned(),
            redirect_uri: "http://127.0.0.1:43123/callback".to_owned(),
            scope: "openid profile email".to_owned(),
            state: random_token(32).unwrap(),
            nonce: Some(random_token(32).unwrap()),
            code_challenge: pkce_challenge(&"a".repeat(64)),
            code_challenge_method: "S256".to_owned(),
            identity_provider: None,
            resource: None,
            #[cfg(feature = "local-login")]
            login_hint: None,
        }
    }

    fn app_state(store: Store) -> AppState {
        AppState::new(
            Arc::new(config()),
            BTreeMap::new(),
            openidconnect::reqwest::ClientBuilder::new()
                .redirect(openidconnect::reqwest::redirect::Policy::none())
                .build()
                .unwrap(),
            store,
        )
    }

    #[tokio::test]
    async fn authorization_server_metadata_advertises_public_pkce_access() {
        let Json(metadata) =
            authorization_server_metadata(State(app_state(Store::in_memory().unwrap()))).await;
        assert_eq!(metadata.issuer, "http://127.0.0.1:8080");
        assert_eq!(
            metadata.authorization_endpoint,
            "http://127.0.0.1:8080/oauth/authorize"
        );
        assert_eq!(metadata.token_endpoint, "http://127.0.0.1:8080/oauth/token");
        assert_eq!(metadata.token_endpoint_auth_methods_supported, ["none"]);
        assert_eq!(metadata.code_challenge_methods_supported, ["S256"]);
        assert!(
            metadata
                .scopes_supported
                .contains(&"resource.read".to_owned())
        );
        assert!(
            metadata
                .scopes_supported
                .contains(&"resource.write".to_owned())
        );
    }

    #[tokio::test]
    async fn standard_authorization_shows_the_configured_provider_choices() {
        let mut config = config();
        config.upstream_providers.push(UpstreamProvider {
            id: "second".to_owned(),
            label: "Second provider".to_owned(),
            issuer: "https://second.example.test".to_owned(),
            client_id: "second-client".to_owned(),
            client_secret: SecretValue::new("second-secret".to_owned()),
            organization_domain_policy: OrganizationDomainPolicy::default(),
        });
        let state = AppState::new(
            Arc::new(config),
            BTreeMap::new(),
            openidconnect::reqwest::ClientBuilder::new()
                .redirect(openidconnect::reqwest::redirect::Policy::none())
                .build()
                .unwrap(),
            Store::in_memory().unwrap(),
        );
        let mut query = authorization_query();
        query.scope = "resource.read".to_owned();
        query.resource = Some(TEST_ACCESS_AUDIENCE.to_owned());
        query.nonce = None;
        let response = authorize(State(state), Query(query)).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), MAX_HTTP_BODY_BYTES)
            .await
            .unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();
        assert!(body.contains("Example"));
        assert!(body.contains("Second provider"));
        assert!(body.contains("name=\"resource\""));
        assert!(body.contains(TEST_ACCESS_AUDIENCE));
    }

    #[test]
    fn upstream_provider_selection_is_explicit_when_the_registry_has_choices() {
        let mut config = config();
        config.upstream_providers.push(UpstreamProvider {
            id: "second".to_owned(),
            label: "Second".to_owned(),
            issuer: "https://second.example.test".to_owned(),
            client_id: "second-client".to_owned(),
            client_secret: SecretValue::new("second-secret".to_owned()),
            organization_domain_policy: OrganizationDomainPolicy::default(),
        });
        assert!(selected_upstream_provider(&config, None).is_err());
        assert_eq!(
            selected_upstream_provider(&config, Some("second"))
                .unwrap()
                .issuer,
            "https://second.example.test"
        );
        assert!(selected_upstream_provider(&config, Some("missing")).is_err());
    }

    #[tokio::test]
    async fn external_identities_are_explicitly_linked_and_the_last_link_is_retained() {
        let store = Store::in_memory().unwrap();
        let identity = Identity {
            subject: "canonical-person".to_owned(),
            email: Some("person@example.test".to_owned()),
        };
        assert!(
            store
                .put_identity_link(
                    "tenant-dev",
                    "gitlab",
                    "https://gitlab.example.test",
                    "gitlab-subject",
                    &identity,
                    1,
                )
                .await
                .unwrap()
        );
        assert_eq!(
            store
                .resolve_identity_link(
                    "tenant-dev",
                    "gitlab",
                    "https://gitlab.example.test",
                    "gitlab-subject",
                )
                .await
                .unwrap()
                .unwrap()
                .subject,
            "canonical-person"
        );
        assert!(
            !store
                .remove_identity_link("tenant-dev", "canonical-person", "gitlab")
                .await
                .unwrap(),
            "the final login method must not be removed"
        );
        assert!(
            store
                .put_identity_link(
                    "tenant-dev",
                    "slack",
                    "https://slack.com",
                    "slack-subject",
                    &identity,
                    2,
                )
                .await
                .unwrap()
        );
        assert!(
            store
                .remove_identity_link("tenant-dev", "canonical-person", "slack")
                .await
                .unwrap()
        );
    }

    /// A hosted Identity is defined by the two facts a deployment cannot avoid: it listens on a
    /// routable address and publishes an HTTPS origin. Both make the local login inadmissible.
    #[cfg(feature = "local-login")]
    fn hosted_config() -> Config {
        Config {
            listen: "0.0.0.0:8080".parse().unwrap(),
            public_origin: Url::parse("https://identity.example.test/").unwrap(),
            ..config()
        }
    }

    #[cfg(feature = "local-login")]
    #[test]
    fn local_login_is_admitted_only_by_a_loopback_listener_and_origin() {
        assert!(
            local_login::admitted(&config()),
            "a 127.0.0.1 listener publishing a 127.0.0.1 HTTP origin is the local stack"
        );
        assert!(
            !local_login::admitted(&hosted_config()),
            "a deployed Identity must never admit the local login"
        );
        for (listen, origin) in [
            ("0.0.0.0:8080", "http://127.0.0.1:8080/"),
            ("127.0.0.1:8080", "https://identity.example.test/"),
            ("10.0.0.7:8080", "http://10.0.0.7:8080/"),
        ] {
            let config = Config {
                listen: listen.parse().unwrap(),
                public_origin: Url::parse(origin).unwrap(),
                ..config()
            };
            assert!(
                !local_login::admitted(&config),
                "{listen} serving {origin} is reachable from off the machine"
            );
        }
    }

    #[cfg(feature = "local-login")]
    #[tokio::test]
    async fn deployed_configuration_refuses_the_local_login_path() {
        let store = Store::in_memory().unwrap();
        let mut query = authorization_query();
        query.login_hint = Some("person@example.test".to_owned());

        let refused = local_login::complete(&hosted_config(), &store, &query)
            .await
            .expect_err("a deployed Identity must refuse to mint a session for a typed mailbox");
        assert_eq!(refused.status, StatusCode::NOT_FOUND);
    }

    #[cfg(feature = "local-login")]
    #[tokio::test]
    async fn local_login_mints_the_same_authorization_code_the_upstream_callback_does() {
        let store = Store::in_memory().unwrap();
        let mut query = authorization_query();
        query.login_hint = Some("  Person@Example.Test ".to_owned());

        let response = local_login::complete(&config(), &store, &query)
            .await
            .unwrap();
        let location = response
            .headers()
            .get(header::LOCATION)
            .and_then(|value| value.to_str().ok())
            .expect("the local login redirects to the client callback");
        let location = Url::parse(location).unwrap();
        assert_eq!(location.path(), "/callback");
        let returned = location
            .query_pairs()
            .map(|(name, value)| (name.into_owned(), value.into_owned()))
            .collect::<HashMap<_, _>>();
        assert_eq!(returned.get("state"), Some(&query.state));

        let authorization = store
            .take_code(returned.get("code").unwrap())
            .await
            .unwrap()
            .expect("the authorization code is the ordinary one /oauth/token consumes");
        assert_eq!(authorization.email.as_deref(), Some("person@example.test"));
        assert_eq!(authorization.tenant_id, "tenant-dev");
        assert_eq!(authorization.code_challenge, query.code_challenge);
        assert_eq!(authorization.redirect_uri, query.redirect_uri);
        assert!(
            authorization.subject.contains("person@example.test"),
            "the session subject names the person who signed in: {}",
            authorization.subject
        );
    }

    /// Without a mailbox the local login can only ask for one, so a bare `/oauth/authorize` in a
    /// browser is a form rather than a redirect into a provider that is not configured here.
    #[cfg(feature = "local-login")]
    #[tokio::test]
    async fn local_login_without_a_mailbox_asks_for_one() {
        let store = Store::in_memory().unwrap();
        let response = local_login::complete(&config(), &store, &authorization_query())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers().get(header::LOCATION).is_none());
    }

    #[cfg(feature = "local-login")]
    #[tokio::test]
    async fn local_login_refuses_a_mailbox_the_static_group_configuration_would_refuse() {
        let store = Store::in_memory().unwrap();
        for hint in ["", "not-an-address", "two@at@signs", "person@example test"] {
            let mut query = authorization_query();
            query.login_hint = Some(hint.to_owned());
            assert!(
                local_login::complete(&config(), &store, &query)
                    .await
                    .is_err(),
                "{hint:?} is not a mailbox address"
            );
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
    fn resource_authorization_requires_an_exact_registered_audience_and_not_an_oidc_nonce() {
        let mut query = authorization_query();
        query.scope = "resource.read".to_owned();
        query.resource = Some(TEST_ACCESS_AUDIENCE.to_owned());
        query.nonce = None;
        validate_authorization_request(&config(), &query).unwrap();

        query.resource = Some("urn:example:unknown".to_owned());
        assert!(validate_authorization_request(&config(), &query).is_err());
    }

    #[test]
    fn authorization_accepts_only_the_registered_web_callback() {
        let mut query = authorization_query();
        query.client_id = "status-web".to_owned();
        query.redirect_uri = "https://code.example.test/status/oauth/callback".to_owned();
        validate_authorization_request(&config(), &query).unwrap();

        query.redirect_uri = "https://code.example.test/status/attacker".to_owned();
        assert!(validate_authorization_request(&config(), &query).is_err());
    }

    #[test]
    fn static_groups_are_exact_normalized_and_deterministic() {
        let groups = StaticGroupMemberships::new(vec![(
            "tenant-a".to_owned(),
            " Operator@Example.Test ".to_owned(),
            vec!["operator".to_owned(), "platform-read".to_owned()],
        )])
        .unwrap();
        assert_eq!(
            groups.groups_for("tenant-a", Some("operator@example.test")),
            vec!["operator", "platform-read"]
        );
        assert!(
            groups
                .groups_for("tenant-b", Some("operator@example.test"))
                .is_empty()
        );
        assert!(
            groups
                .groups_for("tenant-a", Some("other@example.test"))
                .is_empty()
        );
        assert!(
            StaticGroupMemberships::new(vec![
                (
                    "tenant-a".to_owned(),
                    "operator@example.test".to_owned(),
                    vec!["operator".to_owned()]
                ),
                (
                    "tenant-a".to_owned(),
                    "OPERATOR@example.test".to_owned(),
                    vec!["other".to_owned()]
                ),
            ])
            .is_err()
        );
    }

    #[test]
    fn tenant_default_groups_are_granted_to_every_verified_member() {
        let groups = StaticGroupMemberships::new_with_tenant_defaults(
            vec![(
                "tenant-a".to_owned(),
                "operator@example.test".to_owned(),
                vec!["operator".to_owned()],
            )],
            vec![("tenant-a".to_owned(), vec!["org-member".to_owned()])],
        )
        .unwrap();
        assert_eq!(
            groups.groups_for("tenant-a", Some("person@example.test")),
            vec!["org-member"]
        );
        assert_eq!(
            groups.groups_for("tenant-a", Some("operator@example.test")),
            vec!["operator", "org-member"]
        );
        assert!(
            groups
                .groups_for("tenant-b", Some("person@example.test"))
                .is_empty()
        );
        assert!(groups.groups_for("tenant-a", None).is_empty());
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

    #[test]
    fn verified_organization_claims_resolve_two_exact_tenants_without_fallback() {
        let policy = OrganizationDomainPolicy::exact_tenant_mapping(
            "organization_id",
            vec![
                ("org-a".to_owned(), "tenant:a".to_owned()),
                ("org-b".to_owned(), "tenant:b".to_owned()),
            ],
        )
        .unwrap();
        for (organization, tenant) in [("org-a", "tenant:a"), ("ORG-B", "tenant:b")] {
            let claims = HashMap::from([(
                "organization_id".to_owned(),
                Value::String(organization.to_owned()),
            )]);
            assert_eq!(
                policy.resolve_tenant(&claims, "tenant:legacy").as_deref(),
                Some(tenant)
            );
        }
        let unknown = HashMap::from([(
            "organization_id".to_owned(),
            Value::String("org-c".to_owned()),
        )]);
        assert_eq!(policy.resolve_tenant(&unknown, "tenant:legacy"), None);
    }

    #[tokio::test]
    async fn authorization_code_is_single_use_and_stored_as_a_hash() {
        let store = Store::in_memory().unwrap();
        let authorization = PendingAuthorization {
            created_at: unix_time().unwrap(),
            client_id: "harness-cli".to_owned(),
            redirect_uri: "http://127.0.0.1:43123/callback".to_owned(),
            code_challenge: pkce_challenge(&"b".repeat(64)),
            subject: "upstream-subject".to_owned(),
            tenant_id: "tenant-dev".to_owned(),
            email: Some("developer@example.test".to_owned()),
            requested_audience: None,
            requested_scope: Some("openid profile email".to_owned()),
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
    async fn resource_authorization_code_mints_one_exact_short_lived_access_token() {
        let store = Store::in_memory().unwrap();
        let verifier = "b".repeat(64);
        let authorization = PendingAuthorization {
            created_at: unix_time().unwrap(),
            client_id: "harness-cli".to_owned(),
            redirect_uri: "http://127.0.0.1:43123/callback".to_owned(),
            code_challenge: pkce_challenge(&verifier),
            subject: "upstream-subject".to_owned(),
            tenant_id: "tenant-dev".to_owned(),
            email: Some("operator@example.test".to_owned()),
            requested_audience: Some(TEST_ACCESS_AUDIENCE.to_owned()),
            requested_scope: Some("resource.read resource.write".to_owned()),
        };
        store
            .put_code("resource-code", &authorization)
            .await
            .unwrap();
        let state = app_state(store.clone());
        let response = exchange_token(
            State(state),
            Form(TokenRequest {
                grant_type: "authorization_code".to_owned(),
                client_id: authorization.client_id,
                code: "resource-code".to_owned(),
                redirect_uri: authorization.redirect_uri,
                code_verifier: verifier,
                resource: authorization.requested_audience,
                scope: authorization.requested_scope,
            }),
        )
        .await
        .unwrap();
        let body = axum::body::to_bytes(response.into_body(), MAX_HTTP_BODY_BYTES)
            .await
            .unwrap();
        let token: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(token["token_type"], "Bearer");
        assert_eq!(token["audience"], TEST_ACCESS_AUDIENCE);
        assert_eq!(token["scope"], "resource.read resource.write");
        let credential = token["access_token"].as_str().unwrap();
        let authority = store
            .resolve_access_token(credential, TEST_ACCESS_AUDIENCE)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(authority.sub, "upstream-subject");
        assert_eq!(authority.groups, vec!["operator"]);
        assert!(store.take_code("resource-code").await.unwrap().is_none());
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn confidential_exchange_preserves_subject_and_narrows_exact_authority() {
        let store = Store::in_memory().unwrap();
        let target_audience = "urn:example:target-api";
        let caller_secret = "exchange-secret-with-at-least-thirty-two-bytes";
        let mut configured = config();
        configured.audience_registry = AudienceRegistry::new(
            vec![
                TEST_STATUS_AUDIENCE.to_owned(),
                TEST_ZWIRN_AUDIENCE.to_owned(),
            ],
            vec![
                (TEST_ACCESS_AUDIENCE.to_owned(), access_policy()),
                (
                    target_audience.to_owned(),
                    AccessAudiencePolicy::new(
                        vec!["target.read".to_owned()],
                        vec![("operator".to_owned(), vec!["target.invoke".to_owned()])],
                    )
                    .unwrap(),
                ),
            ],
        )
        .unwrap();
        configured.trusted_access_callers = vec![
            TrustedAccessCaller::new(
                "service-a".to_owned(),
                SecretValue::new(caller_secret.to_owned()),
            )
            .unwrap(),
        ];
        configured.access_exchange_policies = vec![
            AccessExchangePolicy::new(
                "service-a".to_owned(),
                TEST_ACCESS_AUDIENCE.to_owned(),
                vec!["resource.read".to_owned()],
                target_audience.to_owned(),
                vec!["target.read".to_owned(), "target.invoke".to_owned()],
            )
            .unwrap(),
        ];
        let now = unix_time().unwrap();
        let source_credential = format!("identity_access_v1_{}", "s".repeat(43));
        store
            .put_access_token(
                &source_credential,
                &AccessAuthority {
                    iss: configured.issuer().to_owned(),
                    sub: "upstream-subject".to_owned(),
                    aud: TEST_ACCESS_AUDIENCE.to_owned(),
                    iat: now,
                    nbf: now,
                    exp: now + ACCESS_TOKEN_LIFETIME_SECONDS,
                    jti: "identity_jti_v1_exchange-source".to_owned(),
                    act: Actor {
                        sub: "upstream-subject".to_owned(),
                    },
                    scope: "resource.read".to_owned(),
                    principal_kind: "human".to_owned(),
                    tenant_id: "tenant-dev".to_owned(),
                    email: Some("operator@example.test".to_owned()),
                    groups: vec!["stale-group-is-not-forwarded".to_owned()],
                },
            )
            .await
            .unwrap();
        let state = AppState::new(
            Arc::new(configured),
            BTreeMap::new(),
            openidconnect::reqwest::ClientBuilder::new()
                .redirect(openidconnect::reqwest::redirect::Policy::none())
                .build()
                .unwrap(),
            store.clone(),
        );
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {source_credential}")).unwrap(),
        );
        headers.insert(
            "x-b10x-access-exchange-caller",
            HeaderValue::from_static("service-a"),
        );
        headers.insert(
            "x-b10x-access-exchange-secret",
            HeaderValue::from_str(caller_secret).unwrap(),
        );
        let response = exchange_access_token(
            State(state.clone()),
            headers.clone(),
            Json(AccessExchangeRequest {
                source_audience: TEST_ACCESS_AUDIENCE.to_owned(),
                audience: target_audience.to_owned(),
                scope: "target.invoke".to_owned(),
            }),
        )
        .await
        .unwrap();
        let body = axum::body::to_bytes(response.into_body(), MAX_HTTP_BODY_BYTES)
            .await
            .unwrap();
        let token: Value = serde_json::from_slice(&body).unwrap();
        let authority = store
            .resolve_access_token(token["access_token"].as_str().unwrap(), target_audience)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(authority.sub, "upstream-subject");
        assert_eq!(authority.act.sub, "upstream-subject");
        assert_eq!(authority.scope, "target.invoke");
        assert_eq!(authority.groups, vec!["operator"]);

        headers.insert(
            "x-b10x-access-exchange-secret",
            HeaderValue::from_static("wrong-secret-that-is-still-long-enough"),
        );
        let refusal = exchange_access_token(
            State(state),
            headers,
            Json(AccessExchangeRequest {
                source_audience: TEST_ACCESS_AUDIENCE.to_owned(),
                audience: target_audience.to_owned(),
                scope: "target.read".to_owned(),
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(refusal.status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn session_store_never_persists_the_plaintext_credential() {
        let store = Store::in_memory().unwrap();
        let identity = Identity {
            subject: "upstream-subject".to_owned(),
            email: Some("developer@example.test".to_owned()),
        };
        store
            .put_session(
                "identity_session_v1_secret",
                &config(),
                "tenant-dev",
                &identity,
            )
            .await
            .unwrap();
        let raw_count: i64 = store
            .sqlite_connection()
            .unwrap()
            .query_row(
                "SELECT count(*) FROM sessions WHERE verifier_hash = ?1",
                [b"identity_session_v1_secret".as_slice()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(raw_count, 0);
    }

    /// The directory and profile schema must be safe to apply to the database a deployed Identity
    /// is already using: no existing table is altered, no row is rewritten, and a pre-existing
    /// credential still resolves afterwards.
    #[tokio::test]
    async fn the_new_schema_applies_additively_to_a_live_database() {
        let connection = Connection::open_in_memory().unwrap();
        connection
            .execute_batch(
                "CREATE TABLE sessions (
                   verifier_hash BLOB PRIMARY KEY,
                   issuer TEXT NOT NULL,
                   configuration_generation TEXT NOT NULL,
                   tenant_id TEXT NOT NULL,
                   subject TEXT NOT NULL,
                   email TEXT,
                   created_at INTEGER NOT NULL,
                   last_used_at INTEGER NOT NULL,
                   idle_expires_at INTEGER NOT NULL,
                   absolute_expires_at INTEGER NOT NULL,
                   revoked_at INTEGER
                 );",
            )
            .unwrap();
        let config = config();
        let now = unix_time().unwrap();
        connection
            .execute(
                "INSERT INTO sessions (
                   verifier_hash, issuer, configuration_generation, tenant_id, subject, email,
                   created_at, last_used_at, idle_expires_at, absolute_expires_at, revoked_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, NULL, ?6, ?6, ?7, ?8, NULL)",
                params![
                    hash("identity_session_v1_already_issued"),
                    config.issuer(),
                    config.configuration_generation(),
                    config.tenant_id,
                    "pre-existing-subject",
                    now,
                    now + 3_600,
                    now + 7_200,
                ],
            )
            .unwrap();

        let store = Store::from_sqlite_connection(connection).unwrap();

        let admitted = store
            .resolve_session("identity_session_v1_already_issued", &config)
            .await
            .unwrap()
            .expect("a credential issued before the migration must keep working");
        assert_eq!(admitted.subject, "pre-existing-subject");

        for table in [
            "directory_principals",
            "directory_groups",
            "directory_group_members",
            "profile_consents",
            "profile_excluded_sources",
            "profile_statements",
        ] {
            let rows: i64 = store
                .sqlite_connection()
                .unwrap()
                .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(rows, 0, "{table} must be created empty");
        }

        // Re-applying the schema, as a restart or a reconnect does, changes nothing.
        for schema in [directory::SQLITE_SCHEMA, profile::SQLITE_SCHEMA] {
            store
                .sqlite_connection()
                .unwrap()
                .execute_batch(schema)
                .unwrap();
        }
        assert!(
            store
                .resolve_session("identity_session_v1_already_issued", &config)
                .await
                .unwrap()
                .is_some()
        );
    }

    /// Exercises the clustered arm of every directory and profile statement against a real
    /// `PostgreSQL` server, because the two arms are separate SQL strings and only one of them is
    /// covered by the in-memory tests. Set `IDENTITY_TEST_POSTGRES_URL` to run it; without a
    /// server the test reports that it was skipped rather than pretending to have proved anything.
    #[tokio::test]
    async fn the_postgres_arm_applies_the_same_schema_and_queries() {
        let Ok(url) = std::env::var("IDENTITY_TEST_POSTGRES_URL") else {
            eprintln!("skipped: IDENTITY_TEST_POSTGRES_URL is not set");
            return;
        };
        let store = Store::connect_postgres(&url).await.unwrap();
        let tenant = format!("tenant-{}", random_token(8).unwrap().to_lowercase());
        let subject = format!("subject-{}", random_token(8).unwrap());
        exercise_postgres_directory(&store, &tenant, &subject).await;
        exercise_postgres_profile(&store, &tenant, &subject).await;
    }

    async fn exercise_postgres_directory(store: &Store, tenant: &str, subject: &str) {
        directory::write_member(
            store,
            tenant,
            &directory::MemberRecord {
                subject: subject.to_owned(),
                principal_kind: "agent".to_owned(),
                email: None,
                display_name: "Planner".to_owned(),
                status: "active".to_owned(),
            },
        )
        .await
        .unwrap();
        directory::write_group(
            store,
            tenant,
            &directory::GroupRecord {
                group_key: "project-atlas".to_owned(),
                display_name: "Project Atlas".to_owned(),
            },
        )
        .await
        .unwrap();
        directory::write_group_member(store, tenant, "project-atlas", subject)
            .await
            .unwrap();
        assert_eq!(
            directory::resolve_subject_groups(store, tenant, subject)
                .await
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            directory::resolve_group_members(store, tenant, "project-atlas")
                .await
                .unwrap()
                .len(),
            1
        );
        assert!(
            directory::erase_group_member(store, tenant, "project-atlas", subject)
                .await
                .unwrap()
        );
    }

    async fn exercise_postgres_profile(store: &Store, tenant: &str, subject: &str) {
        profile::write_consent(store, tenant, subject, true)
            .await
            .unwrap();
        let mut exclusions = BTreeSet::new();
        exclusions.insert("datasource:slack-incidents".to_owned());
        profile::replace_exclusions(store, tenant, subject, &exclusions)
            .await
            .unwrap();
        assert_eq!(
            profile::read_exclusions(store, tenant, subject)
                .await
                .unwrap(),
            exclusions
        );
        let now = unix_time().unwrap();
        let mut record = profile::StatementRecord {
            statement_id: format!(
                "identity_profile_statement_v1_{}",
                random_token(16).unwrap()
            ),
            kind: "preference".to_owned(),
            horizon: None,
            content: "prefers written briefs".to_owned(),
            epistemic_state: "inferred".to_owned(),
            source_kind: "conversation".to_owned(),
            source_reference: "conversation:thread-1".to_owned(),
            observed_at: now,
            created_at: now,
            updated_at: now,
            confirmed_at: None,
            resolved_at: None,
            superseded_by: None,
        };
        profile::write_statement(store, tenant, subject, &record)
            .await
            .unwrap();
        assert_eq!(
            profile::read_statements(store, tenant, subject)
                .await
                .unwrap()
                .len(),
            1
        );
        record.epistemic_state = "revoked".to_owned();
        record.resolved_at = Some(now);
        assert!(
            profile::write_statement_state(store, tenant, subject, &record)
                .await
                .unwrap()
        );
        assert_eq!(
            profile::read_statement(store, tenant, subject, &record.statement_id)
                .await
                .unwrap()
                .unwrap()
                .epistemic_state,
            "revoked"
        );
        assert!(
            profile::erase_statement(store, tenant, subject, &record.statement_id)
                .await
                .unwrap()
        );
        store
            .enforce_row_caps(&[RowCap {
                sqlite_count: "SELECT count(*) FROM profile_statements WHERE tenant_id = ?1",
                postgres_count:
                    "SELECT count(*)::BIGINT FROM profile_statements WHERE tenant_id = $1",
                arguments: &[tenant],
                maximum: 1,
                label: "profile statements",
            }])
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn session_resolution_is_bearer_bound_and_refreshes_only_live_sessions() {
        let store = Store::in_memory().unwrap();
        let config = config();
        let identity = Identity {
            subject: "upstream-subject".to_owned(),
            email: Some("developer@example.test".to_owned()),
        };
        let credential = format!("identity_session_v1_{}", "a".repeat(43));
        store
            .put_session(&credential, &config, "tenant-dev", &identity)
            .await
            .unwrap();

        let admitted = store
            .resolve_session(&credential, &config)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(admitted.tenant_id, "tenant-dev");
        assert_eq!(admitted.subject, "upstream-subject");
        assert!(
            store
                .resolve_session(
                    "identity_session_v1_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    &config,
                )
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn sessions_are_configuration_bound_and_logout_revokes_access() {
        let store = Store::in_memory().unwrap();
        let config = config();
        let identity = Identity {
            subject: "upstream-subject".to_owned(),
            email: None,
        };
        let credential = format!("identity_session_v1_{}", "c".repeat(43));
        store
            .put_session(&credential, &config, "tenant-dev", &identity)
            .await
            .unwrap();

        let mut changed = config.clone();
        changed.tenant_id = "different-tenant".to_owned();
        assert!(
            store
                .resolve_session(&credential, &changed)
                .await
                .unwrap()
                .is_none()
        );

        let now = unix_time().unwrap();
        let authority = AccessAuthority {
            iss: config.issuer().to_owned(),
            sub: identity.subject.clone(),
            aud: TEST_ACCESS_AUDIENCE.to_owned(),
            iat: now,
            nbf: now,
            exp: now + ACCESS_TOKEN_LIFETIME_SECONDS,
            jti: "identity_jti_v1_logout".to_owned(),
            act: Actor {
                sub: identity.subject.clone(),
            },
            scope: "resource.read".to_owned(),
            principal_kind: "human".to_owned(),
            tenant_id: config.tenant_id.clone(),
            email: identity.email.clone(),
            groups: Vec::new(),
        };
        let access = format!("identity_access_v1_{}", "d".repeat(43));
        store.put_access_token(&access, &authority).await.unwrap();
        assert!(
            store
                .revoke_session_and_subject_tokens(&credential, &identity.subject)
                .await
                .unwrap()
        );
        assert!(
            store
                .resolve_session(&credential, &config)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .resolve_access_token(&access, TEST_ACCESS_AUDIENCE)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn session_credential_shape_is_closed() {
        assert!(valid_session_credential(&format!(
            "identity_session_v1_{}",
            "a".repeat(43)
        )));
        assert!(!valid_session_credential("identity_session_v1_short"));
        assert!(!valid_session_credential(&format!(
            "identity_session_v2_{}",
            "a".repeat(43)
        )));
    }

    #[tokio::test]
    async fn access_authority_is_short_lived_audience_bound_and_hash_stored() {
        let store = Store::in_memory().unwrap();
        let now = unix_time().unwrap();
        let authority = AccessAuthority {
            iss: "https://identity.example.test".to_owned(),
            sub: "upstream-subject".to_owned(),
            aud: TEST_ACCESS_AUDIENCE.to_owned(),
            iat: now,
            nbf: now,
            exp: now + ACCESS_TOKEN_LIFETIME_SECONDS,
            jti: "identity_jti_v1_test".to_owned(),
            act: Actor {
                sub: "upstream-subject".to_owned(),
            },
            scope: "resource.read resource.write".to_owned(),
            principal_kind: "human".to_owned(),
            tenant_id: "tenant-dev".to_owned(),
            email: Some("developer@example.test".to_owned()),
            groups: vec!["operator".to_owned()],
        };
        let credential = format!("identity_access_v1_{}", "a".repeat(43));
        store
            .put_access_token(&credential, &authority)
            .await
            .unwrap();
        let raw_count: i64 = store
            .sqlite_connection()
            .unwrap()
            .query_row(
                "SELECT count(*) FROM access_tokens WHERE verifier_hash = ?1",
                [credential.as_bytes()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(raw_count, 0);
        let resolved = store
            .resolve_access_token(&credential, TEST_ACCESS_AUDIENCE)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(resolved, authority);
        assert!(
            store
                .resolve_access_token(&credential, "urn:b10x:substrate")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn access_scope_registration_is_generic_exact_and_canonical() {
        let policy = access_policy();
        assert_eq!(
            policy
                .admit("resource.read resource.write", &["operator".to_owned()])
                .unwrap(),
            "resource.read resource.write"
        );
        for invalid in [
            "resource.read  resource.write",
            "resource.read resource.read",
            "resource.unknown",
        ] {
            assert!(policy.admit(invalid, &["operator".to_owned()]).is_err());
        }
        assert!(valid_access_credential(&format!(
            "identity_access_v1_{}",
            "a".repeat(43)
        )));
        assert!(!valid_access_credential("identity_access_v1_short"));
        assert_eq!(
            policy
                .admit("resource.read", &["member".to_owned()])
                .unwrap(),
            "resource.read"
        );
        assert!(
            policy
                .admit("resource.write", &["member".to_owned()])
                .is_err()
        );
        assert_eq!(
            policy
                .admit("resource.write", &["operator".to_owned()])
                .unwrap(),
            "resource.write"
        );
    }

    #[test]
    fn internal_audiences_are_exact_and_disjoint() {
        let audiences = [
            TEST_ACCESS_AUDIENCE,
            TEST_STATUS_AUDIENCE,
            TEST_ZWIRN_AUDIENCE,
            directory::DIRECTORY_AUDIENCE,
            profile::PROFILE_AUDIENCE,
            profile::PROFILE_PROJECTION_AUDIENCE,
        ];
        assert_eq!(
            audiences.iter().collect::<BTreeSet<_>>().len(),
            audiences.len(),
            "every internal audience must be distinct"
        );

        let mut headers = HeaderMap::new();
        assert!(!audience_matches(&headers, directory::DIRECTORY_AUDIENCE));
        headers.insert(
            "x-b10x-audience",
            directory::DIRECTORY_AUDIENCE.parse().unwrap(),
        );
        assert!(audience_matches(&headers, directory::DIRECTORY_AUDIENCE));
        for wrong in [
            TEST_STATUS_AUDIENCE,
            profile::PROFILE_AUDIENCE,
            "urn:b10x:directory ",
        ] {
            assert!(
                !audience_matches(&headers, wrong),
                "a directory audience must not satisfy {wrong}"
            );
        }
    }

    #[test]
    fn credential_responses_are_explicitly_non_cacheable() {
        let response = confidential_json(serde_json::json!({"secret": "redacted"}));
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(response.headers()[header::PRAGMA], "no-cache");
    }
}
