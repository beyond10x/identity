#![forbid(unsafe_code)]

use std::env;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use axum::Router;
use identity::{
    AccessAudiencePolicy, AppState, AudienceRegistry, Config, OrganizationDomainPolicy,
    SecretValue, StaticGroupMemberships, Store, UpstreamProvider, WebClient, discover_upstreams,
    router,
};
use serde::Deserialize;
use tracing::info;
use tracing_subscriber::EnvFilter;
use url::Url;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let config = Arc::new(config_from_environment()?);
    // This binary carries the local development login, which signs a person in as any mailbox they
    // type. It refuses to serve anything a second machine could reach, before it binds a listener.
    #[cfg(feature = "local-login")]
    if !identity::local_login_admitted(&config) {
        bail!(
            "this binary was built with the local development login, so it serves only a loopback \
             listener publishing a loopback HTTP origin; IDENTITY_LISTEN={} and \
             IDENTITY_PUBLIC_ORIGIN={} are reachable from elsewhere",
            config.listen,
            config.public_origin
        );
    }
    let http_client = openidconnect::reqwest::ClientBuilder::new()
        .redirect(openidconnect::reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(15))
        .build()
        .context("build OIDC HTTP client")?;
    let upstreams = discover_upstreams(&config, &http_client).await?;
    let store = match config.database_url.as_ref() {
        Some(url) => Store::connect_postgres(url.expose_secret()).await?,
        None => Store::open(&config.database_path)?,
    };
    let app: Router = router(AppState::new(config.clone(), upstreams, http_client, store));
    let listener = tokio::net::TcpListener::bind(config.listen)
        .await
        .with_context(|| format!("bind {}", config.listen))?;
    info!(listen = %config.listen, issuer = %config.public_origin, "identity listening");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("serve identity HTTP")
}

fn config_from_environment() -> Result<Config> {
    let listen = env::var("IDENTITY_LISTEN")
        .unwrap_or_else(|_| "0.0.0.0:8080".to_owned())
        .parse()
        .context("IDENTITY_LISTEN must be an IP socket address")?;
    let public_origin = required_url("IDENTITY_PUBLIC_ORIGIN")?;
    if public_origin.scheme() != "https" && public_origin.host_str() != Some("127.0.0.1") {
        bail!("IDENTITY_PUBLIC_ORIGIN must use https (http is allowed only for 127.0.0.1 tests)");
    }
    if public_origin.path() != "/"
        || public_origin.query().is_some()
        || public_origin.fragment().is_some()
    {
        bail!("IDENTITY_PUBLIC_ORIGIN must be an origin without a path, query, or fragment");
    }
    Ok(Config {
        listen,
        public_origin,
        tenant_id: required("IDENTITY_TENANT_ID")?,
        cli_client_id: env::var("IDENTITY_CLI_CLIENT_ID")
            .unwrap_or_else(|_| "identity-cli".to_owned()),
        web_clients: web_clients()?,
        audience_registry: audience_registry()?,
        upstream_providers: upstream_providers()?,
        static_group_memberships: static_group_memberships()?,
        database_url: optional_database_url()?,
        database_path: PathBuf::from(
            env::var("IDENTITY_DATABASE_PATH")
                .unwrap_or_else(|_| "/var/lib/identity/identity.sqlite3".to_owned()),
        ),
    })
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct UpstreamProviderEnvironmentConfig {
    id: String,
    label: String,
    issuer: String,
    client_id: String,
    client_secret_env: String,
    #[serde(default)]
    organization_domain_claim: Option<String>,
    #[serde(default)]
    allowed_organization_base_domains: Vec<String>,
    #[serde(default)]
    organization_tenants: Vec<OrganizationTenantConfig>,
}

fn upstream_providers() -> Result<Vec<UpstreamProvider>> {
    let source = env::var("IDENTITY_UPSTREAM_PROVIDERS_JSON")
        .ok()
        .filter(|value| !value.trim().is_empty());
    let Some(source) = source else {
        return Ok(vec![UpstreamProvider {
            id: "default".to_owned(),
            label: "OpenID Connect".to_owned(),
            issuer: required_issuer("IDENTITY_UPSTREAM_ISSUER")?,
            client_id: required("IDENTITY_UPSTREAM_CLIENT_ID")?,
            client_secret: required_secret("IDENTITY_UPSTREAM_CLIENT_SECRET")?,
            organization_domain_policy: organization_domain_policy()?,
        }]);
    };
    let entries: Vec<UpstreamProviderEnvironmentConfig> = serde_json::from_str(&source)
        .context("IDENTITY_UPSTREAM_PROVIDERS_JSON must be an array of provider declarations")?;
    if entries.is_empty() {
        bail!("IDENTITY_UPSTREAM_PROVIDERS_JSON must contain at least one provider");
    }
    entries
        .into_iter()
        .map(|entry| {
            let policy = if entry.organization_tenants.is_empty() {
                OrganizationDomainPolicy::new(
                    entry.organization_domain_claim,
                    entry.allowed_organization_base_domains,
                )?
            } else {
                if !entry.allowed_organization_base_domains.is_empty() {
                    bail!("provider organization tenants and allowed base domains are mutually exclusive");
                }
                let claim = entry.organization_domain_claim.context(
                    "provider organizationTenants requires organizationDomainClaim",
                )?;
                OrganizationDomainPolicy::exact_tenant_mapping(
                    &claim,
                    entry
                        .organization_tenants
                        .into_iter()
                        .map(|mapping| (mapping.claim_value, mapping.tenant_id))
                        .collect(),
                )?
            };
            if entry.client_secret_env.is_empty()
                || entry.client_secret_env.len() > 128
                || !entry
                    .client_secret_env
                    .bytes()
                    .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
            {
                bail!("provider clientSecretEnv must name a bounded uppercase environment variable");
            }
            let client_secret = env::var(&entry.client_secret_env).with_context(|| {
                format!("{} is required for upstream provider {}", entry.client_secret_env, entry.id)
            })?;
            Ok(UpstreamProvider {
                id: entry.id,
                label: entry.label,
                issuer: entry.issuer,
                client_id: entry.client_id,
                client_secret: SecretValue::new(client_secret),
                organization_domain_policy: policy,
            })
        })
        .collect()
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WebClientConfig {
    client_id: String,
    redirect_uri: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AudienceRegistryConfig {
    version: String,
    session: Vec<String>,
    access: Vec<AccessAudienceConfig>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AccessAudienceConfig {
    audience: String,
    #[serde(default)]
    scopes: Vec<String>,
    #[serde(default)]
    group_scopes: Vec<GroupScopeConfig>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct GroupScopeConfig {
    group: String,
    scopes: Vec<String>,
}

fn audience_registry() -> Result<AudienceRegistry> {
    let source = required("IDENTITY_AUDIENCE_REGISTRY_JSON")?;
    audience_registry_from_source(&source)
}

fn audience_registry_from_source(source: &str) -> Result<AudienceRegistry> {
    let registry: AudienceRegistryConfig = serde_json::from_str(source)
        .context("IDENTITY_AUDIENCE_REGISTRY_JSON must be a versioned exact audience registry")?;
    if registry.version != "identity.audiences/2" {
        bail!("IDENTITY_AUDIENCE_REGISTRY_JSON has an unsupported version");
    }
    AudienceRegistry::new(
        registry.session,
        registry
            .access
            .into_iter()
            .map(|entry| {
                AccessAudiencePolicy::new(
                    entry.scopes,
                    entry
                        .group_scopes
                        .into_iter()
                        .map(|rule| (rule.group, rule.scopes))
                        .collect(),
                )
                .map(|policy| (entry.audience, policy))
            })
            .collect::<Result<Vec<_>>>()?,
    )
}

#[cfg(test)]
mod audience_registry_tests {
    use super::*;

    const VALID: &str = r#"{
      "version":"identity.audiences/2",
      "session":["urn:example:status","urn:example:console"],
      "access":[{
        "audience":"urn:example:resource-api",
        "scopes":["resource.read"],
        "groupScopes":[{"group":"operator","scopes":["resource.write"]}]
      }]
    }"#;

    #[test]
    fn exact_versioned_registry_is_accepted() {
        assert!(audience_registry_from_source(VALID).is_ok());
    }

    #[test]
    fn unknown_version_field_policy_and_duplicates_are_refused() {
        for invalid in [
            VALID.replace("identity.audiences/2", "identity.audiences/1"),
            VALID.replace("\"access\":", "\"unknown\":[],\"access\":"),
            VALID.replace("\"resource.read\"", "\"resource read\""),
            VALID.replace(
                "\"urn:example:status\",\"urn:example:console\"",
                "\"urn:example:status\",\"urn:example:status\"",
            ),
        ] {
            assert!(
                audience_registry_from_source(&invalid).is_err(),
                "invalid registry was accepted: {invalid}"
            );
        }
    }
}

fn web_clients() -> Result<Vec<WebClient>> {
    let source = env::var("IDENTITY_WEB_CLIENTS_JSON").unwrap_or_else(|_| "[]".to_owned());
    let clients: Vec<WebClientConfig> = serde_json::from_str(&source)
        .context("IDENTITY_WEB_CLIENTS_JSON must be a JSON array of exact public clients")?;
    clients
        .into_iter()
        .map(|client| WebClient::new(&client.client_id, &client.redirect_uri))
        .collect()
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StaticGroupMembershipConfig {
    tenant_id: String,
    email: String,
    groups: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DefaultTenantGroupsConfig {
    tenant_id: String,
    groups: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct OrganizationTenantConfig {
    claim_value: String,
    tenant_id: String,
}

fn static_group_memberships() -> Result<StaticGroupMemberships> {
    let source =
        env::var("IDENTITY_STATIC_GROUP_MEMBERSHIPS_JSON").unwrap_or_else(|_| "[]".to_owned());
    let memberships: Vec<StaticGroupMembershipConfig> = serde_json::from_str(&source).context(
        "IDENTITY_STATIC_GROUP_MEMBERSHIPS_JSON must be a JSON array of tenant-scoped email assignments",
    )?;
    let defaults_source =
        env::var("IDENTITY_DEFAULT_TENANT_GROUPS_JSON").unwrap_or_else(|_| "[]".to_owned());
    let defaults: Vec<DefaultTenantGroupsConfig> = serde_json::from_str(&defaults_source).context(
        "IDENTITY_DEFAULT_TENANT_GROUPS_JSON must be a JSON array of tenant-scoped default groups",
    )?;
    StaticGroupMemberships::new_with_tenant_defaults(
        memberships
            .into_iter()
            .map(|membership| (membership.tenant_id, membership.email, membership.groups))
            .collect(),
        defaults
            .into_iter()
            .map(|membership| (membership.tenant_id, membership.groups))
            .collect(),
    )
}

fn organization_domain_policy() -> Result<OrganizationDomainPolicy> {
    let claim = env::var("IDENTITY_UPSTREAM_ORGANIZATION_DOMAIN_CLAIM")
        .ok()
        .filter(|value| !value.trim().is_empty());
    let allowed_base_domains = env::var("IDENTITY_ALLOWED_ORGANIZATION_BASE_DOMAINS")
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if let Some(source) = env::var("IDENTITY_ORGANIZATION_TENANTS_JSON")
        .ok()
        .filter(|value| !value.trim().is_empty())
    {
        if !allowed_base_domains.is_empty() {
            bail!(
                "IDENTITY_ORGANIZATION_TENANTS_JSON and IDENTITY_ALLOWED_ORGANIZATION_BASE_DOMAINS are mutually exclusive"
            );
        }
        let claim = claim.context(
            "IDENTITY_ORGANIZATION_TENANTS_JSON requires IDENTITY_UPSTREAM_ORGANIZATION_DOMAIN_CLAIM",
        )?;
        let mappings: Vec<OrganizationTenantConfig> = serde_json::from_str(&source).context(
            "IDENTITY_ORGANIZATION_TENANTS_JSON must be an array of exact claimValue/tenantId mappings",
        )?;
        return OrganizationDomainPolicy::exact_tenant_mapping(
            &claim,
            mappings
                .into_iter()
                .map(|mapping| (mapping.claim_value, mapping.tenant_id))
                .collect(),
        );
    }
    OrganizationDomainPolicy::new(claim, allowed_base_domains).context(
        "IDENTITY_UPSTREAM_ORGANIZATION_DOMAIN_CLAIM and \
         IDENTITY_ALLOWED_ORGANIZATION_BASE_DOMAINS do not form a valid policy",
    )
}

fn optional_database_url() -> Result<Option<SecretValue>> {
    if let Some(value) = env::var("IDENTITY_DATABASE_URL")
        .ok()
        .filter(|value| !value.is_empty())
    {
        if database_parts_are_present() {
            bail!("IDENTITY_DATABASE_URL and IDENTITY_DB_* variables are mutually exclusive");
        }
        let url = Url::parse(&value).context("IDENTITY_DATABASE_URL must be an absolute URL")?;
        if !matches!(url.scheme(), "postgres" | "postgresql") {
            bail!("IDENTITY_DATABASE_URL must use the postgres or postgresql scheme");
        }
        return Ok(Some(SecretValue::new(value)));
    }

    if !database_parts_are_present() {
        return Ok(None);
    }

    let port = required("IDENTITY_DB_PORT")?
        .parse::<u16>()
        .context("IDENTITY_DB_PORT must be a TCP port")?;
    database_url_from_parts(
        &required("IDENTITY_DB_USER")?,
        &required("IDENTITY_DB_PASSWORD")?,
        &required("IDENTITY_DB_HOST")?,
        port,
        &required("IDENTITY_DB_NAME")?,
        &env::var("IDENTITY_DB_PARAMS").unwrap_or_else(|_| "sslmode=require".to_owned()),
    )
    .map(Some)
}

fn database_parts_are_present() -> bool {
    [
        "IDENTITY_DB_USER",
        "IDENTITY_DB_PASSWORD",
        "IDENTITY_DB_HOST",
        "IDENTITY_DB_PORT",
        "IDENTITY_DB_NAME",
        "IDENTITY_DB_PARAMS",
    ]
    .iter()
    .any(|name| env::var(name).is_ok_and(|value| !value.is_empty()))
}

fn database_url_from_parts(
    user: &str,
    password: &str,
    host: &str,
    port: u16,
    database: &str,
    params: &str,
) -> Result<SecretValue> {
    let mut url = Url::parse("postgresql://localhost")?;
    url.set_username(user)
        .map_err(|()| anyhow::anyhow!("IDENTITY_DB_USER is not valid in a PostgreSQL URL"))?;
    url.set_password(Some(password))
        .map_err(|()| anyhow::anyhow!("IDENTITY_DB_PASSWORD is not valid in a PostgreSQL URL"))?;
    url.set_host(Some(host))
        .context("IDENTITY_DB_HOST is not a valid hostname or IP address")?;
    url.set_port(Some(port))
        .map_err(|()| anyhow::anyhow!("IDENTITY_DB_PORT is not valid in a PostgreSQL URL"))?;
    url.set_path(database);
    if !params.is_empty() {
        url.set_query(Some(params));
    }
    Ok(SecretValue::new(url.into()))
}

fn required(name: &'static str) -> Result<String> {
    env::var(name).with_context(|| format!("{name} is required"))
}

fn required_secret(name: &'static str) -> Result<SecretValue> {
    required(name).map(SecretValue::new)
}

fn required_url(name: &'static str) -> Result<Url> {
    Url::parse(&required(name)?).with_context(|| format!("{name} must be an absolute URL"))
}

fn required_issuer(name: &'static str) -> Result<String> {
    let value = required(name)?;
    let url = Url::parse(&value).with_context(|| format!("{name} must be an absolute URL"))?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        bail!("{name} must be an HTTPS issuer URL without a query or fragment");
    }
    Ok(value)
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("install Ctrl-C signal handler");
    };
    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("install SIGTERM signal handler")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
}

#[cfg(test)]
mod tests {
    use super::database_url_from_parts;

    #[test]
    fn database_parts_are_safely_encoded() {
        let url = database_url_from_parts(
            "identity user",
            "p@ss:/?#[]!",
            "postgresql.example.test",
            5432,
            "identity database",
            "sslmode=verify-full",
        )
        .unwrap();

        assert_eq!(
            url.expose_secret(),
            "postgresql://identity%20user:p%40ss%3A%2F%3F%23%5B%5D!@postgresql.example.test:5432/identity%20database?sslmode=verify-full"
        );
    }
}
