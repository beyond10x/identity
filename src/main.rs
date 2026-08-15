#![forbid(unsafe_code)]

use std::env;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use axum::Router;
use daemonloom_identity::{
    AppState, Config, OrganizationDomainPolicy, SecretValue, Store, discover_upstream, router,
};
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
    let http_client = openidconnect::reqwest::ClientBuilder::new()
        .redirect(openidconnect::reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(15))
        .build()
        .context("build OIDC HTTP client")?;
    let upstream = discover_upstream(&config, &http_client).await?;
    let store = match config.database_url.as_ref() {
        Some(url) => Store::connect_postgres(url.expose_secret()).await?,
        None => Store::open(&config.database_path)?,
    };
    let app: Router = router(AppState::new(config.clone(), upstream, http_client, store));
    let listener = tokio::net::TcpListener::bind(config.listen)
        .await
        .with_context(|| format!("bind {}", config.listen))?;
    info!(listen = %config.listen, issuer = %config.public_origin, "daemonloom identity listening");
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
        connectors_endpoint: optional_connectors_endpoint()?,
        tenant_id: required("IDENTITY_TENANT_ID")?,
        cli_client_id: env::var("IDENTITY_CLI_CLIENT_ID")
            .unwrap_or_else(|_| "daemonloom-harness-cli".to_owned()),
        upstream_issuer: required_issuer("IDENTITY_UPSTREAM_ISSUER")?,
        upstream_client_id: required("IDENTITY_UPSTREAM_CLIENT_ID")?,
        upstream_client_secret: required_secret("IDENTITY_UPSTREAM_CLIENT_SECRET")?,
        organization_domain_policy: organization_domain_policy()?,
        database_url: optional_database_url()?,
        database_path: PathBuf::from(
            env::var("IDENTITY_DATABASE_PATH")
                .unwrap_or_else(|_| "/var/lib/daemonloom-identity/identity.sqlite3".to_owned()),
        ),
    })
}

fn optional_connectors_endpoint() -> Result<Option<Url>> {
    let Some(value) = env::var("IDENTITY_CONNECTORS_ENDPOINT")
        .ok()
        .filter(|value| !value.trim().is_empty())
    else {
        return Ok(None);
    };
    normalize_connectors_endpoint(&value).map(Some)
}

fn normalize_connectors_endpoint(value: &str) -> Result<Url> {
    let endpoint =
        Url::parse(value).context("IDENTITY_CONNECTORS_ENDPOINT must be an absolute HTTPS URL")?;
    if endpoint.scheme() != "https"
        || endpoint.host_str().is_none()
        || !endpoint.username().is_empty()
        || endpoint.password().is_some()
        || endpoint.path() == "/"
        || endpoint.path().contains("//")
        || endpoint.path().ends_with('/')
        || endpoint.query().is_some()
        || endpoint.fragment().is_some()
    {
        bail!(
            "IDENTITY_CONNECTORS_ENDPOINT must be a closed HTTPS API base without credentials, query, fragment, or trailing slash"
        );
    }
    Ok(endpoint)
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
        .collect();
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
    use super::{database_url_from_parts, normalize_connectors_endpoint};

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

    #[test]
    fn connector_discovery_endpoint_is_a_closed_https_base() {
        assert!(normalize_connectors_endpoint("https://code.example/api/connectors/v1").is_ok());
        for endpoint in [
            "http://code.example/api/connectors/v1",
            "https://user@code.example/api/connectors/v1",
            "https://code.example/api/connectors/v1/",
            "https://code.example/api/connectors/v1?next=evil",
        ] {
            assert!(normalize_connectors_endpoint(endpoint).is_err());
        }
    }
}
