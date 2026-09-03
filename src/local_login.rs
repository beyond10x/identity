//! A sign-in for a loopback Identity that has no upstream provider.
//!
//! The local process stack runs Identity on `127.0.0.1` with placeholder upstream client
//! credentials, so the ordinary browser flow cannot complete: there is no provider that would
//! return an ID token. This module replaces exactly that one step. Everything after it is the
//! deployed path unchanged — the same authorization code, the same `/oauth/token` exchange, the
//! same opaque session row, the same group resolution from the deployment's static and default
//! group configuration.
//!
//! Minting a session for a typed mailbox is a complete authentication bypass, so the module is
//! refused three independent ways and each one alone is sufficient:
//!
//! 1. It is compiled only behind the non-default `local-login` feature, and `lib.rs` raises
//!    `compile_error!` when that feature is combined with any shipping profile. Two independent
//!    predicates raise it: `debug_assertions` off (which every release build clears) and the
//!    `optimized_build` cfg `build.rs` derives from the profile's `OPT_LEVEL` (which `RUSTFLAGS`
//!    cannot force on, unlike `debug_assertions`). Either way the deployed binary cannot contain
//!    this code — the attempt does not produce a flag to leave off, it produces a build failure.
//! 2. `Dockerfile` passes no `--features`, so the image is built from the default set.
//! 3. [`admitted`] refuses unless this process both listens on a loopback address and publishes a
//!    loopback HTTP origin. `main.rs` checks it before binding, so a feature-built binary pointed
//!    at a routable address exits instead of serving, and [`complete`] checks it again per request.
//!
//! No environment variable, configuration file, or request can turn any of the three off.

use std::collections::HashMap;
use std::fmt::Write as _;

use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Redirect, Response};
use url::{Host, Url};

use crate::{
    AuthorizeQuery, Config, HttpError, PendingAuthorization, Store, html_escape, normalize_email,
    random_token, unix_time,
};

/// Marks the subject of a session that no upstream provider ever attested.
const SUBJECT_PREFIX: &str = "local-login:";

/// Whether this process is a loopback development Identity.
///
/// Both facts have to hold. A loopback origin with a routable listener is reachable from another
/// machine under a name it does not publish, and a loopback listener publishing an HTTPS origin is
/// a deployment behind a proxy. Only the pair describes a process that nothing but this machine can
/// reach.
pub(crate) fn admitted(config: &Config) -> bool {
    config.listen.ip().is_loopback()
        && config.public_origin.scheme() == "http"
        && config.public_origin.host().is_some_and(|host| match host {
            Host::Ipv4(address) => address.is_loopback(),
            Host::Ipv6(address) => address.is_loopback(),
            Host::Domain(name) => name == "localhost",
        })
}

/// Completes an authorization request without an upstream provider.
///
/// With no mailbox in the request this answers with the form that asks for one, so opening
/// `/oauth/authorize` in a browser is a page a person can use. With a mailbox it stores the same
/// [`PendingAuthorization`] the verified upstream callback stores and redirects to the client's
/// callback, so the caller's next step is the ordinary token exchange.
pub(crate) async fn complete(
    config: &Config,
    store: &Store,
    query: &AuthorizeQuery,
) -> Result<Response, HttpError> {
    // Checked again here, and not only at the call site, so no future caller can reach the mint.
    if !admitted(config) {
        return Err(HttpError::missing("no such route"));
    }
    let Some(login_hint) = query.login_hint.as_deref() else {
        return Ok(form(config, query).into_response());
    };
    let email = normalize_email(login_hint)
        .map_err(|_| HttpError::invalid("sign in with a mailbox address"))?;
    // The deployment's own tenant resolution, consulted with no upstream claims at all: a
    // deployment that requires an organization claim therefore resolves nothing and refuses.
    let tenant_id = config
        .upstream_providers
        .first()
        .map(|provider| &provider.organization_domain_policy)
        .ok_or_else(|| HttpError::internal("no upstream provider configuration"))?
        .resolve_tenant(&HashMap::new(), &config.tenant_id)
        .ok_or_else(|| {
            HttpError::denied("this Identity resolves a tenant from a verified upstream claim")
        })?;
    let code = random_token(32).map_err(HttpError::internal)?;
    store
        .put_code(
            &code,
            &PendingAuthorization {
                created_at: unix_time().map_err(HttpError::internal)?,
                client_id: query.client_id.clone(),
                redirect_uri: query.redirect_uri.clone(),
                code_challenge: query.code_challenge.clone(),
                subject: format!("{SUBJECT_PREFIX}{email}"),
                tenant_id,
                email: Some(email),
                requested_audience: query.resource.clone(),
                requested_scope: Some(query.scope.clone()),
            },
        )
        .await
        .map_err(HttpError::internal)?;
    let mut redirect = Url::parse(&query.redirect_uri).map_err(HttpError::internal)?;
    redirect
        .query_pairs_mut()
        .append_pair("code", &code)
        .append_pair("state", &query.state);
    Ok(Redirect::to(redirect.as_str()).into_response())
}

/// The page that asks for a mailbox, resubmitting the same authorization request to the same
/// endpoint. Every value comes back through the ordinary query validation, so the form cannot
/// widen what `/oauth/authorize` already admits.
fn form(config: &Config, query: &AuthorizeQuery) -> (StatusCode, Html<String>) {
    let mut hidden = String::new();
    for (name, value) in [
        ("response_type", query.response_type.as_str()),
        ("client_id", query.client_id.as_str()),
        ("redirect_uri", query.redirect_uri.as_str()),
        ("scope", query.scope.as_str()),
        ("state", query.state.as_str()),
        ("code_challenge", query.code_challenge.as_str()),
        (
            "code_challenge_method",
            query.code_challenge_method.as_str(),
        ),
    ] {
        let value = html_escape(value);
        let _ = write!(
            hidden,
            "<input type=\"hidden\" name=\"{name}\" value=\"{value}\">"
        );
    }
    for (name, value) in [
        ("nonce", query.nonce.as_deref()),
        ("resource", query.resource.as_deref()),
    ] {
        if let Some(value) = value {
            let value = html_escape(value);
            let _ = write!(
                hidden,
                "<input type=\"hidden\" name=\"{name}\" value=\"{value}\">"
            );
        }
    }
    let origin = html_escape(config.public_origin.as_str());
    let tenant = html_escape(&config.tenant_id);
    (
        StatusCode::OK,
        Html(format!(
            "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
             <title>Local development sign-in</title>\
             <style>body{{font:16px/1.5 system-ui,sans-serif;margin:4rem auto;max-width:34rem}}\
             input[type=email]{{font:inherit;padding:.4rem;width:100%}}\
             button{{font:inherit;margin-top:1rem;padding:.5rem 1rem}}\
             p{{color:#444}}</style></head><body>\
             <h1>Local development sign-in</h1>\
             <p>This Identity serves <code>{origin}</code> from a loopback listener and has no \
             upstream identity provider. It issues a real session for the mailbox you type, in \
             tenant <code>{tenant}</code>, with the groups this deployment's configuration \
             assigns. It exists only in a debug build on this machine.</p>\
             <form method=\"get\" action=\"/oauth/authorize\">{hidden}\
             <label for=\"login_hint\">Mailbox</label>\
             <input id=\"login_hint\" name=\"login_hint\" type=\"email\" required autofocus \
             placeholder=\"you@example.test\">\
             <button type=\"submit\">Sign in</button></form></body></html>"
        )),
    )
}
