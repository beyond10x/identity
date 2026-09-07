---
format: aep.planning-md/1
id: story:upstream-ca-bundle
kind: story
status: implemented
title: Trust an explicitly configured upstream OIDC certificate authority
relations:
- informed_by: story:agnostic-relying-party-registry
scope:
- confidence: cited
  path: README.md
- confidence: cited
  path: src/main.rs
- confidence: cited
  path: src/upstream_tls.rs
revision: 8
---
## Outcome

An operator can configure a PEM CA bundle for the upstream OIDC HTTP client, enabling a real HTTPS provider on a private CA, including the local Kubernetes acceptance composition. The ordinary OIDC discovery, signed token verification, session issuance and authorization code exchange stay intact.

## Acceptance

With no bundle configured, existing public-root HTTPS behavior is unchanged. A configured empty, malformed, missing or oversized bundle refuses startup. A valid bundle allows HTTPS to an otherwise untrusted test provider, while the default client and a client configured with a different CA reject it. Hostname and TLS verification remain enabled and redirects remain disabled. No local-login feature or insecure certificate bypass is introduced.

## Scope

Cited: src/main.rs and README.md. Inferred: src/upstream_tls.rs. This is transport trust configuration, without a new product domain entity or token audience.

## Relation to composition work

The Devcenter local Kubernetes acceptance story needs a real upstream OIDC provider with an explicitly selected local CA. That consumer must test the ordinary production Identity binary. The public component change is generic and contains no deployment coordinates or credentials.

## Validation

The repository gate completed with all Rust formatting, lint, tests, shipping login-feature checks, dependency audit under its existing exception, and secret scanning green. The real TLS regression rejects an unselected CA, an unrelated CA and an incorrect hostname, and admits only the selected test root. Missing, empty, malformed and oversized configured bundles refuse.

The canonical application Dockerfile was built and composed with the ordinary Identity login path. The local browser journey obtained an Identity-issued session through the synthetic external OIDC provider with certificate and hostname verification enabled. Local-login was not used. The local composition evidence is retained privately because it includes session state and deployment configuration.
