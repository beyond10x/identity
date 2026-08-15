# Daemonloom Identity

This repository contains the first deployable human-login slice for Daemonloom. It owns upstream
OpenID Connect login, one-tenant principal identity, opaque CLI sessions, and the server-side
credential store. Product services such as the AI Agent Platform consume this identity; they do not
run Google OAuth themselves.

The implemented CLI flow is:

```text
agent-harness login [HOST]
  -> GET /.well-known/daemonloom-cli-login
  -> browser authorization with state + nonce + S256 PKCE
  -> daemonloom-identity redirects to configured upstream OIDC (Google in dev)
  -> exact loopback callback
  -> one-use authorization-code exchange
  -> opaque Daemonloom session stored by the CLI
```

Google access and refresh tokens never leave the identity process and are not persisted by this
slice. Authorization codes, sessions, and Connector access tokens are stored only as SHA-256
verifiers. Login transactions and authorization codes are single-use, expired rows are collected,
and every credential table has a finite row cap. Sessions are bound to the exact Identity issuer,
tenant, and authority-defining configuration generation; a change requires a new login.
`POST /v1/logout` revokes the presented session and every outstanding Connector access token for
that subject.

SQLite remains available for local single-process use. Its database must be a non-symlink regular
file inside a service-user-owned directory with mode `0700` or stricter; the database is forced to
`0600`. Cluster deployments use PostgreSQL through `IDENTITY_DATABASE_URL` or
the separately supplied `IDENTITY_DB_USER`, `IDENTITY_DB_PASSWORD`, `IDENTITY_DB_HOST`,
`IDENTITY_DB_PORT`, `IDENTITY_DB_NAME`, and optional `IDENTITY_DB_PARAMS` fields. The latter form
is used for provider-generated connection Secrets and safely URL-encodes credentials.
PostgreSQL access reconnects under a five-second deadline after a broken transport; reconnects
re-validate the schema before the client becomes ready. Capacity check-and-insert admission is
serialized inside the process. Distributed admission has not been proven, so the Cloud development
composition fixes Identity at one replica and uses replacement rollouts.

When configured, login metadata also publishes one closed `connectors_endpoint`. Native clients
persist that non-secret HTTPS base with the account record. It is discovery and destination
pinning, not a credential or an access grant.

Before a hosted Connector request, the native client presents its login-continuity session only to
Identity at `POST /v1/access-token`. Identity returns a five-minute opaque access token with the
exact `urn:daemonloom:connectors` audience. The current bootstrap mints only
`connectors.catalog.read`; it refuses invocation and management scopes until receiver-owned Grant
and management authorization exist. Connectors
then resolves that access token through `GET /v1/access-authority`; the result is the complete
validated foundation envelope (`iss`, `sub`, `aud`, time window, `jti`, immediate actor, scopes,
principal kind, and tenant). Login sessions and upstream provider credentials never reach
Connectors. Connector scopes remain only a coarse gate: Connectors must still perform its own
Connection and Grant admission before an effect-bearing invocation.

`GET /livez` reports only process liveness. `GET /readyz` (and the compatibility `/healthz` route)
executes a database query and returns `503` when durable state is unavailable.
Request bodies are capped at 64 KiB. Upstream OIDC connections use a five-second connect deadline
and a fifteen-second total request deadline, so an unavailable issuer cannot hold login workers
indefinitely. Session, access-token, and resolved-authority responses carry explicit `no-store` and
`no-cache` headers.

## Run locally

Create a Google OAuth web client whose authorized redirect URI is exactly:

```text
http://127.0.0.1:8080/oauth/callback/upstream
```

Then run. `IDENTITY_CONNECTORS_ENDPOINT` is optional for a standalone Identity process and is
required when native clients should discover a trusted hosted Connector API:

```bash
IDENTITY_LISTEN=127.0.0.1:8080 \
IDENTITY_PUBLIC_ORIGIN=http://127.0.0.1:8080 \
IDENTITY_CONNECTORS_ENDPOINT=https://code.example.test/api/connectors/v1 \
IDENTITY_TENANT_ID=local \
IDENTITY_UPSTREAM_ISSUER=https://accounts.google.com \
IDENTITY_UPSTREAM_CLIENT_ID='your-client-id' \
IDENTITY_UPSTREAM_CLIENT_SECRET='your-client-secret' \
IDENTITY_UPSTREAM_ORGANIZATION_DOMAIN_CLAIM=hd \
IDENTITY_ALLOWED_ORGANIZATION_BASE_DOMAINS=example.com \
IDENTITY_DATABASE_PATH=/tmp/daemonloom-identity/private/identity.sqlite3 \
cargo run --locked
```

The organization policy is optional, but the claim and allowlist must be configured together. It
reads only the cryptographically verified upstream ID token. Each configured base domain admits
the exact domain and label-bound subdomains; `evilexample.com` does not match `example.com`. With
Google Workspace, use the signed `hd` claim rather than inferring membership from the email
address or the authorization request's `hd` hint.

Production configuration refuses a non-HTTPS public origin. Plain HTTP is accepted only for the
literal `127.0.0.1` local-test origin.

## Deploy to the dev cluster

Deployment composition belongs to the Daemonloom Cloud umbrella chart rather than this service
repository. Its developer profile installs PostgreSQL, BuildKit, an ephemeral self-hosted registry,
and Identity by immutable digest behind an internal TLS ingress.

The chart creates a labeled Identity discovery `ExternalName` Service. A
hostless harness login discovers the current cluster's CoreDNS service and cluster domain, tunnels
DNS-over-TCP through the Kubernetes API, and resolves that Service's CNAME to the public HTTPS
origin. The service record exists only in a cluster where Daemonloom Identity is deployed;
the CLI does not derive a company domain from a Kubernetes context name.

Register the chart's public Identity origin plus `/oauth/callback/upstream` as the Google redirect
URI. For example:

```text
https://identity.dev.daemonloom.dev/oauth/callback/upstream
```

Then run the Cloud developer deployment command with a JSON file containing `client_id` and
`client_secret`. The command creates Kubernetes Secrets without putting their values in Helm,
builds this exact clean Git commit inside the cluster, and installs the resulting digest.

```bash
../cloud/deploy/dev/deploy.sh --help
```

The repositories contain no OAuth client secret, database password, registry password, or reusable
login credential.

## Checks

```bash
cargo test --locked
cargo clippy --all-targets --locked -- -D warnings
cargo fmt --all -- --check
scripts/check-audit.sh
../cloud/deploy/tests/static.sh
```

The audit check contains one narrowly justified transitive exception: `openidconnect 4.0.1`
carries `rsa 0.9` unconditionally, while this service uses it only to verify signatures with public
JWKs and never possesses an RSA private key, so the advisory's private-key timing-recovery path is
absent. The script first proves that the dependency path is still exactly
`Identity -> openidconnect -> rsa`; any path drift forces re-review. The exception must be removed
when the upstream dependency no longer carries that crate.
