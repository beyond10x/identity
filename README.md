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
slice. Authorization codes and sessions are stored only as SHA-256 verifiers. Login transaction,
authorization-code, and redirect bindings are single-use and expire. SQLite remains available for
local single-process use. Cluster deployments use PostgreSQL through `IDENTITY_DATABASE_URL` or
the separately supplied `IDENTITY_DB_USER`, `IDENTITY_DB_PASSWORD`, `IDENTITY_DB_HOST`,
`IDENTITY_DB_PORT`, `IDENTITY_DB_NAME`, and optional `IDENTITY_DB_PARAMS` fields. The latter form
is used for provider-generated connection Secrets and safely URL-encodes credentials.

## Run locally

Create a Google OAuth web client whose authorized redirect URI is exactly:

```text
http://127.0.0.1:8080/oauth/callback/upstream
```

Then run:

```bash
IDENTITY_LISTEN=127.0.0.1:8080 \
IDENTITY_PUBLIC_ORIGIN=http://127.0.0.1:8080 \
IDENTITY_TENANT_ID=local \
IDENTITY_UPSTREAM_ISSUER=https://accounts.google.com \
IDENTITY_UPSTREAM_CLIENT_ID='your-client-id' \
IDENTITY_UPSTREAM_CLIENT_SECRET='your-client-secret' \
IDENTITY_DATABASE_PATH=/tmp/daemonloom-identity.sqlite3 \
cargo run --locked
```

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
../cloud/deploy/tests/static.sh
```
