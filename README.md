# identity

The platform's login and principal service. It owns upstream OpenID Connect login, tenant-scoped
principal identity, opaque CLI sessions, the server-side credential store, the organization
directory, and the personal collaboration profile.

The problem it removes: every product service otherwise runs its own Google OAuth, keeps its own
copy of who works here, and invents its own idea of what a user identifier means. Here, upstream
provider tokens never leave this process, a user key is always `(tenant, sub)` and never a bare
subject, and a consumer resolves a short-lived audience-scoped authority instead of holding a
login session.

## Where it sits

| direction | what |
|---|---|
| authenticates | [connectors](https://github.com/beyond10x/connectors) — issues a five-minute opaque access token, which Connectors resolves through `GET /v1/access-authority` |
| authenticates | in-cluster applications, through `GET /v1/session-authority` with an exact audience header |
| will authenticate | [llmgw](https://github.com/beyond10x/llmgw) — its `[identity]` config section exists but that build refuses to start with it |
| consumes | an upstream OIDC provider (Google in dev), SQLite locally, PostgreSQL in cluster |
| mapped in | [atlas](https://github.com/beyond10x/atlas) |

Login sessions and upstream provider credentials never reach a consumer. A consumer's scope is a
coarse gate only — it must still run its own admission before an effect-bearing operation.

## Status

**The first deployable human-login slice, running in the dev cluster.** Version `0.1.0`,
`publish = false`, no git tag cut.

| area | state |
|---|---|
| CLI login, sessions, logout | implemented |
| access tokens and access authority | implemented |
| organization directory and groups | implemented |
| personal collaboration profile | implemented |
| PostgreSQL backend | implemented; **distributed admission is not proven**, so the dev composition fixes one replica and uses replacement rollouts |
| deployment composition | lives in the platform's cloud umbrella chart, not in this repo |

## Build, test, run

The gate is **`bash scripts/gate.sh`**. It runs tests and clippy in *both* feature postures, plus
four component checks. Green here is the bar for main.

| step | command |
|---|---|
| tests | `cargo test --workspace --locked` |
| tests, dev-login posture | `cargo test --workspace --locked --features local-login` |
| lint | `cargo clippy --workspace --all-targets --locked -- -D warnings` |
| lint, dev-login posture | `cargo clippy --workspace --all-targets --locked --features local-login -- -D warnings` |
| format | `cargo fmt --all --check` |
| dev login cannot ship | `bash scripts/check-local-login-refused.sh` |
| dependency advisories | `bash scripts/check-audit.sh` |
| brand | `bash scripts/check-brand.sh` |
| secrets | `bash scripts/check-secrets.sh` |

Rust 1.88, edition 2024, `unsafe_code = "forbid"`.

The PostgreSQL arm runs against a real server and reports itself skipped when
`IDENTITY_TEST_POSTGRES_URL` is unset:

```bash
IDENTITY_TEST_POSTGRES_URL='postgresql://user:password@host:5432/identity?sslmode=disable' \
  cargo test --locked the_postgres_arm
```

`check-audit.sh` carries one narrowly justified transitive exception: `openidconnect 4.0.1` pulls
`rsa 0.9` unconditionally, and this service uses it only to verify signatures with public JWKs and
never holds an RSA private key. The script first proves the dependency path is still exactly
`identity -> openidconnect -> rsa`; any drift forces re-review, and the exception goes when the
upstream dependency stops carrying that crate.

### Running it locally

Create a Google OAuth web client whose authorized redirect URI is exactly
`http://127.0.0.1:8080/oauth/callback/upstream`, then:

```bash
IDENTITY_LISTEN=127.0.0.1:8080 \
IDENTITY_PUBLIC_ORIGIN=http://127.0.0.1:8080 \
IDENTITY_TENANT_ID=local \
IDENTITY_UPSTREAM_ISSUER=https://accounts.google.com \
IDENTITY_UPSTREAM_CLIENT_ID='your-client-id' \
IDENTITY_UPSTREAM_CLIENT_SECRET='your-client-secret' \
IDENTITY_UPSTREAM_ORGANIZATION_DOMAIN_CLAIM=hd \
IDENTITY_ORGANIZATION_TENANTS_JSON='[{"claimValue":"example.com","tenantId":"local"}]' \
IDENTITY_DATABASE_PATH=/tmp/identity/private/identity.sqlite3 \
cargo run --locked
```

`IDENTITY_CONNECTORS_ENDPOINT` is optional standalone and required when native clients should
discover a trusted hosted Connector API. Production configuration refuses a non-HTTPS public
origin; plain HTTP is accepted only for the literal `127.0.0.1` local-test origin.

### Signing in on a workstation

A workstation has no upstream provider to redirect to, so the flow above cannot complete there. The
optional `local-login` feature replaces exactly the step that has no counterpart: `/oauth/authorize`
asks which mailbox to sign in as and mints the ordinary authorization code. Everything after that
is unchanged.

```bash
cargo run --locked --features local-login
```

Issuing a session for a mailbox somebody typed authenticates nobody, so **three independent rules
refuse it in a deployment, and any one of them is sufficient**:

- **The release profile refuses to compile it.** `src/lib.rs` raises `compile_error!` when the
  feature is combined with `debug_assertions` off, and again — via the `optimized_build` cfg
  `build.rs` derives from `OPT_LEVEL` — whenever the profile optimizes, so
  `RUSTFLAGS='-C debug-assertions=yes' cargo build --release` cannot sneak the route in.
- **The image selects no feature.** `Dockerfile` runs `cargo build --locked --release` with no
  `--features`.
- **A feature build refuses a reachable address.** The process exits before binding unless it both
  listens on a loopback address and publishes a loopback HTTP origin, and the request path checks
  the same predicate again.

`scripts/check-local-login-refused.sh` proves the first two.

## Routes

| route | for |
|---|---|
| `GET /livez` | process liveness only |
| `GET /readyz`, `GET /healthz` | executes a database query; `503` when durable state is unavailable |
| `GET /.well-known/identity-cli-login` | login metadata, including the one closed `connectors_endpoint` |
| `GET /oauth/authorize`, `GET /oauth/callback/upstream`, `POST /oauth/token` | the browser leg and the one-use code exchange |
| `GET /v1/session-authority` | an allowlisted in-cluster caller resolves the current session |
| `POST /v1/access-token`, `GET /v1/access-authority` | mint and resolve a five-minute audience-scoped access token |
| `POST /v1/logout` | revokes the session and every outstanding access token for that subject |
| `/v1/directory/…` | memberships and groups |
| `/v1/profile/…` | the personal collaboration profile |

### Audiences

Every authority-bearing call names **exactly one** audience, verbatim. The vocabulary is
wire-visible — it is minted into issued tokens and required by every relying party — so it still
carries the former org name and moves only as a protocol change with a migration.

| audience | reached by |
|---|---|
| `urn:b10x:connectors` | a native client, via `POST /v1/access-token`; Connectors resolves it at `GET /v1/access-authority` |
| `urn:b10x:substrate` | the same path, for substrate |
| `urn:b10x:status`, `urn:b10x:zwirn` | an in-cluster application, in the `x-b10x-audience` header on `GET /v1/session-authority` |
| `urn:b10x:directory` | every `/v1/directory/…` route, in `x-b10x-audience` |
| `urn:b10x:profile` | the person's own control surface |
| `urn:b10x:profile-projection` | the learning consumer's — it reaches the projection and the learning write, and nothing else: the durable store, the withheld statements and the lifecycle controls are not addressable under it |

The person may see exactly what a consumer is given; a consumer may see nothing else.

Request bodies are capped at 64 KiB. Upstream OIDC uses a five-second connect and fifteen-second
total deadline. Session, access-token and authority responses carry `no-store` and `no-cache`.

Every credential table has a finite row cap, and so do the directory and the profile: 100 000
principals and 10 000 groups per tenant, 512 members per group, 512 groups per subject, 512
statements per subject, 200 000 statements per tenant, 512 characters of statement content, 64
excluded sources. Listings are capped rather than paginated.

## The rules that shape the code

These are the reasons the surface looks the way it does. The full statements are in
[`AGENTS.md`](AGENTS.md).

- **Tenant is resolved from a cryptographically verified upstream claim**, before any code or
  session exists, by exact `claimValue` → `tenantId` mapping. No suffix, email-domain, request-hint
  or default-tenant fallback. Unknown, duplicate, non-string and unmapped claims fail closed. See
  [the tenant-resolution decision](docs/decisions/0001-verified-organization-tenant-resolution.md).
- **Nothing reusable is stored in the clear.** Authorization codes, sessions and access tokens are
  stored only as SHA-256 verifiers. Provider access and refresh tokens are never persisted.
- **Sessions are bound to issuer, tenant and configuration generation.** Changing the
  authority-defining configuration requires a new login.
- **A directory group carries no authority.** Only the deployment-configured static group
  assignments reach an authority response; adding a principal to a directory group grants nothing.
  Directory writes require the static group `identity-directory-admin`, so administration is
  deployment configuration and can never be granted from inside the directory.
- **Groups are flat and membership is direct** — one bounded indexed query, no recursion, no
  transitive closure. Hierarchy belongs to the collaboration product.
- **An inference never silently becomes a confirmation.** The profile learning path admits only
  `observed` and `inferred`; the only transition into `confirmed` is an explicit act by the person.
- **Secret material never enters a profile projection.** Content and source references are screened
  for credential markers, vendor prefixes, JWT shape, URL user info and long opaque tokens — on
  write *and* again when a snapshot is built, so a row that arrived by another route still cannot
  reach a model.
- **Schema changes are additive only.** Every statement is `CREATE … IF NOT EXISTS`; an older
  binary keeps working against a newer schema.

## Layout

| path | holds |
|---|---|
| `src/lib.rs` | the router, OIDC login, sessions, access tokens, authority resolution |
| `src/directory.rs` | memberships and groups |
| `src/profile.rs` | the durable profile lifecycle and its snapshot projection |
| `src/screening.rs` | the credential screen a statement and a snapshot both pass |
| `src/local_login.rs` | the loopback-only development login, behind `local-login` |
| `docs/decisions/` | component decisions |
| `scripts/` | `gate.sh` and the checks it runs |

## Read more

- [`docs/decisions/0001-verified-organization-tenant-resolution.md`](docs/decisions/0001-verified-organization-tenant-resolution.md)
  — why tenant comes from a verified claim and nothing else.
- [`AGENTS.md`](AGENTS.md) — working agreements, invariants, and the release procedure.
