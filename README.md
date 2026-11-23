# identity

The platform's login and principal service. It owns upstream OpenID Connect login, tenant-scoped
principal identity, opaque CLI sessions, the server-side credential store, the organization
directory, and the personal collaboration profile.

Without it, every product service runs its own upstream OAuth, keeps its own copy of who works
here, and defines what a user identifier means. Upstream provider tokens never leave this process.
A user key is always `(tenant, sub)` and never a bare subject. Every consumer resolves an authority
bound to one exact registered audience.

## Where it sits

Identity consumes a generically configured upstream OIDC provider and either SQLite or PostgreSQL.
Relying parties resolve sessions or five-minute opaque access credentials through exact, opaque
audience registrations. Identity contains no relying-party endpoint, provider integration, product
name, or capability vocabulary.

Upstream provider credentials never reach a consumer. A consumer's registration decides what it
holds:

| consumer | holds | resolves it at |
|---|---|---|
| an in-cluster application registered as a session audience | the person's Identity session, presented with the exact audience | `GET /v1/session-authority` |
| a caller of the directory or profile routes | the person's Identity session, presented with the route's fixed audience | `/v1/directory/…`, `/v1/profile/…` |
| a relying party registered as an access audience | a five-minute access credential for that one audience and scope set, never the session | `GET /v1/access-authority` |

Resolving a session returns the person's authority for that audience. It never mints a reusable
token and never reaches another subject. A consumer's scope is a coarse gate only, so the consumer
must still run its own admission before an effect-bearing operation.

## Status

**The deployable human-login and relying-party authority slice.** The source is public. Its crates
remain deployment components and are not published to crates.io.

| area | state |
|---|---|
| CLI login, sessions, logout | implemented |
| access tokens and access authority | implemented |
| organization directory and groups | implemented |
| personal collaboration profile | implemented |
| PostgreSQL backend | implemented; **distributed admission is not proven**, so a deployment runs one replica with replacement rollouts |
| deployment composition | no maintained chart or manifest; the image and the runtime configuration in [Deploying](#deploying) are the contract |

## Build, test, run

The gate is **`bash scripts/gate.sh`**. It runs tests and clippy in both feature postures, plus
three component checks, and main requires it green.

| step | command |
|---|---|
| tests (each test 60 s, the test run 120 s) | `timeout 600 cargo nextest run --workspace --locked` |
| tests, dev-login posture | `timeout 600 cargo nextest run --workspace --locked --features local-login` |
| lint | `cargo clippy --workspace --all-targets --locked -- -D warnings` |
| lint, dev-login posture | `cargo clippy --workspace --all-targets --locked --features local-login -- -D warnings` |
| format | `cargo fmt --all --check` |
| dev login cannot ship | `bash scripts/check-local-login-refused.sh` |
| dependency advisories | `bash scripts/check-audit.sh` |
| secrets | `bash scripts/check-secrets.sh` |

The former-brand fence is not a step here: it runs organization-wide as Atlas's
`scripts/check-org-brand.sh`.

Rust 1.89 or newer, edition 2024, `unsafe_code = "forbid"`. The gate and the image build use the
rustc pinned in `rust-toolchain.toml`.

The PostgreSQL arm runs against a real server and reports itself skipped when
`IDENTITY_TEST_POSTGRES_URL` is unset:

```bash
IDENTITY_TEST_POSTGRES_URL='postgresql://user:password@host:5432/identity?sslmode=disable' \
  cargo test --locked the_postgres_arm
```

`check-audit.sh` carries one transitive exception: `openidconnect 4.1.0` pulls `rsa 0.9`
unconditionally. This service uses that crate only to verify signatures with public JWKs and never holds
an RSA private key. The script first proves the dependency path is still exactly
`identity -> openidconnect -> rsa`, and any drift forces re-review. The exception goes when the
upstream dependency stops carrying that crate.

### Running it locally

Create an upstream OIDC web client whose authorized redirect URI is exactly
`http://127.0.0.1:8080/oauth/callback/upstream`, then:

```bash
IDENTITY_LISTEN=127.0.0.1:8080 \
IDENTITY_PUBLIC_ORIGIN=http://127.0.0.1:8080 \
IDENTITY_TENANT_ID=local \
IDENTITY_UPSTREAM_ISSUER=https://accounts.example.com \
IDENTITY_UPSTREAM_CLIENT_ID='your-client-id' \
IDENTITY_UPSTREAM_CLIENT_SECRET='your-client-secret' \
IDENTITY_UPSTREAM_ORGANIZATION_DOMAIN_CLAIM=organization \
IDENTITY_ORGANIZATION_TENANTS_JSON='[{"claimValue":"example.com","tenantId":"local"}]' \
IDENTITY_AUDIENCE_REGISTRY_JSON='{"version":"identity.audiences/2","session":["urn:example:console"],"access":[{"audience":"urn:example:resource-api","scopes":["resource.read"],"groupScopes":[{"group":"operator","scopes":["resource.write"]}]}]}' \
IDENTITY_DATABASE_PATH=/tmp/identity/private/identity.sqlite3 \
cargo run --locked
```

`IDENTITY_UPSTREAM_CA_BUNDLE` optionally names a PEM certificate bundle of additional trusted roots
for upstream OIDC HTTPS requests. It supports private certificate authorities, including disposable
local deployments, and certificate and hostname verification stay on. The file must contain
certificates and be no larger than 1 MiB. An unreadable or invalid configured bundle refuses
startup. Omit the variable to use the normal built-in roots. It applies to every configured upstream
provider and does not enable the development login route.

The three `IDENTITY_UPSTREAM_*` variables remain the single-provider compatibility surface. A
deployment with several providers instead supplies a credential-free registry whose
`clientSecretEnv` entries name separately injected environment variables:

```bash
IDENTITY_UPSTREAM_PROVIDERS_JSON='[{"id":"one","label":"Provider one","issuer":"https://accounts.example.com","clientId":"client-one","clientSecretEnv":"IDENTITY_PROVIDER_ONE_SECRET","organizationDomainClaim":"organization","organizationTenants":[{"claimValue":"example.com","tenantId":"local"}]}]'
```

Provider ids are selected through the standard authorization request's `identity_provider`
parameter. When more than one provider is configured, a browser request that omits the selection
receives an Identity-owned chooser that preserves the exact authorization request. An explicit
unknown selection is refused. Login state binds the provider id, so a callback code can be
exchanged only against the issuer and client that started it.

Additional identities are linked only from a live Identity session through `/v1/identity-links`.
Email equality never links people, and the final login method cannot be removed.

A deployment may admit a confidential service to exchange one exact access authority for another.
The seam is disabled by default. A caller declaration contains only the environment-variable name.
The secret must be injected separately from deployment-owned secret material:

```bash
IDENTITY_TRUSTED_ACCESS_CALLERS_JSON='[{"id":"relying-service","secretEnv":"IDENTITY_RELYING_SERVICE_EXCHANGE_SECRET"}]'
IDENTITY_ACCESS_EXCHANGE_POLICIES_JSON='[{"callerId":"relying-service","sourceAudience":"urn:example:published-resource","requiredSourceScopes":["published.call"],"targetAudience":"urn:example:resource-api","allowedTargetScopes":["resource.read"]}]'
```

`POST /v1/access-exchange` requires the source access token in `Authorization` and the confidential
caller in `x-b10x-access-exchange-caller` plus `x-b10x-access-exchange-secret`. Identity binds the
request to the exact policy, requires a human self-actor, recomputes current groups, re-applies the
target audience policy, and returns the ordinary five-minute verifier-only target credential.

The calling service must never forward that credential to the public client whose source token it
exchanged.

Production configuration refuses a non-HTTPS public origin. Plain HTTP is accepted only for the
literal `127.0.0.1` local-test origin.

### Signing in on a workstation

A workstation has no upstream provider to redirect to, so the flow above cannot complete there. The
optional `local-login` feature replaces only the step that has no counterpart: `/oauth/authorize`
asks which mailbox to sign in as and mints the ordinary authorization code. Everything after that
is unchanged.

A feature build needs no upstream provider: leave out every `IDENTITY_UPSTREAM_*` variable and it
starts with the local sign-in only. A partly configured provider is still refused, and a default
build still requires `IDENTITY_UPSTREAM_ISSUER`.

```bash
IDENTITY_LISTEN=127.0.0.1:8080 \
IDENTITY_PUBLIC_ORIGIN=http://127.0.0.1:8080 \
IDENTITY_TENANT_ID=local \
IDENTITY_AUDIENCE_REGISTRY_JSON='{"version":"identity.audiences/2","session":["urn:example:console"],"access":[{"audience":"urn:example:resource-api","scopes":["resource.read"]}]}' \
IDENTITY_DATABASE_PATH="$PWD/target/identity-local/identity.sqlite3" \
cargo run --locked --features local-login
```

With a provider configured as well, it is discovered before the listener opens, as in a default
build. The provider then serves only identity links, because `/oauth/authorize` signs in locally.

Issuing a session for a mailbox somebody typed authenticates nobody, so **three independent rules
refuse it in a deployment, and any one of them is sufficient**:

- **The release profile refuses to compile it.** `src/lib.rs` raises `compile_error!` when the
  feature is combined with `debug_assertions` off, and again whenever the profile optimizes, through
  the `optimized_build` cfg that `build.rs` derives from `OPT_LEVEL`. So
  `RUSTFLAGS='-C debug-assertions=yes' cargo build --release` cannot include the route.
- **The image selects no feature.** `Dockerfile` runs `cargo build --locked --release` with no
  `--features`.
- **A feature build refuses a reachable address.** The process exits before binding unless it both
  listens on a loopback address and publishes a loopback HTTP origin, and the request path checks
  the same predicate again.

`scripts/check-local-login-refused.sh` proves the first two.

## Deploying

This repository ships no chart or manifest. `Dockerfile` builds the image: distroless, the
`nonroot` user, port 8080, volume `/var/lib/identity`. Startup validates the whole environment
below, fetches every upstream provider's OIDC discovery document, opens the store, and only then
binds the listener. Any failure exits non-zero.

Required:

| variable | format |
|---|---|
| `IDENTITY_PUBLIC_ORIGIN` | the issuer: an absolute `https` origin without path, query or fragment; `http` only for host `127.0.0.1` |
| `IDENTITY_TENANT_ID` | the tenant of a login whose provider uses a single-tenant compatibility mode (no organization claim, or the base-domain allowlist); never used under an exact mapping, see [the rules](#the-rules-that-shape-the-code) |
| `IDENTITY_AUDIENCE_REGISTRY_JSON` | the `identity.audiences/2` document in [Audiences](#audiences); no default |
| upstream provider | `IDENTITY_UPSTREAM_PROVIDERS_JSON`, a non-empty array as in [Running it locally](#running-it-locally) whose every `clientSecretEnv` names a set variable; or else all three of `IDENTITY_UPSTREAM_ISSUER` (an `https` URL without query or fragment), `IDENTITY_UPSTREAM_CLIENT_ID`, `IDENTITY_UPSTREAM_CLIENT_SECRET` |

Durable state is SQLite unless a PostgreSQL variable is set:

| variable | default and format |
|---|---|
| `IDENTITY_DATABASE_PATH` | `/var/lib/identity/identity.sqlite3`; the SQLite file |
| `IDENTITY_DATABASE_URL` | a `postgres://` or `postgresql://` URL; selects PostgreSQL |
| `IDENTITY_DB_USER`, `IDENTITY_DB_PASSWORD`, `IDENTITY_DB_HOST`, `IDENTITY_DB_PORT`, `IDENTITY_DB_NAME` | the same URL in parts; once any `IDENTITY_DB_*` is set all five are required; `IDENTITY_DB_PARAMS` defaults to `sslmode=require`; refused together with `IDENTITY_DATABASE_URL` |

Optional:

| variable | default and format |
|---|---|
| `IDENTITY_LISTEN` | `0.0.0.0:8080` |
| `IDENTITY_CLI_CLIENT_ID` | `identity-cli`; the public client whose redirect may be any loopback port |
| `IDENTITY_WEB_CLIENTS_JSON` | `[]`; `[{"clientId":"…","redirectUri":"…"}]`, further public clients, each bound to one exact redirect URI |
| `IDENTITY_STATIC_GROUP_MEMBERSHIPS_JSON` | `[]`; `[{"tenantId":"…","email":"…","groups":["…"]}]`, groups per person; `identity-directory-admin` grants directory writes |
| `IDENTITY_DEFAULT_TENANT_GROUPS_JSON` | `[]`; `[{"tenantId":"…","groups":["…"]}]`, groups for every verified member of the tenant; with the row above, the only groups an authority response carries |
| `IDENTITY_UPSTREAM_ORGANIZATION_DOMAIN_CLAIM` | unset; the single-provider organization claim, set together with exactly one of the next two |
| `IDENTITY_ORGANIZATION_TENANTS_JSON` | unset; `[{"claimValue":"…","tenantId":"…"}]`, exact claim-to-tenant mapping |
| `IDENTITY_ALLOWED_ORGANIZATION_BASE_DOMAINS` | unset; comma-separated base domains, the legacy single-tenant allowlist matched by dotted suffix |
| `IDENTITY_UPSTREAM_CA_BUNDLE` | unset; see [Running it locally](#running-it-locally) |
| `IDENTITY_TRUSTED_ACCESS_CALLERS_JSON`, `IDENTITY_ACCESS_EXCHANGE_POLICIES_JSON` | `[]`; see [Running it locally](#running-it-locally) |
| `RUST_LOG` | `info` |

Constraints ([`AGENTS.md`](AGENTS.md) invariant 7 and the safety envelope):

- **One replica, replacement rollouts**, on either backend. Capacity check-and-insert admission is
  serialized inside one process. A second process, including the overlap of a rolling update, is
  not proven safe.
- **The SQLite directory** must be a non-symlink directory owned by the process user with no group
  or other permission bit (`0700` or stricter). Identity creates it at `0700` when it is missing.
  An existing database must be a non-symlink regular file owned by the same user with no permission
  beyond `0600`. Identity sets it to `0600` on every start. A volume that grants group access is
  refused.
- **Probes:** `GET /livez` for liveness, `GET /readyz` for readiness (`503` while the store is
  unavailable).
- **Configuration changes end sessions.** The issuer, tenant, CLI client, providers with their
  organization policy, web clients, audience registry and access-exchange policies form the session
  configuration generation. Changing any of them requires every person to log in again. Group
  assignments and secrets are not part of it.

## Routes

| route | for |
|---|---|
| `GET /livez` | process liveness only |
| `GET /readyz`, `GET /healthz` | executes a database query; `503` when durable state is unavailable |
| `GET /.well-known/identity-cli-login` | Identity-only login and access-token endpoint metadata |
| `GET /.well-known/oauth-authorization-server` | RFC 8414 metadata for public PKCE clients |
| `GET /oauth/authorize`, `GET /oauth/callback/upstream`, `POST /oauth/token` | the browser leg and the one-use code exchange; a registered RFC 8707 resource yields its short-lived access token directly |
| `GET /v1/session-authority` | an allowlisted in-cluster caller resolves the current session |
| `POST /v1/access-token`, `GET /v1/access-authority` | mint and resolve a five-minute audience-scoped access token |
| `POST /v1/access-exchange` | confidentially narrow one live human access token into an exact deployment-admitted target audience and scope set |
| `POST /v1/logout` | revokes the session and every outstanding access token for that tenant and subject |
| `GET /v1/identity-links` | lists the current person's explicitly linked upstream identities |
| `POST`, `DELETE /v1/identity-links/{provider_id}` | starts an authenticated link flow or removes a non-final link |
| `/v1/directory/…` | memberships and groups |
| `/v1/profile/…` | the personal collaboration profile |

### Audiences

Every authority-bearing call names **exactly one** audience, verbatim. The vocabulary is
wire-visible: it is minted into issued tokens and required by every relying party. It moves only
as a protocol change with a migration. Extensible relying parties are admitted by the required,
versioned `IDENTITY_AUDIENCE_REGISTRY_JSON`. Adding an audience is deployment configuration after
the relying parties have released the same exact byte.

| audience | reached by |
|---|---|
| a registered access audience | an authenticated session via `POST /v1/access-token`, or a public PKCE client through `/oauth/authorize` with the exact `resource`; the relying party resolves either credential at `GET /v1/access-authority` |
| a registered session audience | an in-cluster application, in the `x-b10x-audience` header on `GET /v1/session-authority` |
| `urn:b10x:directory` | every `/v1/directory/…` route, in `x-b10x-audience` |
| `urn:b10x:profile` | the person's own control surface |
| `urn:b10x:profile-projection` | the learning consumer's — it reaches the projection and the learning write, and nothing else: the durable store, the withheld statements and the lifecycle controls are not addressable under it |

The registry document is closed and deterministic:

```json
{
  "version": "identity.audiences/2",
  "session": ["urn:example:console"],
  "access": [{
    "audience": "urn:example:resource-api",
    "scopes": ["resource.read"],
    "groupScopes": [{"group": "operator", "scopes": ["resource.write"]}]
  }]
}
```

Audience and scope bytes are opaque registration data. `scopes` are available to every
authenticated subject. An exact `groupScopes` entry can expand issuance for subjects carrying that
verified group. Identity only enforces the closed registration. The relying party owns the meaning
of those bytes and every operation-level authorization decision.

Unknown versions and fields,
duplicate identifiers or rules, malformed names, unregistered audiences and unregistered scopes are
refused. The canonical registry contributes to the session configuration generation, so changing it
requires a new login.

The standard authorization-server document advertises no dynamic client registration.
A deployment registers one public client ID. Its loopback callback accepts an ephemeral port, and
PKCE S256 is mandatory. An OAuth resource authorization never creates a reusable browser session:
the one-use code is bound to its exact registered audience and scope and exchanges directly for the
same five-minute access-token authority used by `/v1/access-token`.

The person may see exactly what a consumer is given. A consumer may see nothing else.

Request bodies are capped at 64 KiB. Upstream OIDC uses a five-second connect and fifteen-second
total deadline. Session, access-token and authority responses carry `no-store` and `no-cache`.

Session credentials use the opaque `identity_session_v1_` format and short-lived access
credentials use `identity_access_v1_`. Callers must treat both as indivisible bearer values. The
resolved authority vocabulary is product-neutral: `tenant_id` and `principal_kind` carry the
tenant and actor kind without an inherited product namespace.

Every credential table has a finite row cap, and so do the directory and the profile: 100 000
principals and 10 000 groups per tenant, 512 members per group, 512 groups per subject, 512
statements per subject, 200 000 statements per tenant, 512 characters of statement content, 64
excluded sources. Listings are capped and are not paginated.

## The rules that shape the code

The full statements are in [`AGENTS.md`](AGENTS.md).

- **Tenant is resolved from a cryptographically verified upstream claim**, before any code or
  session exists. A provider resolves it in one of three modes:
  1. **Exact mapping** (`IDENTITY_ORGANIZATION_TENANTS_JSON`, or a provider's
     `organizationTenants`): the claim value maps to its `tenantId`. Suffix matching, email domains,
     request hints and `IDENTITY_TENANT_ID` are never fallbacks.
  2. **No organization claim configured**: every login of that provider gets `IDENTITY_TENANT_ID`.
  3. **Legacy base-domain allowlist** (`IDENTITY_ALLOWED_ORGANIZATION_BASE_DOMAINS`, mutually
     exclusive with the mapping): a claim equal to a listed domain or ending in `.` plus it gets
     `IDENTITY_TENANT_ID`.

  Modes 2 and 3 are single-tenant compatibility modes. Unknown, duplicate, non-string and unmapped
  claims fail closed. See
  [the tenant-resolution decision](docs/decisions/0001-verified-organization-tenant-resolution.md).
- **Nothing reusable is stored in the clear.** Authorization codes, sessions and access tokens are
  stored only as SHA-256 verifiers. Provider access and refresh tokens are never persisted.
- **Sessions are bound to issuer, tenant and configuration generation.** Changing the
  authority-defining configuration requires a new login.
- **A directory group carries no authority.** Only the deployment-configured static group
  assignments reach an authority response. Adding a principal to a directory group grants nothing.
  Directory writes require the static group `identity-directory-admin`, so administration is
  deployment configuration and can never be granted from inside the directory.
- **Groups are flat and membership is direct**, one bounded indexed query with no recursion and no
  transitive closure. Hierarchy belongs to the collaboration product.
- **An inference does not become a confirmation by itself.** The profile learning path admits only
  `observed` and `inferred`. The only transition into `confirmed` is an explicit act by the person.
- **Secret material never enters a profile projection.** Content and source references are screened
  for credential markers, vendor prefixes, JWT shape, URL user info and long opaque tokens, on
  write and again when a snapshot is built. A row that arrived by another route therefore still
  cannot reach a model.
- **Schema changes are additive only.** Every statement is `CREATE … IF NOT EXISTS`. An older
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

- [`docs/decisions/0001-verified-organization-tenant-resolution.md`](docs/decisions/0001-verified-organization-tenant-resolution.md):
  why tenant comes from a verified claim and nothing else.
- [`docs/decisions/0003-product-neutral-wire-vocabulary.md`](docs/decisions/0003-product-neutral-wire-vocabulary.md):
  why credentials and resolved authority fields use Identity-owned names.
- [`docs/decisions/0004-agnostic-relying-party-registration.md`](docs/decisions/0004-agnostic-relying-party-registration.md):
  why downstream audiences and scopes are opaque deployment data and not compiled policy.
- [`AGENTS.md`](AGENTS.md): working agreements, invariants, and the release procedure.

<!-- b10x-docs:start -->
## Documentation

[Identity documentation](https://beyond10x.github.io/docs/identity/) · [Start](https://beyond10x.github.io/) · [Ecosystem](https://beyond10x.github.io/ecosystem/) · [Impact](https://beyond10x.github.io/changes/) · [Releases](https://beyond10x.github.io/releases/)
<!-- b10x-docs:end -->
