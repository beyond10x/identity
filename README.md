# identity

The platform's login and principal service. It owns upstream OpenID Connect login, tenant-scoped
principal identity, opaque CLI sessions, the server-side credential store, the organization
directory, and the personal collaboration profile.

The problem it removes: every product service otherwise runs its own upstream OAuth, keeps its own
copy of who works here, and invents its own idea of what a user identifier means. Here, upstream
provider tokens never leave this process, a user key is always `(tenant, sub)` and never a bare
subject, and a consumer resolves a short-lived audience-scoped authority instead of holding a
login session.

## Where it sits

Identity consumes a generically configured upstream OIDC provider and either SQLite or PostgreSQL.
Relying parties resolve sessions or five-minute opaque access credentials through exact, opaque
audience registrations. Identity contains no relying-party endpoint, provider integration, product
name, or capability vocabulary.

Login sessions and upstream provider credentials never reach a consumer. A consumer's scope is a
coarse gate only — it must still run its own admission before an effect-bearing operation.

## Status

**The deployable human-login and relying-party authority slice.** The source is public; its crates
remain deployment components and are not published to crates.io.

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

The three `IDENTITY_UPSTREAM_*` variables remain the single-provider compatibility surface. A
deployment with several providers instead supplies a credential-free registry whose
`clientSecretEnv` entries name separately injected environment variables:

```bash
IDENTITY_UPSTREAM_PROVIDERS_JSON='[{"id":"one","label":"Provider one","issuer":"https://accounts.example.com","clientId":"client-one","clientSecretEnv":"IDENTITY_PROVIDER_ONE_SECRET","organizationDomainClaim":"organization","organizationTenants":[{"claimValue":"example.com","tenantId":"local"}]}]'
```

Provider ids are selected through the standard authorization request's `identity_provider`
parameter. When more than one provider is configured, a browser request that omits the selection
receives an Identity-owned chooser preserving the exact authorization request; an explicit unknown
selection is refused. Login state binds the provider id, so a callback code can be exchanged only
against the issuer and client that started it. Additional identities are linked only from a live Identity session through
`/v1/identity-links`; email equality never links people and the final login method cannot be
removed.

A deployment may admit a confidential service to exchange one exact access authority for another.
The seam is disabled by default. Caller declarations contain only the environment-variable name;
the secret itself must be injected separately from deployment-owned secret material:

```bash
IDENTITY_TRUSTED_ACCESS_CALLERS_JSON='[{"id":"relying-service","secretEnv":"IDENTITY_RELYING_SERVICE_EXCHANGE_SECRET"}]'
IDENTITY_ACCESS_EXCHANGE_POLICIES_JSON='[{"callerId":"relying-service","sourceAudience":"urn:example:published-resource","requiredSourceScopes":["published.call"],"targetAudience":"urn:example:resource-api","allowedTargetScopes":["resource.read"]}]'
```

`POST /v1/access-exchange` requires the source access token in `Authorization` and the confidential
caller in `x-b10x-access-exchange-caller` plus `x-b10x-access-exchange-secret`. Identity binds the
request to the exact policy, requires a human self-actor, recomputes current groups, re-applies the
target audience policy, and returns the ordinary five-minute verifier-only target credential. The
calling service must never forward that credential to the public client whose source token it
exchanged.

Production configuration refuses a non-HTTPS public origin; plain HTTP is accepted only for the
literal `127.0.0.1` local-test origin.

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
| `GET /.well-known/identity-cli-login` | Identity-only login and access-token endpoint metadata |
| `GET /.well-known/oauth-authorization-server` | RFC 8414 metadata for public PKCE clients |
| `GET /oauth/authorize`, `GET /oauth/callback/upstream`, `POST /oauth/token` | the browser leg and the one-use code exchange; a registered RFC 8707 resource yields its short-lived access token directly |
| `GET /v1/session-authority` | an allowlisted in-cluster caller resolves the current session |
| `POST /v1/access-token`, `GET /v1/access-authority` | mint and resolve a five-minute audience-scoped access token |
| `POST /v1/access-exchange` | confidentially narrow one live human access token into an exact deployment-admitted target audience and scope set |
| `POST /v1/logout` | revokes the session and every outstanding access token for that subject |
| `GET /v1/identity-links` | lists the current person's explicitly linked upstream identities |
| `POST`, `DELETE /v1/identity-links/{provider_id}` | starts an authenticated link flow or removes a non-final link |
| `/v1/directory/…` | memberships and groups |
| `/v1/profile/…` | the personal collaboration profile |

### Audiences

Every authority-bearing call names **exactly one** audience, verbatim. The vocabulary is
wire-visible — it is minted into issued tokens and required by every relying party — and moves only
as a protocol change with a migration. Extensible relying parties are admitted by the required,
versioned `IDENTITY_AUDIENCE_REGISTRY_JSON`; adding an audience is deployment configuration after
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
authenticated subject; an exact `groupScopes` entry can expand issuance for subjects carrying that
verified group. Identity only enforces the closed registration. The relying party owns the meaning
of those bytes and every operation-level authorization decision. Unknown versions and fields,
duplicate identifiers or rules, malformed names, unregistered audiences and unregistered scopes are
refused. The canonical registry contributes to the session configuration generation, so changing it
requires a new login.

The standard authorization-server document deliberately advertises no dynamic client registration.
A deployment registers one public client ID; its loopback callback accepts an ephemeral port, and
PKCE S256 is mandatory. An OAuth resource authorization never creates a reusable browser session:
the one-use code is bound to its exact registered audience and scope and exchanges directly for the
same five-minute access-token authority used by `/v1/access-token`.

The person may see exactly what a consumer is given; a consumer may see nothing else.

Request bodies are capped at 64 KiB. Upstream OIDC uses a five-second connect and fifteen-second
total deadline. Session, access-token and authority responses carry `no-store` and `no-cache`.
Session credentials use the opaque `identity_session_v1_` format and short-lived access
credentials use `identity_access_v1_`; callers must treat both as indivisible bearer values. The
resolved authority vocabulary is product-neutral: `tenant_id` and `principal_kind` carry the
tenant and actor kind without an inherited product namespace.

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
- [`docs/decisions/0003-product-neutral-wire-vocabulary.md`](docs/decisions/0003-product-neutral-wire-vocabulary.md)
  — why credentials and resolved authority fields use Identity-owned names.
- [`docs/decisions/0004-agnostic-relying-party-registration.md`](docs/decisions/0004-agnostic-relying-party-registration.md)
  — why downstream audiences and scopes are opaque deployment data rather than compiled policy.
- [`AGENTS.md`](AGENTS.md) — working agreements, invariants, and the release procedure.

<!-- b10x-docs:start -->
## Documentation

[Identity documentation](https://beyond10x.github.io/docs/identity/) · [Start](https://beyond10x.github.io/) · [Ecosystem](https://beyond10x.github.io/ecosystem/) · [Impact](https://beyond10x.github.io/changes/) · [Releases](https://beyond10x.github.io/releases/)
<!-- b10x-docs:end -->
