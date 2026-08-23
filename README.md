# identity

This component contains the first deployable human-login slice for the platform. It owns upstream
OpenID Connect login, tenant-scoped principal identity, opaque CLI sessions, and the server-side
credential store. Product services such as the AI Agent Platform consume this identity; they do not
run Google OAuth themselves.

The supported Babelforce development deployment configures one organization. The implementation
does not encode that deployment choice as a global tenant assumption: an exact mapping from a
cryptographically verified upstream organization claim to `tenant_id` is resolved before an
authorization code or session is created, and tenant plus subject remains the stable user key.
Unknown, duplicate, non-string, and unmapped claims fail closed. See the
[tenant-resolution decision](docs/decisions/0001-verified-organization-tenant-resolution.md).

The implemented CLI flow is:

```text
agent-harness login [HOST]
  -> GET /.well-known/identity-cli-login
  -> browser authorization with state + nonce + S256 PKCE
  -> identity redirects to configured upstream OIDC (Google in dev)
  -> exact loopback callback
  -> one-use authorization-code exchange
  -> opaque identity session stored by the CLI
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
exact `urn:daemonloom:connectors` audience. Every authenticated principal may request
`connectors.catalog.read` or `connectors.invoke` independently. Invocation remains
receiver-authorized: hosted Connectors admits ordinary tenant members only to configured
read-only module operations, while effect-bearing and non-module invocation remains behind its
operator policy. Principals mapped to the deployment's `operator` group may request the exact
larger Connector scope set they need; the resolved group facts travel in the short-lived
authority envelope so Connectors can apply its independent receiver-owned management policy.
Connectors then resolves that access token through `GET /v1/access-authority`; the result is the complete
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
IDENTITY_ORGANIZATION_TENANTS_JSON='[{"claimValue":"example.com","tenantId":"local"}]' \
IDENTITY_DATABASE_PATH=/tmp/identity/private/identity.sqlite3 \
cargo run --locked
```

## Local development sign-in

A workstation has no upstream provider to redirect to, so the flow above cannot complete there and
the local process stack shows every consumer as signed out. The optional `local-login` feature
replaces exactly the step that has no counterpart: with it, `/oauth/authorize` answers with a page
asking which mailbox to sign in as, and then mints the ordinary authorization code. Everything
after that is unchanged — the same one-use code, the same `/oauth/token` exchange, the same opaque
session row, the same tenant resolution, and the same groups
`IDENTITY_STATIC_GROUP_MEMBERSHIPS_JSON` and `IDENTITY_DEFAULT_TENANT_GROUPS_JSON` already assign.

```bash
cargo run --locked --features local-login   # then open /oauth/authorize, or run `zwirn login`
```

Issuing a session for a mailbox somebody typed authenticates nobody, so in a deployment this is not
a setting to leave off. Three independent rules refuse it, and any one of them is sufficient:

- **The release profile refuses to compile it.** `src/lib.rs` raises `compile_error!` whenever the
  feature is combined with `debug_assertions` off. Every release build clears `debug_assertions`,
  so the deployed binary cannot contain the code — the attempt is a build failure, not a flag.
- **The image selects no feature.** `Dockerfile` runs `cargo build --locked --release` with no
  `--features`, so the shipped binary is the default feature set.
- **A feature build refuses a reachable address.** The process exits before binding unless it both
  listens on a loopback address and publishes a loopback HTTP origin, and the request path checks
  the same predicate again.

`scripts/check-local-login-refused.sh` proves the first two: it fails unless
`cargo check --release --features local-login` fails and the `Dockerfile` build stays feature-free.

Browser applications are registered as exact public PKCE clients. Static group assignments are
deployment configuration evaluated against the verified upstream email on every authority lookup;
tenant-default groups apply to every verified email admitted into that exact tenant. Neither form
is copied into application databases or browser cookies. For example:

```bash
IDENTITY_WEB_CLIENTS_JSON='[{"clientId":"status-web","redirectUri":"https://code.example.test/status/oauth/callback"}]'
IDENTITY_STATIC_GROUP_MEMBERSHIPS_JSON='[{"tenantId":"local","email":"operator@example.test","groups":["operator"]}]'
IDENTITY_DEFAULT_TENANT_GROUPS_JSON='[{"tenantId":"local","groups":["org-member"]}]'
```

An internal Status or Zwirn application may resolve the current Identity session with `GET
/v1/session-authority`, an Identity session bearer, and the exact
`x-daemonloom-audience: urn:daemonloom:status` or `urn:daemonloom:zwirn` header. The no-store response contains the verified
subject, email, tenant, expiry, and current static groups. This endpoint is intended for an
allowlisted in-cluster caller; it does not turn groups into independently reusable access tokens.

## Organization directory and groups

Identity owns principals, so it also owns the organization directory that names them. A
consuming product resolves a person or a set of people here instead of keeping its own copy.

A **membership** records that a principal belongs to one resolved tenant, its kind
(`human`, `agent`, or `service`), and whether it is `active` or `suspended`. A **group** names a set
of members inside the same tenant.

- **Groups are flat.** A group holds principals and never another group, so resolution is one
  bounded indexed query with no recursion and no transitive closure. Hierarchy — teams inside
  teams, reporting lines, progression — belongs to the collaboration product's workforce view.
- **Membership is direct.** Belonging to one group never implies belonging to another.
- **A directory group carries no authority.** The static group assignments above remain the only
  group vocabulary that reaches an authority response. Adding a principal to a directory group
  grants nothing, mints no token, and changes no scope.
- **An agent identity is an ordinary member.** Mixed human and agent participation is the normal
  case, and a group that could not hold an agent would force a second grouping model downstream.
  An agent membership is still not a login, and only a `human` principal may carry an email
  address, which is the join key of the static authority table.
- Suspending a membership removes the principal from every group resolution in one operation;
  the rows are preserved, so reactivation restores the memberships.

Every route requires an Identity session and the exact `x-daemonloom-audience:
urn:daemonloom:directory` header. Writes additionally require the deployment-configured static
group `identity-directory-admin`, so directory administration is deployment configuration and can
never be granted by a directory group.

```text
GET    /v1/directory/membership                              own membership and groups
GET    /v1/directory/groups/{group_key}                      group and its active members
PUT    /v1/directory/groups/{group_key}                      admin: create or rename a group
PUT    /v1/directory/members/{subject}                       admin: enroll or update a membership
PUT    /v1/directory/groups/{group_key}/members/{subject}    admin: add a member
DELETE /v1/directory/groups/{group_key}/members/{subject}    admin: remove a member
```

Bounds: 100 000 memberships and 10 000 groups per tenant, 512 members per group, 512 groups per
subject. Listings are capped rather than paginated.

## Personal collaboration profile

Identity owns the durable profile lifecycle. A worker never touches the store; it receives an
immutable snapshot value identified by a digest over its own content. Every route is self-scoped —
the subject of the presented session is the subject of the profile — and no route in this service
reads or writes another principal's profile.

There are two exact audiences. `urn:daemonloom:profile` is the person's own control surface.
`urn:daemonloom:profile-projection` is the learning consumer's, and it reaches only the projection
and the learning write: the durable store, the withheld statements, and the lifecycle controls are
not addressable under it. The person may see exactly what a consumer is given; a consumer may see
nothing else.

A statement has a kind (`goal_horizon` with a `session`, `short_term`, or `long_term` horizon,
`preference`, `working_pattern`, or `friction`), an epistemic state, and the source evidence it
came from as a closed `kind:id` reference.

- **An inference never silently becomes a confirmation.** The learning write path admits only
  `observed` and `inferred`. The only transition into `confirmed` is an explicit act by the person
  on their own profile.
- **The person can inspect, correct, forget, and revoke.** Inspection works regardless of consent.
  Revoking withdraws a statement from every projection while keeping the record of the withdrawal;
  forgetting deletes the row and its evidence. Correcting writes a new confirmed statement and
  marks the previous one revoked and superseded.
- **Profile-learning consent is its own consent.** It is not a Connector scope, a datasource grant,
  or an endpoint authority. Granting it mints nothing; revoking it empties the projection without
  touching any other authority and without destroying data.
- **Secret material and excluded sources never enter a projection.** Statement content and source
  references are screened for credential markers, vendor prefixes, JSON Web Token shape, URL user
  information, and long mixed-class opaque tokens. The screen runs when a statement is written and
  again when a snapshot is built, so a row that reached the database by another route still cannot
  reach a model.

```text
person only    GET    /v1/profile                          durable view, with withheld reasons
person only    PUT    /v1/profile/consent                  profile.learning and excluded sources
person only    POST   /v1/profile/statements/{id}/confirm  the person confirms
person only    POST   /v1/profile/statements/{id}/revoke   the person revokes or rejects
person only    POST   /v1/profile/statements/{id}/correct  corrects, superseding the previous one
person only    DELETE /v1/profile/statements/{id}          the person forgets
also consumer  GET    /v1/profile/snapshot                 immutable model-visible projection
also consumer  POST   /v1/profile/statements               learn an observed or inferred statement
```

Bounds: 512 statements per subject, 200 000 per tenant, 512 characters of statement content, 64
excluded sources.

Directory and profile tables are additive. Every statement is `CREATE TABLE`/`CREATE INDEX IF NOT
EXISTS`; no existing table, column, index, or row is altered, rewritten, or dropped, so the schema
is safe to apply to a running deployment and an older binary keeps working against it unchanged.

The organization policy reads only the cryptographically verified upstream ID token. Hosted
multi-organization-ready configuration uses `IDENTITY_ORGANIZATION_TENANTS_JSON`, an array of
exact `claimValue`/`tenantId` mappings, together with
`IDENTITY_UPSTREAM_ORGANIZATION_DOMAIN_CLAIM`. No suffix, email-domain, request-hint, or default
tenant fallback is applied. The older base-domain allowlist remains mutually exclusive
single-tenant compatibility configuration. With Google Workspace, use the signed `hd` claim rather
than inferring membership from the email address or the authorization request's `hd` hint.

For example, an isolation fixture can configure two exact organizations in one process:

```bash
IDENTITY_UPSTREAM_ORGANIZATION_DOMAIN_CLAIM=hd
IDENTITY_ORGANIZATION_TENANTS_JSON='[
  {"claimValue":"alpha.example","tenantId":"tenant-alpha"},
  {"claimValue":"beta.example","tenantId":"tenant-beta"}
]'
```

Authorization codes, sessions, access authorities, static groups, directory rows, and profile rows
all retain the resolved tenant. Downstream authority always carries both `tenant` and `sub`; a user
identifier without its tenant is incomplete.

Production configuration refuses a non-HTTPS public origin. Plain HTTP is accepted only for the
literal `127.0.0.1` local-test origin.

## Deploy to the dev cluster

Deployment composition belongs to the platform's cloud umbrella chart rather than this service
component. Its developer profile installs PostgreSQL and Identity by immutable digest behind an
internal TLS ingress. Workstation Buildx pushes to the persistent development registry; in-cluster
BuildKit is disabled.

The chart creates a labeled Identity discovery `ExternalName` Service. A
hostless harness login discovers the current cluster's CoreDNS service and cluster domain, tunnels
DNS-over-TCP through the Kubernetes API, and resolves that Service's CNAME to the public HTTPS
origin. The service record exists only in a cluster where identity is deployed;
the CLI does not derive a company domain from a Kubernetes context name.

Register the chart's public Identity origin plus `/oauth/callback/upstream` as the Google redirect
URI. For example:

```text
https://identity.dev.example.com/oauth/callback/upstream
```

Then run the Cloud developer deployment command with a JSON file containing `client_id` and
`client_secret`. The command creates Kubernetes Secrets without putting their values in Helm,
builds this exact clean Git commit locally, pushes its digest, and installs the resulting lock.

```bash
../../deployments/dev/release.sh --help
```

The monorepo contains no OAuth client secret, database password, registry password, or reusable
login credential.

## Checks

```bash
cargo test --locked
cargo test --locked --features local-login
cargo clippy --all-targets --locked -- -D warnings
cargo clippy --all-targets --locked --features local-login -- -D warnings
cargo fmt --all -- --check
scripts/check-local-login-refused.sh
scripts/check-audit.sh
../cloud/tests/static.sh
```

The directory and profile stores keep a separate SQL statement per backend, and the in-memory tests
cover only the `SQLite` one. `the_postgres_arm_applies_the_same_schema_and_queries` exercises the
clustered arm against a real server and reports that it was skipped when
`IDENTITY_TEST_POSTGRES_URL` is unset:

```bash
IDENTITY_TEST_POSTGRES_URL='postgresql://user:password@host:5432/identity?sslmode=disable' \
  cargo test --locked the_postgres_arm
```

The audit check contains one narrowly justified transitive exception: `openidconnect 4.0.1`
carries `rsa 0.9` unconditionally, while this service uses it only to verify signatures with public
JWKs and never possesses an RSA private key, so the advisory's private-key timing-recovery path is
absent. The script first proves that the dependency path is still exactly
`Identity -> openidconnect -> rsa`; any path drift forces re-review. The exception must be removed
when the upstream dependency no longer carries that crate.
