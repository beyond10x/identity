# Working on daemonloom/foundation/identity

This component owns Daemonloom's tenant-scoped principal identity: upstream OpenID Connect login,
opaque CLI sessions, the server-side credential store, and the short-lived access-token authority
that Connectors resolves. The root [`AGENTS.md`](../../AGENTS.md) applies throughout; this file
adds component rules.

Read in order:

1. `README.md`
2. `docs/decisions/0001-verified-organization-tenant-resolution.md`
3. the applicable architecture ADRs for identity and authority envelopes

## Boundary

- Identity owns principal and tenant truth. Products and other foundation services consume it;
  they never run upstream OAuth themselves or store a second copy of principal facts.
- Upstream provider tokens never leave the identity process. Authorization codes, sessions, and
  Connector access tokens are stored only as SHA-256 verifiers.
- Unknown, duplicate, non-string, and unmapped upstream claims fail closed. Never widen a
  fail-closed path to make a deployment convenient.
- Tenant plus subject is the stable user key; a deployment choice (one organization) must not be
  encoded as a global tenant assumption.
- Distributed admission is unproven: the development composition fixes Identity at one replica.
  Do not raise the replica count without proving check-and-insert admission across processes.

## Gate

```text
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo fmt --all --check
```

Run `bash scripts/check-local.sh --release` from the monorepo root before treating a
cross-component change as green.

## Safety

Never commit credentials, tokens, customer data, or database files. Automated commits and pushes
use `daemonloom-bot` per the root `AGENTS.md`.
