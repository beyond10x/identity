# Working on identity

[github.com/beyond10x/identity](https://github.com/beyond10x/identity) is the canonical home of
the identity broker, extracted from the daemonloom monorepo at
[`a7c40017`](https://github.com/daemonloom/daemonloom/tree/a7c400179d398c3b884da5f6b386db0c8c5dc462)
with full history on 2026-08-23. The monorepo keeps a pinned git-submodule checkout at
`foundation/identity` that its deployment image builds and release checks consume. The gate is
`bash scripts/gate.sh`.

This component owns tenant-scoped principal identity: upstream OpenID Connect login, opaque CLI
sessions, the server-side credential store, and the short-lived access-token authority that
Connectors resolves. Its rules originated in the monorepo root
[`AGENTS.md`](https://github.com/daemonloom/daemonloom/blob/a7c400179d398c3b884da5f6b386db0c8c5dc462/AGENTS.md);
this file carries the component rules.

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
- The `local-login` feature signs a person in as whatever mailbox they name, which in a deployment
  would authenticate nobody. It is refused three ways at once — a build in any shipping profile
  fails to compile, `Dockerfile` selects no feature, and a feature build exits unless both its
  listener and its public origin are loopback. The compile-time refusal fires on two independent
  predicates so `RUSTFLAGS='-C debug-assertions=yes'` cannot force the route into an optimized
  artifact: `not(debug_assertions)` and the `optimized_build` cfg `build.rs` derives from
  `OPT_LEVEL`. Never weaken any of the three, never remove the second predicate, and never make it
  a default feature; `scripts/check-local-login-refused.sh` is the gate that holds the first two.
  `scripts/gate.sh` runs it on every gate here, and the monorepo's pre-release suite keeps running
  it through the pinned submodule checkout.

## Gate

```text
cargo test --workspace --locked
cargo test --workspace --locked --features local-login
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo clippy --workspace --all-targets --locked --features local-login -- -D warnings
cargo fmt --all --check
bash scripts/check-local-login-refused.sh
bash scripts/check-audit.sh
bash scripts/check-secrets.sh
```

`bash scripts/gate.sh` runs the whole sequence; each check script also runs standalone. Green
here is the bar for main.

## Pending per the extraction plan

This is step 1 of the
[identity extraction plan](https://github.com/daemonloom/daemonloom/blob/a7c400179d398c3b884da5f6b386db0c8c5dc462/architecture/docs/reviews/2026-08-23-identity-extraction-plan.md):
extraction only, no renames.

- **M1 — de-brand** is pending: the tree deliberately still carries daemonloom strings (crate
  name, audience URN, well-known route, docs), and there is no brand fence here by design until
  M1 lands. The product name decision (I-1) is open with Timo and blocks M1.
- **M2 — audience registry** is pending: the hardcoded connectors downstream becomes a configured
  registry entry. M1 and M2 come before any new identity feature.

## Safety

Never commit credentials, tokens, customer data, or database files. Automated commits and pushes
use the bot App via `scripts/as-bot.sh`; `scripts/bot-token.sh` selects the beyond10x
installation.
