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
bash scripts/check-brand.sh
bash scripts/check-secrets.sh
```

`bash scripts/gate.sh` runs the whole sequence; each check script also runs standalone. Green
here is the bar for main.

## Extraction plan status

This repository follows the
[identity extraction plan](https://github.com/daemonloom/daemonloom/blob/a7c400179d398c3b884da5f6b386db0c8c5dc462/architecture/docs/reviews/2026-08-23-identity-extraction-plan.md).

- **Step 1 — extraction** landed 2026-08-23: full history, and the monorepo consumes a pinned
  submodule checkout at `foundation/identity`.
- **M1 — de-brand** landed 2026-08-23. I-1 is resolved: the product's name is **identity**
  (Timo, 2026-08-23). I-2 took its default: a hard cut with no compatibility alias — the dev
  cluster was the only consumer, and the monorepo callers moved in the same wave. The crate and
  binary are `identity`, CLI discovery is `/.well-known/identity-cli-login`, and
  `scripts/check-brand.sh` is the fence: it fails the gate on any surface regression, with the
  allowed classes documented in the script (pinned provenance URLs, the extraction-provenance
  phrase, the `urn:daemonloom:*` audience vocabulary and `x-daemonloom-audience` header held for
  M2, and the bot App machinery).
- **M2 — audience registry** is pending: the hardcoded connectors downstream becomes a configured
  registry entry, and the audience vocabulary above becomes deployment configuration. M2 comes
  before any new identity feature.

## Safety

Never commit credentials, tokens, customer data, or database files. Automated commits and pushes
use the bot App via `scripts/as-bot.sh`; `scripts/bot-token.sh` selects the beyond10x
installation.
