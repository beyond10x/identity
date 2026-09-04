# AGENTS.md — identity

The contract for changing **this** repository. Org-wide rules — the naming convention, the language rule (anything that runs is Rust, not Python), the
former-brand rule (atlas ADR 0001) and its four exemption categories, and the rule that renaming
anything another repo verifies is a coordinated migration with an ADR — live in `atlas/AGENTS.md`
and are not restated here.

`README.md` describes the login flow, the storage postures and the configuration surface. This file
says what must not break.

## Serves

The objectives of the collection this repository moves, by id from `atlas/ROADMAP.md` — the only
cross-repository roadmap, and the page that says what each id means and which evidence closes it:

- **O1 — governed reach.** Who is acting, for which tenant, with which audience — decided before any grant is consulted.
- **O4 — products run on the foundation.** The predecessor's phase 8, identity delivery against released seams, is carried here.

A change here that moves none of these is a question for the operator, not a task.
`atlas/scripts/check-map.sh` fails a repository whose `AGENTS.md` names no objective.

## What this repository owns

Tenant-scoped principal identity: upstream OpenID Connect login, opaque CLI sessions, the
server-side credential store, and the short-lived access-token authority that relying parties
resolve.

## Invariants

Each is a claim that can be checked. Breaking one is a design change, not a refactor.

1. **Identity owns principal and tenant truth.** Products and other services consume it. They never
   run upstream OAuth themselves and never store a second copy of a principal fact.
2. **Upstream provider tokens never leave this process.** Authorization codes, sessions and relying-
   party access tokens are stored **only as SHA-256 verifiers** — never as the value.
3. **Unknown, duplicate, non-string and unmapped upstream claims fail closed.** Never widen a
   fail-closed path to make a deployment convenient.
4. **Tenant plus subject is the stable user key.** The supported deployment configures one
   organization; that deployment choice must not be encoded as a global tenant assumption. The exact
   mapping from a cryptographically verified upstream organization claim to `tenant_id` is resolved
   *before* an authorization code or session is created
   (`docs/decisions/0001-verified-organization-tenant-resolution.md`).
5. **Login transactions and authorization codes are single-use**, expired rows are collected, and
   every credential table has a finite row cap.
6. **A session is bound to the exact issuer, tenant and authority-defining configuration
   generation.** Changing any of them requires a new login; a session must never survive a change to
   what it was an authority over.
7. **Distributed admission is unproven.** Capacity check-and-insert admission is serialized inside
   the process, so the development composition fixes Identity at **one replica** with replacement
   rollouts. Do not raise the replica count without first proving check-and-insert admission across
   processes.
8. **The `local-login` feature is refused three ways at once, and each way is load-bearing.** It
   signs a person in as whatever mailbox they name, which in a deployment would authenticate nobody.
   - a build in any shipping profile **fails to compile**;
   - `Dockerfile` selects no feature;
   - a feature build **exits unless both its listener and its public origin are loopback**.

   The compile-time refusal fires on **two independent predicates** so
   `RUSTFLAGS='-C debug-assertions=yes'` cannot force the route into an optimized artifact:
   `not(debug_assertions)`, and the `optimized_build` cfg that `build.rs` derives from `OPT_LEVEL`.
   **Never weaken any of the three, never remove the second predicate, and never make it a default
   feature.** `scripts/check-local-login-refused.sh` holds the first two and runs on every gate.
9. **The RUSTSEC-2023-0071 exception is pinned to one dependency path.** `openidconnect` carries
   `rsa` unconditionally; identity uses only public-JWK signature verification and never loads an RSA
   private key, so the advisory's private-key recovery path is unreachable.
   `scripts/check-audit.sh` fails if that path changes, which is the signal to **re-review the
   exception** rather than to re-pin it.

## Safety envelope

This repository *is* the auth boundary. Every item below needs its own change, its own review and
its own evidence.

- **Wire-visible token audiences are admitted through the M2 registry.** The
  `urn:b10x:*` audience URNs and the `x-b10x-audience` request header are minted into
  issued tokens and required **verbatim by every relying party** (`README.md` § *Audiences*).
  They were moved off the former brand in one deliberate cut, which invalidated
  every session then live; they carry no banned token now, so nothing about them is exempt from
  a per-repo fence any more. Renaming one again is a **coordinated migration with an ADR in
  atlas** (atlas ADR 0001 § *Wire-visible identifiers*), done by cutting a new audience vocabulary —
  never by rewriting the current one. The versioned registry is the only extensible admission
  path; route-owned directory and profile audiences remain fixed to those routes. A new audience
  still requires its relying parties to release the same exact byte before deployment configuration
  admits it.
- **Credential storage is verifier-only (invariant 2).** A change that persists, logs, traces or
  returns a token value — including in an error path or a debug impl — is a breach, not a
  regression.
- **The database file is part of the envelope.** SQLite must be a non-symlink regular file inside a
  service-user-owned directory at mode `0700` or stricter, and the database itself is forced to
  `0600`. Never relax either check to make a local run easier.
- **Revocation is total.** `POST /v1/logout` revokes the presented session **and every outstanding
  relying-party access token for that subject**. A partial revocation leaves a live credential
  behind.
- **Relying-party registration is opaque.** Identity may validate and bind configured audience and
  scope bytes, but it contains no downstream endpoint, provider flow, product name, capability
  vocabulary, or product-specific policy branch. The relying party owns scope meaning and the final
  authorization decision.
- **Nothing sensitive enters history.** `scripts/check-secrets.sh` scans the **complete repository
  history** with a checksum-pinned Gitleaks release. Never commit credentials, tokens, customer data
  or database files.

## Out of scope

| Belongs elsewhere | Repo |
|---|---|
| Authorization decisions a relying party makes with a valid token | the relying party |
| Model routing and LLM request termination | `llmgw` |
| Agent loops | `harness` |
| Sandboxed execution | `substrate` |
| The audience *vocabulary's* cross-repo rename | an ADR in `atlas` — see the safety envelope |

Identity answers *who* and *which tenant*. It does not answer *may they*.

## The gate

```console
bash scripts/gate.sh
```

Each step also runs standalone. In order:

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

Both feature postures are gated because invariant 8 is a property of *both* builds. Green here is the
bar for `main`.

**A green local gate does not guarantee a green CI.** The steps mirror each other; the toolchain does
not — CI installs whatever `stable` is that day, and a newer clippy or a newly published advisory can
fail a commit that passed locally. Run `rustup update` before pushing, and read the gate's own exit
status, never a pipeline's (`gate.sh 2>&1 | tail` reports `tail`'s status, not the gate's).

## Releases

The tag is the bare version — `0.2.0`, the version and nothing else (atlas § *Naming*), annotated, at
a fully gated `main` commit. The full gate comes first; component steps alone are not enough. This
repository has no `CHANGELOG.md`; if one is added, its heading is the version the tag carries.

## Where work is tracked

| What | Where |
|---|---|
| Agreed and proposed work | `.engineering/planning/` — the governed store; every mutation goes through `protocol artifact`, never an editor |
| Accepted component decisions | `docs/decisions/` |
| The current milestone | Agnostic relying-party registration — see the governed planning store |
| The deployed behaviour a client depends on | `README.md` |

## Public source

This repository is public. Organization delivery credentials and bot-authenticated remote
operations are provided by Atlas-owned tooling outside component source.

<!-- b10x-docs-operations:start -->
## Public documentation operations

This repository owns the public source and presentation allowlist in `b10x.docs.yaml`. The generated credential-free `.github/workflows/b10x-docs-bundle.yml` passively packages only those declared files for the exact successful `main` commit; it must never run repository code. Atlas selects the latest successful bundle with every other catalog source, and Website plus Docs System own rendering, shared components, search, and feeds. Do not add a standalone docs deployer or put App credentials in this public repository. If Atlas catalogs a former Pages workflow, that file remains repository-owned validation: preserve its bespoke checks while keeping exact read-only permissions, an unconditional pull-request trigger, and no deployment primitives. Project Pages at `/identity/` is only the generated stable redirect façade in `.github/workflows/b10x-docs-pages.yml`; content-only publication never rebuilds it.

From the complete organization workspace, verify the contract with a clean Atlas checkout at the current remote `main`. Set `B10X_ATLAS_CHECKOUT` to a managed Atlas worktree when the primary checkout is dirty or stale; never infer command availability from the primary alone.

```bash
atlas_checkout="${B10X_ATLAS_CHECKOUT:-atlas}"
atlas_head="$(git -C "$atlas_checkout" rev-parse HEAD)"
atlas_main="$(git -C "$atlas_checkout" ls-remote origin refs/heads/main | awk '{print $1}')"
test -z "$(git -C "$atlas_checkout" status --porcelain)"
test "$atlas_head" = "$atlas_main"
cargo run --manifest-path "$atlas_checkout/Cargo.toml" --locked -q -- \
  --store "$atlas_checkout/catalog/store" docs reconcile --workspace . --check
```

Keep internal plans, stories, ADRs, decisions, worklogs, security material, and research out of the public allowlist unless a repository authority explicitly declares them public.
<!-- b10x-docs-operations:end -->
