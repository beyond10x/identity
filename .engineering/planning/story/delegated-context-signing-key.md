---
format: aep.planning-md/1
id: story:delegated-context-signing-key
kind: story
status: draft
title: Sign a delegated-context assertion substrate can verify offline
summary: Substrate ADR 0011 needs an EdDSA-signed, audience-scoped assertion; identity holds no signing key and admits one audience.
revision: 2
---
## Why

[substrate ADR 0011](https://github.com/beyond10x/substrate/blob/main/adr/0011-delegated-context-and-grant-attribution.md)
(accepted 2026-08-29) makes an effectful substrate operation carry a **delegated-context document**:
a compact JWS, `alg` EdDSA over Ed25519, `typ` `substrate-delegated-context+jwt`, `kid` naming a
configured trusted key, lifetime at most 300 s, audience `urn:b10x:substrate`, carrying the platform
principal in `sub`, the immediate actor in `act.sub`, the substrate subject and deployment it is bound
to, the tenant, a grant reference and a grant-set revision. Substrate verifies it **offline** — it
calls no issuer during a request and does not resolve the grant.

That closes atlas objective O1: every effectful call in a run's record attributable to a declared
grant. Today substrate's ledger `principal` column holds the calling process id, so it cannot answer
that question at all.

ADR 0011 names identity and connectors as the two candidate issuers and leaves the choice to
configuration. Connectors already issues Ed25519 compact JWS. Identity does not.

## What is true here today (verified)

| Fact | Evidence |
|---|---|
| The access token is an opaque random string; the claim set is stored server-side and returned by callback | `src/lib.rs:1938-1941` mints `dl_access_v1_<32 random>`; `put_access_token` at `src/lib.rs:1172` |
| Nothing in this service signs anything | no signing key, `SigningKey`, Ed25519 or JWT-encode call in `src/`; `rsa 0.9` is used only to *verify* upstream public JWKs (`README.md:68`) |
| There is no `kid`, no JWKS endpoint of our own, no key rotation story | same |
| Exactly one audience is admitted, hardcoded | `src/lib.rs:77` `CONNECTORS_AUDIENCE = "urn:b10x:connectors"`; `issue_access_token` refuses any other at `src/lib.rs:1920-1922` |
| The claim shape already overlaps what ADR 0011 wants | `AccessAuthority` at `src/lib.rs:1658` already carries `iss`, `sub`, `aud`, `iat`/`nbf`/`exp`, `jti`, `act.sub`, `scope`, `dl_tenant` |
| The lifetime already matches | `ACCESS_TOKEN_LIFETIME_SECONDS = 5 * 60` (`src/lib.rs:70`); ADR 0011 caps at 300 s |
| Identity holds no grant | ADR 0011 § Context: connectors owns the grant and carries the grant reference and grant-set revision on every decision |

So the gap is three things, not a rewrite: **a signing key with a `kid` and a way to publish it**, **a
second audience**, and **two claims (`grant_ref`, `grant_rev`) identity does not have**.

## The blocker, stated plainly

`AGENTS.md:73-84`: *"Wire-visible token audiences are frozen until the M2 audience registry lands… **M2
comes before any new identity feature.**"* ADR 0011 assumes `urn:b10x:substrate` is *"adopted from
identity's published vocabulary, not minted here"* — but this repository's published vocabulary is one
audience, `urn:b10x:connectors`. `urn:b10x:substrate` is a **new mint**, and a new mint is a
coordinated migration with an ADR in atlas (atlas ADR 0001 § *Wire-visible identifiers*), gated behind
M2.

**This story therefore depends on M2 and does not jump it.** Nothing here is urgent for substrate:
ADR 0011 ships the field optional everywhere, and the hosted requirement stays off until an issuer
exists.

## The decision this asks for

Not "build it" — **which issuer signs**. Two readings, and identity's own state argues against itself:

1. **Connectors signs.** It already issues Ed25519 compact JWS and it is the only service that holds
   the grant reference and grant revision the document must carry. Identity does nothing; this story
   closes as declined with that recorded. Substrate changes no code either way — the trusted key is
   configuration.
2. **Identity signs.** Correct if the platform principal, not the grant, is what the trust anchor
   should be rooted in. Then identity takes on: an Ed25519 key with a `kid`, a publication mechanism
   (JWKS or a pinned key in substrate's config), rotation, a second audience after M2, and a way to
   obtain `grant_ref`/`grant_rev` from connectors — which it currently has no path to.

Option 1 is the cheaper and better-grounded reading, and this story exists so that choosing it is
recorded rather than defaulted into by nobody acting.

## Acceptance

Either:

- **(declined)** an accepted decision record in `docs/decisions/` stating that connectors is the
  delegated-context issuer and identity mints no substrate audience, cross-referenced from substrate
  ADR 0011 — the story moves to `rejected`; or
- **(built)** identity issues an EdDSA/Ed25519 compact JWS with the ADR 0011 claim set and `typ`, under
  a `kid` substrate can resolve to a public key, for audience `urn:b10x:substrate` admitted through the
  M2 registry rather than a second hardcoded constant, with the conformance vector pair from ADR 0011
  held byte-identically here and in substrate and carrying only public key material — and no token
  value or private key persisted, logged or returned (invariant 2, `AGENTS.md:84-86`).

## Not in scope

Grant evaluation, introspection, or any runtime call from substrate to identity. ADR 0011 forbids all
three: a verified document annotates or refuses, and never admits an operation substrate's own checks
declined.
