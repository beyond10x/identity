---
format: aep.planning-md/1
id: story:agnostic-relying-party-registry
kind: story
status: implemented
title: Keep Identity agnostic of relying parties
summary: Replace compiled downstream policy and discovery with generic deployment-owned registration.
revision: 4
---
## Outcome

Identity registers opaque relying-party audiences and generic scope admission rules without compiling any downstream service, provider, endpoint, or capability vocabulary.

## Acceptance

- The audience registry v2 represents allowed scopes and optional group expansions as bounded deployment data; no product-specific policy enum or hardcoded scope exists.
- Identity discovery publishes only Identity endpoints and client registration metadata.
- Identity source and public client types contain no downstream service endpoint field.
- Relying parties still receive exact-audience, short-lived, verifier-only opaque authority with tenant, subject, actor, groups, and canonical admitted scopes.
- A v1 registry is rejected so an old product-specific policy cannot silently survive.
- Documentation states that audience and scope bytes are opaque registration data and authorization semantics belong to the relying party.

## Out of Scope

Provider OAuth, Connector custody, Agent Platform policy, and deployment-specific registrations.
