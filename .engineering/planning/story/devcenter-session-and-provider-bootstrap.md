---
format: aep.planning-md/1
id: story:devcenter-session-and-provider-bootstrap
kind: story
status: draft
title: Issue Devcenter sessions without treating provider credentials as identity
summary: After M2, register Devcenter as a relying party and define a fail-closed provider-bootstrap handoff that ends in an Identity session.
revision: 1
---
## Outcome

An engineer can enter Devcenter through the configured login path, and an optional provider-connect
bootstrap can link a verified person and a Connector-owned credential in one journey without making
the provider credential a Devcenter bearer or a second principal authority.

## Context

Atlas ADR 0015 makes Identity the owner of the Devcenter session and Connectors the owner of
user-bound model credentials. Devcenter 0.1.0 already has a fail-closed verifier port, but Identity
has no registered Devcenter audience or supported bootstrap choreography. Identity's safety envelope
requires M2, the configured audience registry, before any new audience or identity feature; this
story records the work after that gate and must not bypass it.

A provider subscription credential may be useful to Connectors while being unsuitable as proof of a
stable person. The bootstrap must therefore distinguish provider authorization from authentication,
cryptographically verify any provider identity facts it relies on, apply deployment-configured
subject/organization admission, and always terminate in an ordinary Identity session.

## Acceptance

- M2 supplies a configured, versioned Devcenter relying-party audience; no second hardcoded audience
  constant is added.
- Identity and Devcenter share conformance vectors for valid, expired, wrong-audience, wrong-tenant,
  revoked and malformed session authority, with actor and tenant derived only from verified context.
- The generic login configuration contains no deployment brand, email suffix or organization id.
- The optional provider bootstrap has an explicit protocol and threat model: authorization and
  authentication are separate facts, ambiguous/missing identity claims fail closed, and replay or
  partial completion cannot create a session or orphan a credential binding.
- Credential bytes move only into Connector custody and never enter Identity persistence, Identity
  logs, the Devcenter session, URLs or browser-readable application state.
- Revoking the Identity session does not pretend to revoke the provider credential; both lifecycle
  owners and the user-visible state are explicit.
- Generic SSO remains a supported fallback when provider identity is unavailable or insufficient.

## Out of Scope

Implementing provider OAuth, refreshing model credentials, Connector storage, model routing, or
Devcenter's agent-management UI. Those remain with Connectors, the model execution path and
Devcenter respectively.

## Blocker

M2 audience registry and a reviewed cross-service bootstrap contract. No implementation starts by
minting a Devcenter audience directly in the current hardcoded vocabulary.
