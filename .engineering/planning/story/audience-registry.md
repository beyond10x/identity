---
format: aep.planning-md/1
id: story:audience-registry
kind: story
status: implemented
title: Configure the relying-party audience registry
summary: M2 moves downstream audience admission from constants into a validated versioned deployment registry.
revision: 5
---
## Outcome

An operator registers new relying-party audiences through validated deployment configuration
instead of a code change or another hardcoded constant.

## Context

This is Identity milestone M2 and must precede the Devcenter session story. Existing session and
access-token audiences are wire-visible and remain byte-identical; the registry changes admission,
not vocabulary.

## Acceptance

- A versioned JSON registry configures exact session audiences and exact access-token audience
  policies, rejecting unknown versions, duplicate audiences, malformed identifiers and unknown
  policies.
- Existing status, Zwirn and Connectors behavior is represented through configuration and covered
  by compatibility tests.
- Devcenter and Agent Platform are added only as deployment configuration, never constants.
- The registry contributes deterministically to the authority configuration generation so changing
  it invalidates existing sessions.
- Documentation and tests cover valid, missing, duplicate, malformed and wrong-audience cases.

## Out of Scope

Changing any existing audience byte, adding JWTs, or moving relying-party authorization decisions
into Identity.

## Implementation record — 2026-09-01

Identity 0.2.0 replaces hardcoded extensible relying-party audiences with a closed, versioned deployment registry. The canonical registry contributes to session generation; malformed, duplicate, unregistered, cross-class and unknown-policy entries fail closed. The workspace now ships an Identity-owned credential-safe Rust client for login discovery, code exchange and exact-audience session resolution. The repository gate passed in both production and loopback-development feature postures, including 54 tests, clippy, formatting, local-login refusal, dependency audit and secret scan. The release image also builds from the multi-crate workspace.
