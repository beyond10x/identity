# Decision 0002: relying-party audiences are deployment-registered

Status: superseded by decision 0004, 2026-09-01.

## Context

Identity originally admitted the Connector, status and Zwirn audiences through constants in the
request handlers. Adding another relying party therefore required editing the identity authority
itself, and a deployment could not show which services it intended to trust. The audience bytes are
wire-visible and must remain exact, but admission is a deployment decision.

## Decision

`IDENTITY_AUDIENCE_REGISTRY_JSON` is required and uses the closed version
`identity.audiences/1`. It separately registers session-authority audiences and access-token
audiences. Every access-token audience selects one server-owned policy; version 1 exposes only the
existing Connector policy, so configuration cannot invent scopes or grants.

The registry rejects unknown fields, versions and policies, malformed or duplicate identifiers and
an empty document. Its canonical sorted contents contribute to the session configuration
generation. A rollout that changes the registry consequently requires every person to authenticate
again.

Directory and profile audiences remain route-owned because they are not extensible relying-party
seams. Adding or changing a wire-visible audience still requires a coordinated migration in Atlas
and matching released clients before the deployment admits it.

## Consequences

- Identity no longer needs a code change for every new session-authority consumer.
- A deployment declares its complete relying-party set in one reviewable value.
- Existing audience bytes and Connector scope behavior remain unchanged.
- Configuration changes deliberately invalidate sessions rather than silently widening them.
