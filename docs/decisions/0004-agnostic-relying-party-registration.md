# 0004 — Relying-party registration is opaque deployment data

Status: accepted, 2026-09-01.

Identity owns authentication, tenant and principal facts, exact audience binding, and safe opaque
credential issuance. It does not own a downstream service's endpoint, provider OAuth flow,
capability vocabulary, or operation authorization.

Audience registry v1 violated that boundary by selecting a compiled product-specific policy. It
also exposed a downstream API endpoint in Identity discovery. Version 0.4.0 removes both surfaces
and rejects v1 configuration rather than silently preserving its semantics.

Registry v2 treats audience and scope names as bounded opaque bytes. A deployment registers base
scopes for every authenticated subject and optional exact group-to-scope expansions. Identity
enforces only that closed issuance registration. A relying party verifies the exact audience and
interprets the returned scopes under its own policy before every operation.

This keeps the central login and credential lifecycle uniform without turning Identity into a
platform-service SDK or a catalogue of the services that consume it.
