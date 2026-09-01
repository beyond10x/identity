# 0003 — Identity owns a product-neutral wire vocabulary

Status: accepted, 2026-09-01.

Identity credentials and resolved authority documents must not expose names inherited from an
earlier product or implementation. Version 0.3.0 therefore makes one deliberate pre-deployment
protocol break:

- session credentials are prefixed `identity_session_v1_`;
- short-lived access credentials are prefixed `identity_access_v1_`;
- token identifiers are prefixed `identity_jti_v1_`; and
- resolved authorities carry `tenant_id` and `principal_kind`.

The corresponding database columns were already named `tenant_id` and `principal_kind`; no schema
migration is required. Credentials are opaque, so clients may transport them but must not parse or
branch on their prefix. The official `identity-client` owns authority decoding and moves in the
same release.

The older vocabulary had not been deployed as part of Devcenter. Compatibility would preserve the
identifier this change removes, so 0.3.0 intentionally does not admit it. All sessions and access
credentials minted by a pre-0.3 binary are invalid after the upgrade.
