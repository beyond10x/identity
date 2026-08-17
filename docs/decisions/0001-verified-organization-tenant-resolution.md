# Decision 0001: verified organization claims resolve tenants exactly

**Status:** accepted · **Date:** 2026-08-16

## Decision

Hosted Identity resolves `tenant_id` from an exact deployment mapping of a cryptographically
verified upstream organization claim. Mapping happens before authorization-code issuance and
session creation. The stable human identity presented to downstream services is the pair
`(tenant_id, sub)`; immediate actor remains a separate authority fact.

`IDENTITY_ORGANIZATION_TENANTS_JSON` contains exact `claimValue`/`tenantId` pairs. Duplicate,
unknown, ambiguous, absent, or non-string claim values fail closed. Email domains, authorization
request hints, suffix matching, and `IDENTITY_TENANT_ID` are not fallbacks when this mapping is
enabled. The legacy base-domain allowlist is mutually exclusive and retained only for compatible
single-tenant deployments.

The Babelforce developer profile deliberately contains one mapping because the deployment is one
organization, not SaaS. Identity storage and authority envelopes nevertheless retain the resolved
tenant per authorization code, session, access authority, directory record, group assignment, and
profile record. Synthetic tests configure two mappings and prove that two organizations resolve to
distinct tenant/subject identities.

This implements the Identity part of
[Architecture ADR 0041](https://github.com/daemonloom/architecture/blob/main/adr/0041-hosted-domain-modules-require-connector-signed-request-authority.md).
