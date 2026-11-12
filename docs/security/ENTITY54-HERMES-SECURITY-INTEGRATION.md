# ENTITY54 / Hermes Security integration contract (draft)

ENTITY54 owns persistent identity resolution, ownership, runtime bindings, scoped delegations and revocation checks. AGENT-ENTITY continuity does not imply inherited authorization.

## Proposed request envelope
- request_id, subject_entity_id, owner_id, runtime_id, profile_id
- action, resource, purpose, nonce, issued_at, expires_at
- delegation_chain, requested_capabilities, policy_version
- integrity_proof and evidence references (never raw secrets)

## Required behavior
- Deny unknown, expired, revoked, mismatched-profile or replayed requests.
- Verify runtime binding at each privileged operation, including storage and plugin access.
- Hermes Security findings are untrusted advisory signals, never authorization.
- Deny if 54-T, AEGIS or the final execution gate cannot be reached.
- Keep separate denied and approved decision receipts.
- No cross-profile credential, environment or storage inheritance.

## Acceptance tests
Unknown identity DENY; revoked delegation DENY; replay DENY; cross-profile DENY; changed runtime DENY; security-signal SAFE without authority DENY; authorized operation only when all gates pass.

Status: design proposal; source implementation, actual plugin interfaces and tests not yet verified. No live integration or credential changes.