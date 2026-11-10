# ROMRIOT / ENTITY54 agent-avatar binding — review-only v0.1

Status: PROPOSED. Not implemented, tested, merged, deployed, or authorized for live use.

## Boundary
HERMES orchestrates an isolated hackathon prototype; ENTITY54 owns identity and capability policy; CREATOR-CORE supplies verified licensed GLB/VRM characters, rigs, animations and environments; ROMRIOT owns interactive gameplay; MATH54/POM54 provide measurable game rules; SCIENCE54 tests reproducibility.

Hackathon scope: one actual rigged character, one actual 3D environment, one HERMES-triggered workflow, one capability manifest and a demonstrable deny condition. Do not import or depend on the separate model-agnostic authorization-core remediation branch. No financial or production credentials.

## Future extension (NOT a hackathon dependency)
VYBE NOIR consumes ROMRIOT world events and generates branching Bandersnatch-style narrative nodes, choices, and persistent consequences. ARCANA54 supplies narrative/lore/symbolic rule contracts after interface discovery. HOLOFOIL presents immersive/interactive visual experiences. No implementation/interface for ARCANA54 or HOLOFOIL is presumed verified.

Proposed flow:
HERMES intent -> ENTITY54 request authorization -> CREATOR-CORE asset provenance check -> ROMRIOT playable scene -> signed/attributed event stream -> VYBE NOIR branching narrative -> ARCANA54 lore rules -> HOLOFOIL presentation.

## Proposed binding manifest (NOT enforcement)
```json
{
  "schema": "agentropolis.entity54.avatar-binding.v0.1",
  "world_id": "romriot:demo01",
  "avatar_id": "romriot:avatar01",
  "asset_ref": "creator-core:asset01",
  "asset_license_ref": "manifest:license01",
  "workload_id": "entity54:workload01",
  "capabilities": ["world.navigate", "avatar.animate", "game.interact"],
  "denied": ["payment.execute", "credential.read", "world.admin"],
  "policy_version": "resolve-at-execution",
  "narrative": {"event_schema": "romriot.world-event.v0.1", "future_consumers": ["vybe-noir", "arcana54", "holofoil"]}
}
```

## Execution-time invariants
Manifest entries never confer authority. Fail closed unless current identity, workload, delegation, capability, policy, enforcement boundary, request integrity and freshness all pass. Revocation must be effective without restart. An earlier ALLOW must not authorize a later execution after committed revocation. Preserve strict no-secrets-in-agent-runtime and brokered egress requirements for production.

## Proposed event contract
Each world event includes world_id, actor_id, action, causal_parent_id, event_id, timestamp, policy_decision_receipt_ref, and payload_schema_version. Narrative choices refer to event IDs and branch IDs; consequences are state transitions rather than static scene annotations. Event authenticity, ordering, and persistence remain unimplemented.

## Evidence gates
1. Inventory source and license of each actual asset; no unverified redistribution.
2. Import GLB/VRM character and play one real animation.
3. Load actual environment, collision, player control, objective and win condition.
4. Run one HERMES invocation end to end.
5. Show permitted world.navigate and denied payment.execute; distinguish simulated denial from a real enforcement check.
6. Record exact commit SHA, commands, runtime, observed output, screenshots/recording, and limitations.
7. Keep hackathon and authorization-core branches isolated.
8. Independent review/reproduction and NEURO approval required for merge/deploy.

No merge, deployment, live payment, production credentials, or release gate movement is authorized.
