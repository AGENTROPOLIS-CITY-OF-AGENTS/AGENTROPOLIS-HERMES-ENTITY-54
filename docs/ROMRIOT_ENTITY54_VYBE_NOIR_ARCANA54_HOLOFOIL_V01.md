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

## AGENTICtv distribution and creator participation (future extension)
Canonical routing: **short-form plays on VYBE NOIR; long-form plays on AGENTICtv**. ROMRIOT world events and VYBE NOIR branch decisions are inputs to both surfaces. AGENTICtv is the long-form destination for full episodes, films, creator documentaries, and authorized livestreams; VYBE NOIR distributes short episodes, teasers, choice-driven clips, and entry points back to playable worlds.

Proposed lifecycle:
1. HERMES coordinates CREATOR-CORE + ROMRIOT production of a playable world and narrative event log.
2. VYBE NOIR selects an authorized narrative branch and produces short-form discovery content.
3. AGENTICtv publishes the associated long-form story or gameplay program.
4. Opt-in UGC creators remix permitted assets, submit branch proposals, and publish attributed work.
5. KOLs (key opinion leaders) can opt into collaboration invitations based on genuine creator interest, not fake engagement or manufactured endorsement.
6. Verified participation, creator attribution, and viewer choices can inform new story branches and ROMRIOT world events. No automatic posting, unsolicited outreach, or metric manipulation.

### Proposed shared content manifest (NOT implemented)
```json
{
  "schema": "agentropolis.media.world-release.v0.1",
  "world_id": "romriot:demo01",
  "narrative_branch_id": "vybe-noir:branch01",
  "creator_entity_id": "entity54:creator01",
  "source_event_ids": ["romriot:event01"],
  "short_form": {"surface": "vybe-noir", "asset_ref": "creator-core:clip01"},
  "long_form": {"surface": "agentictv", "asset_ref": "creator-core:episode01"},
  "interactive": {"surface": "romriot", "world_ref": "romriot:demo01"},
  "remix_policy_ref": "entity54:policy:ugc01",
  "license_provenance_ref": "creator-core:manifest01",
  "consent_receipt_ref": "entity54:receipt:consent01"
}
```

### Publication and KOL safeguards
- ENTITY54 must enforce rights and current permissions at publication, remix, and external-distribution boundaries; manifests alone do not grant authority.
- Preserve original-asset licenses, music/likeness rights, creator consent, credit, and revocation handling.
- UGC submission and KOL invitations are opt-in and subject to moderation and anti-spam rules.
- Distinguish genuine engagement from automated/bought views; never fabricate KOL participation or endorsements.
- Record published URLs and content hashes only after independent verification.

### Acceptance criteria (future, not November 11 hackathon gate)
- One ROMRIOT world event links to a VYBE NOIR short and an AGENTICtv long-form release through the same world_id and narrative_branch_id.
- A viewer can navigate short -> long -> playable world with traceable attribution.
- A creator without remix permission receives a deny decision at the actual publishing boundary.
- A creator with permission can submit a branch proposal; no automatic canonical publication without review.
- KOL collaboration requires an affirmative opt-in and produces a consent receipt.

AGENTICtv, ARCANA54, HOLOFOIL, and VYBE NOIR integrations remain PROPOSED until source contracts, tests, and runtime behavior are verified. They do not expand the isolated hackathon prototype.
