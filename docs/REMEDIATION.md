# ENTITY54 N1–N9 remediation

This branch remediates the independent reproduction of commit
`623a0a079914b3e7f1b782f20a9a4ee756892627` (draft PR #1 head,
`feat/entity54-plugin-v1`). The reproduction verdict was REQUEST CHANGES.
That report was not edited. The reviewed commit was not amended.

Authority stays where it was. 54T remains the sole capability issuer.
This plugin authorizes Hermes tools only. It is not a production grant,
a merge grant, or a live-system verification.

The implementing agent does not self-certify. APEX54 / VERITY (or another
independent reviewer) must re-review this head. A new head voids the
previous verdict.

No live Linear, Telegram, Hermes, or BUILDER COMMONS call was made.

## Dispositions

| ID | Severity | Disposition | What changed |
| --- | --- | --- | --- |
| N1 | Medium | FIX | Enabled feed without `ENTITY54_PSEUDONYM_KEY` is refused at startup. `entity54_events_list` denies the same configuration. `EventStore.list` returns no events for every role when the key is null, so a shared `"unkeyed"` token cannot match across principals. |
| N2 | Medium | FIX | `receipts.anchor.json` stores `lastSeq` and `lastHash` under a separate HMAC. `verify()` compares the log head to that anchor. Tail deletion, an emptied log with a surviving anchor, a missing anchor on a non-empty log, and a tampered anchor all fail. A reloaded store refuses to append onto a broken anchor. |
| N3 | Low | FIX | Allowed `policy:export`, `entity54:status`, `entity54:receipts-verify`, and `entity54:events-list` write an authorization receipt. The disabled-feed denial writes one too. See the exception below. |
| N4 | Low | FIX | The MCP default branch receipts the deny for an unexposed tool name, with the gateway-asserted caller. |
| N5 | Low | FIX | `response.text()` is raced against the same timeout promise as `fetch`. |
| N6 | Low | FIX | Outer-catch denial receipts store the gateway-asserted principal, role, and bot. Claimed principal and bot are in the detail. `LinearError` from issue validation is an execution failure with the caller role and the Linear error code, not an `internal_error` deny with role `unknown`. `PolicyError` is recorded as `policy_error`. |
| N7 | Info | FIX | Staging must be strictly newer than the active policy and strictly newer than any policy already staged. An ADMIN cannot replace a higher staged version with a lower one. Activation stays OWNER-only. |
| N8 | Info | FIX | `events_list` returns the clamped `limit` and `offset`. |
| N9 | Info | FIX | The `src/events.ts` header now matches the code: USER and ADMIN are bot-scoped; OWNER sees all events. |

## N1 detail

`hashPrincipal` used to return the literal `"unkeyed"` for every principal
when `ENTITY54_PSEUDONYM_KEY` was unset. The GUEST filter compared
`event.principalHash === viewerHash`, so one GUEST saw every event.

Three gates now fail closed:

1. `loadConfig` throws `ConfigError` when `ENTITY54_EVENTS_ENABLED=true`
   and the pseudonym key is empty. `main` exits 2.
2. `eventsFeedDenial` makes `entity54_events_list` deny that configuration
   even if a caller reaches the handler.
3. `EventStore.list` returns `{ events: [], total: 0 }` for GUEST, USER,
   ADMIN, and OWNER when the store has no key.

The feed may stay disabled without a pseudonym key. Decisions can still
be recorded in that mode. Those records use a per-principal `nokey:`
digest, not the shared token `"unkeyed"`, and they are not listed until
a key is configured and the feed is enabled.

Regression tests: `GUEST sees no events when the pseudonym key is unset
(P5b)`, `with a pseudonym key, a GUEST sees only their own events`,
`enabling the event feed without a pseudonym key is refused`, and
`startup refuses ENTITY54_EVENTS_ENABLED=true without ENTITY54_PSEUDONYM_KEY`.

## N2 detail

A hash chain cannot see a missing tail. A prefix still verifies. The
anchor is a second file, `receipts.anchor.json`, written after each
append. Its HMAC covers canonical `{ v: 1, lastSeq, lastHash }` and does
not include the HMAC field. `verify()` walks the chain, then requires
the log head to equal the anchor.

| Case | Result |
| --- | --- |
| Intact chain, anchor matches | `ok: true`, reason `chain intact` |
| Last receipt deleted | `ok: false`, reason starts with `tail truncation` |
| Log emptied, anchor still present | `ok: false`, reason includes `empty` |
| Middle receipt deleted | `ok: false`, `badSeq` is the next remaining sequence (hash mismatch at that sequence; the stored hash was computed with the deleted predecessor) |
| Anchor HMAC edited | `ok: false`, reason `anchor HMAC mismatch` |
| Reloaded store after an emptied log | `verify()` fails and `append()` throws `receipt log failed closed` |

Residual, stated plainly: deleting both `receipts.jsonl` and
`receipts.anchor.json` is indistinguishable from a fresh store.
Rewriting the anchor still requires the policy key. A crash between the
JSONL append and the anchor rename fails closed on the next `verify()`
because the head and the anchor disagree. `receipts_verify` does not
append when `verify()` is already false, so a broken anchor is not
advanced by the verify tool.

## N3 detail and the audited surface

The module header in `server/src/index.ts` now names the surface that
actually writes receipts:

- authorize allow and deny
- Linear authorization, execution success, and execution failure
- policy import and activation, including import rejection and activation
  with nothing staged
- allowed policy export
- allowed status
- allowed receipt verification, only after `verify()` returns ok
- event-feed allow, disabled-feed denial, and unknown-category denial
- unexposed MCP tool names (N4)
- outer-catch denials (N6)

`tools/list` is not a decision and is not receipted. Startup refusal
happens before a store exists and is not receipted.

Exception: a successful `entity54_receipts_verify` writes its allow
receipt after the check, so `checked` is the chain that was verified and
the file gains one receipt afterward. A failed verification does not
append. Appending would move the anchor past the damage.

## N7 design note

Staging compares against the active version only in the reviewed commit.
An ADMIN who can import could replace an OWNER-staged v5 with a signed
v3. That was not privilege escalation: activation stayed OWNER-only, and
the active policy did not change.

The cheap fix is in `stagePolicyImport`. A candidate must be strictly
newer than the active policy and strictly newer than the pending policy
when one exists. Replacing pending upward (v5 then v6) still works.
Equal or lower than pending is rejected. Activation is unchanged and
remains OWNER-only.

## Doc corrections

- `docs/SECURITY-GATE-REPORT.md` now says four defects (D1–D4), not
  "All three".
- The Linear unit test title is `live transport parses a stubbed
  issueCreate response (no network)`.
- `docs/COVERAGE.md` marks "govern real issue creation" as PARTIAL.
  The live path is implemented and covered with a stubbed fetch. No real
  Linear issue was created.
- `docs/DEMO.md` matches the post-remediation mock transcript. Steps 1–3
  are unchanged (`receiptSeq` 1, 2, and 4; `mock-issue-1`). Step 4 still
  checks 4 receipts and then records receipt 5. The feed lists 6 events.
  Disk shows receipts 5 and 6 for the verify allow and the events-list
  allow.
- README receipt and pseudonym-key wording matches the code.

## What this branch does not do

- It does not merge PR #1, mark it ready, or retarget it onto `main`.
- It does not deploy.
- It does not claim live Linear, Telegram, Hermes, CI, or BUILDER COMMONS.
- It does not add `.github/workflows/entity54-ci.yml`. That file was
  absent at the reviewed commit and is still absent.
- It does not treat the gateway-asserted identity as re-authenticated.
  A wrong assertion from the gateway is still outside this server.
