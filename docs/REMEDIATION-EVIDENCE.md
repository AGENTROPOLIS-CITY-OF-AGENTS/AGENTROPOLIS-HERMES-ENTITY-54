# ENTITY54 remediation evidence

Immutable record of the N1–N9 remediation. This file is evidence of what
this agent ran. It is not an independent review, not a merge approval,
and not a live-system verification.

Independent re-review is required. The implementing agent cannot
self-certify. Role for that re-review: APEX54 / VERITY, or another
reviewer who did not write this change. Re-review this head. The
reviewed parent `623a0a079914b3e7f1b782f20a9a4ee756892627` stays in
history and was not amended, rewritten, or force-pushed.

No live Linear API call. No live Telegram. No live Hermes. No BUILDER
COMMONS check. No deploy. Draft only.

## Identity

| Item | Value |
| --- | --- |
| Repository | AGENTROPOLIS-HERMES-ENTITY-54 |
| Reviewed parent | `623a0a079914b3e7f1b782f20a9a4ee756892627` |
| Branch | `fix/entity54-n1-n9-remediation` |
| Base for the new draft PR | `feat/entity54-plugin-v1` |
| Remediation commit | `COMMIT_SHA_HERE` |
| Evidence commit | The child of the remediation commit. `git rev-parse HEAD` on this branch after both commits is the re-review target. The pull request body records that head. |
| Reproduction report SHA-256 | `c5b8e5fd58c6b74f819c54f8633a4d710be55aad88630344c0d97c9445af1292` (the attached report; not modified, not committed) |
| Prior verdict | REQUEST CHANGES against the parent above |

## Dispositions

| ID | Disposition |
| --- | --- |
| N1 | FIX |
| N2 | FIX |
| N3 | FIX, with the failed-verify no-append exception in `docs/REMEDIATION.md` |
| N4 | FIX |
| N5 | FIX |
| N6 | FIX |
| N7 | FIX (reject `version <= pending`) plus the design note in `docs/REMEDIATION.md` |
| N8 | FIX |
| N9 | FIX |

Nothing in N1–N9 was deferred.

## Files changed

- `server/src/config.ts`, `server/src/events.ts`, `server/src/index.ts`, `server/src/linear.ts`, `server/src/policy.ts`, `server/src/receipts.ts`
- `server/dist/config.js`, `server/dist/events.js`, `server/dist/index.js`, `server/dist/linear.js`, `server/dist/policy.js`, `server/dist/receipts.js` (rebuilt; `authz` and `crypto` outputs unchanged)
- `server/test/events.test.mjs`, `server/test/linear.test.mjs`, `server/test/policy.test.mjs`, `server/test/receipts.test.mjs`
- `server/scripts/setup.mjs` (comment that the pseudonym key is required when the feed is enabled)
- `README.md`
- `docs/COVERAGE.md`, `docs/DEMO.md`, `docs/SECURITY-GATE-REPORT.md`, `docs/REMEDIATION.md`, `docs/REMEDIATION-EVIDENCE.md`
- `skills/entity54-authorization/SKILL.md`

## Commands and results

Working directory `server/` unless noted. This run's toolchain is Node
v22.23.4 and npm 10.9.9. The original reproduction used Node v24.22.1
and npm 11.21.1. `package.json` allows Node `>=22`. This is not a claim
that the v24 environment was re-used.

| Command | Exit | Result |
| --- | --- | --- |
| `npm ci` | 0 | 98 packages added, 99 audited, 0 vulnerabilities |
| `npm run build` (`tsc`) | 0 | no diagnostics |
| `npm test` (`node --test test/*.test.mjs`) | 0 | tests 64, pass 64, fail 0, cancelled 0, skipped 0, todo 0, duration_ms 2896.895097 |
| `npm run demo` | 0 | mock transport. Decisions for steps 1–3 match the reviewed transcript. `mock-issue-1`. Verify `ok: true`, `checked: 4`, `receiptSeq: 5`. Feed `total: 6`. Disk receipts #1–#6. Pseudonyms `9f1db3f3006b41b0` (GUEST) and `f6c1946f021d7445` (OWNER), same as the reproduction's keyed demo. |

`package.json` scripts are `build`, `demo`, `setup`, `start`, and `test`.
There is no separate security-gate script. `setup` writes fresh keys into
a data directory and was not run. `start` is the server process and was
exercised through the test harness, not as a live Hermes install.

Pre-remediation self-test at the parent was 48 pass / 0 fail. That count
is unchanged as a historical fact. This head is 64 pass / 0 fail.

### Tests added for the findings

- N1: `GUEST sees no events when the pseudonym key is unset (P5b)`; `with a pseudonym key, a GUEST sees only their own events`; `enabling the event feed without a pseudonym key is refused`; `startup refuses ENTITY54_EVENTS_ENABLED=true without ENTITY54_PSEUDONYM_KEY`
- N2: `an intact receipt chain passes verification against its anchor`; `deleting the last receipt fails verification`; `emptying the receipt log fails verification when an anchor exists`; `deleting a middle receipt still fails verification`; `a tampered receipt anchor fails verification`
- N3: `allowed export, status, verify, and a disabled event list are receipted`
- N4: `an unexposed MCP tool name is denied and receipted`
- N5: `live transport body read shares the fetch timeout`
- N6: `outer-catch denials record the gateway-asserted identity and the claimed identity separately`; `invalid Linear input after an allow is an execution failure with the caller role`
- N7: `a staged policy cannot be replaced by an equal or lower version`
- N8: `events_list echoes the clamped limit and offset`
- N9: comment-only in `server/src/events.ts` (covered by the existing visibility tests plus the keyed GUEST test)

`npm test` summary from this run:

```
# tests 64
# suites 0
# pass 64
# fail 0
# cancelled 0
# skipped 0
# todo 0
# duration_ms 2896.895097
```

Local log SHA-256 (not committed; re-run to reproduce): `6f373b4dafd572c99fc47034a36bc44ae3c2b79b200cdccfc894ff4af2daee58` for the TAP log and `c6eaf37ddfc1a5e4d160c6770d18b6e9e0527bf21e21869991291bc2e39337b0` for the demo log.

## SHA-256 of committed artifacts at the time of the test run

```
af3904d095528fc91677bbb1711c3249afcb8bc161e6c6103cc03c84c45f39e6  server/src/config.ts
57f5bc384878f0b95491df85e40ba3ea7b1617421c144ce96613579a0908c0b1  server/src/events.ts
cbdb6e548879e34105ad48c739fc4157ff925b170fa493766c267efb20d6b333  server/src/index.ts
0ede13b5abcbb06443ce5c1b1d3664f956cd4d64c68b126c0d71d1d4c0899ea7  server/src/linear.ts
54e9c8032007a71dee08635e9a53bbdb12928f7966c3f149ce4441193e5970f5  server/src/policy.ts
779223dc3dedaca7585fef0d67f5dd71b6281cafad7ba798a4c7c8c348e8f625  server/src/receipts.ts
627c1fa745aac2a73c18cc7303eab235b4c3c5f76309205eef0e752a96c34ce6  server/src/authz.ts
2acc96b63fe778edd2cee0a2febfe0adde500e45828812a691dca883fc94251d  server/src/crypto.ts
e48107a282e6dc523f6e7552ef1e8459782f1bf1fb9d764aabdb8e9baae822f4  server/dist/config.js
c61092cfa784509ccf1bc489df240f7114bbcb203a26e57f8ec1eaebeca4db3f  server/dist/events.js
5cd2e43433b6939e77d91021b4a8b0442d9a56edcb421651484f4fed9970b088  server/dist/index.js
fb3bf2c1b325338dc3287bc74ee1fa26ede70ae12355ccf81e7c1f4063e08ecd  server/dist/linear.js
f0dde6f75a9f36264a17cd675495169cc28409b4414abad65606517352ddfdfc  server/dist/policy.js
8b089f5db2bfcda4d2f180549578e9a9edc06d4fb0553d17b2ad75e086b1390e  server/dist/receipts.js
57db8534d3e4552066e57a2b953dd2f84e9dab87aa1983359908a6b23a83d1c7  server/dist/authz.js
b4bf847a251603d6ff37ee6f726beca89b83aa585868ec781fd81d87230d958f  server/dist/crypto.js
13af2997321b66c21cbb3c52e60eb89b5a089f97b4393c5b2d9840f8cc529ae9  server/test/events.test.mjs
7d9852910b0b819b3528cb136aa4ad2d0ddc68b8c2a6aed7617db4b1b08a442d  server/test/linear.test.mjs
fcc69ba51b7dfff405806ef3e81b36633b15898df44f0cec407b67dbc31f0c83  server/test/policy.test.mjs
3eab8d701bdfcf21b890f43574a72817b85807cdda4a1184a6f65990d23d87c2  server/test/receipts.test.mjs
```

`npm run build` was run before the tests. The committed `server/dist/*.js` files are that build. A reviewer should rebuild and diff `dist/` before trusting DIST_MATCH.

## Remaining blockers

- Independent re-review of this head has not been done. This packet does not replace it.
- Live Hermes install, two-bot Telegram, live Linear, CI, and BUILDER COMMONS remain unverified. `.github/workflows/entity54-ci.yml` is still absent.
- Deleting both the receipt log and the anchor is indistinguishable from a fresh store.
- The gateway-asserted identity is still trusted. This server does not re-authenticate Telegram.
- PR #1 stays a HOLD draft. This work does not merge it and does not mark it ready.

## Explicit non-claims

- No live Linear issue was created.
- No live Telegram bot was contacted.
- No live Hermes process was installed or started.
- No BUILDER COMMONS verification was performed.
- 54T remains the sole capability issuer. This change authorizes Hermes tool behavior inside the plugin only.
