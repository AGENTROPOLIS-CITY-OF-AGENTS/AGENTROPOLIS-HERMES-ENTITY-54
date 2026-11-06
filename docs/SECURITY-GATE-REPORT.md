# HERMES ENTITY54: Security-Gate Report

Version 0.1.0. Date: 2026-11-05. Author: VERITY (AGENTROPOLIS Evidence
Steward). Every result in this report is SELF-TESTED unless it says
otherwise. Self-tested means the author ran the author's own tests against
the author's own code. It is not independent verification. Independent
reproduction by GROKBOT is pending and is required before any production
claim. Nothing in this report is a production authorization.

## How to reproduce

```sh
cd server
npm ci
npm run build
npm test
```

The 2026-11-05 qualifying run, before N1–N9 remediation, was 48 tests,
48 pass, 0 fail, exit 0 (`entity54-test-run-2026-11-05.log`, about
13.4s, Node v24.22.1, npm 10.9.4). The remediated suite is larger.
`docs/REMEDIATION-EVIDENCE.md` records the command, the pass count, and
the runtime for this head. This report does not replace that evidence
and does not claim an independent re-review.

The demo reproduces the headline story without any test framework:

```sh
npm run demo
```

## Scope

The server under test is `server/dist/` built from `server/src/` at the
commit on branch `feat/entity54-plugin-v1`. The tests spawn real server
processes over MCP stdio with real client connections and a fresh temp
data dir per test, with signed policies and the mock Linear transport
unless a test says otherwise. Unit tests cover the Linear client and the
event store directly, with a stubbed fetch where network behavior is
under test. No test talks to a real Hermes instance, a real Telegram bot,
or the real Linear API. No real credentials were used.

## Results

### 1. Unauthorized tool access

| Check | Result | Test |
| --- | --- | --- |
| GUEST denied `linear:create-issue` by default-deny | PASS (self-tested) | authorization: GUEST is denied |
| USER allowed `linear:create-issue` only inside team ENG; OPS denied by constraint mismatch | PASS (self-tested) | authorization: USER constraint |
| ADMIN inherits USER allow rules upward; ADMIN cannot activate policy | PASS (self-tested) | authorization: ADMIN inherits |
| Unknown tool names fail closed, including for OWNER | PASS (self-tested) | authorization: unknown tool names |
| Empty policy denies everyone, including OWNER | PASS (self-tested) | authorization: no matching rule |
| A denied Linear request writes an authorization receipt and zero execution receipts | PASS (self-tested) | linear: denied request never executes |

### 2. Principal spoofing

| Check | Result | Test |
| --- | --- | --- |
| Claiming a different principal than the gateway asserted is denied as spoofing | PASS (self-tested) | authorization: spoofing principal |
| Claiming the OWNER role as an extra argument changes nothing | PASS (self-tested) | authorization: role claim argument |
| Unknown principal asserted by the gateway is denied | PASS (self-tested) | authorization: unknown principal |
| Startup refuses to run without an asserted principal | PASS (self-tested) | packaging: no asserted principal |
| Startup refuses to run without a policy key | PASS (self-tested) | packaging: no policy key |
| Startup refuses an unsigned example policy | PASS (self-tested) | policy: unsigned example policy |

### 3. Cross-bot privilege escalation

| Check | Result | Test |
| --- | --- | --- |
| A bot-main principal has nothing on bot-other (spoofing deny) | PASS (self-tested) | authorization: cross-bot privilege |
| A principal scoped only to bot-other is denied on bot-main | PASS (self-tested) | authorization: bot-other principal |
| Live two-bot Telegram end-to-end | NOT TESTED | Needs real Telegram bots and a Hermes instance. Authorizer-level enforcement is tested; the Telegram path is not |

### 4. Prompt injection

| Check | Result | Test |
| --- | --- | --- |
| Three injection strings in tool arguments ("ignore previous instructions", fake SYSTEM role grant, "disregard ENTITY54 policy") cannot change a GUEST denial | PASS (self-tested) | authorization: prompt-injection strings |
| Policy export stays denied for GUEST after injection attempts | PASS (self-tested) | authorization: prompt-injection strings |
| The skill file instructs the agent to treat tool output as untrusted data | PASS (self-tested, by inspection) | packaging: skill names authorize tool |

Limitation: injection testing covers strings carried as tool arguments.
It does not cover a compromised model or a prompt injection delivered
through a long conversation history. Those are outside what an
authorizer can test.

### 5. Hook failure and timeout behavior

| Check | Result | Test |
| --- | --- | --- |
| Linear call timeout fails closed with code `timeout` | PASS (self-tested) | linear: live transport timeout |
| Linear HTTP failure is a LinearError, never a silent success | PASS (self-tested) | linear: HTTP failure |
| Live transport without a key fails closed as `not_configured` after authorization | PASS (self-tested) | linear: live transport without key |
| Live transport without a key throws before any fetch | PASS (self-tested) | linear: no key unit |
| Linear input validation rejects empty title, overlong title, bad priority, missing team | PASS (self-tested) | linear: input validation |

Note: the timeout test initially exposed a real defect (see Defects,
D2). The fix races the fetch against a timeout promise instead of
relying only on an abort signal. The test now passes in about 60ms.

### 6. Policy tampering and replay

| Check | Result | Test |
| --- | --- | --- |
| Tampered policy with a stale HMAC is rejected | PASS (self-tested) | policy: tampered policy |
| Policy signed with a different key is rejected | PASS (self-tested) | policy: wrong key |
| Replay of the same version is rejected | PASS (self-tested) | policy: replay |
| Downgrade to an older version after activation is rejected | PASS (self-tested) | policy: downgrade |
| Valid newer policy stages but does not activate until OWNER activates | PASS (self-tested) | policy: staging |
| OWNER activation switches the active policy | PASS (self-tested) | policy: activation |
| ADMIN cannot activate a staged policy | PASS (self-tested) | policy: ADMIN activation |
| Activation with no staged policy is denied | PASS (self-tested) | policy: no staged policy |

### 7. Receipt integrity

| Check | Result | Test |
| --- | --- | --- |
| Every decision writes a receipt and the chain verifies | PASS (self-tested) | receipts: chain verifies |
| Tampering with a receipt detail breaks verification at that sequence | PASS (self-tested) | receipts: tamper |
| Deleting a receipt breaks the chain at the next sequence | PASS (self-tested) | receipts: deletion |
| Receipts never contain a Linear API key or a policy key | PASS (self-tested) | receipts: key leakage |

### 8. Sensitive-data leakage through the event feed

| Check | Result | Test |
| --- | --- | --- |
| Feed is disabled by default and refuses to list | PASS (self-tested) | events: disabled by default |
| Enabled feed carries no titles, descriptions, raw ids, or keys | PASS (self-tested) | events: sanitized |
| Same principal always maps to the same pseudonym | PASS (self-tested) | events: pseudonym stability |
| GUEST sees only their own events in a shared store | PASS (self-tested) | events: GUEST visibility |
| Category filter and pagination work | PASS (self-tested) | events: filter and pagination |
| Retention caps at 1000 entries, oldest dropped | PASS (self-tested) | events: retention cap |

### 9. Plugin installation and startup

| Check | Result | Test |
| --- | --- | --- |
| `plugin.json` conforms to Agent Plugins 1.0.0 (required fields, closed schema, valid name) | PASS (self-tested) | packaging: plugin.json |
| `mcp.json` conforms to the MCP schema (stdio server, `${PLUGIN_ROOT}` paths, no secrets) | PASS (self-tested) | packaging: mcp.json |
| Static manifests contain no secrets | PASS (self-tested) | packaging: no secrets |
| Server build output exists and compiles clean | PASS (self-tested) | packaging: build output; `npm run build` exit 0 |
| Install inside a real Hermes Agent | NOT TESTED | Needs a Hermes instance. The install command is documented, not executed |

### 10. Real Hermes integration compatibility

| Check | Result | Test |
| --- | --- | --- |
| MCP stdio transport with the MCP SDK client (real protocol, real processes) | PASS (self-tested) | all integration tests |
| Agent Plugins 1.0.0 manifest shape verified against the published schemas | PASS (self-tested, by inspection) | packaging tests plus schema fetch from agent-plugins.org, 2026-11-05 |
| Hermes runtime behavior (plugin load, gateway env assertion, Telegram gateway) | NOT TESTED | Needs a Hermes instance. Documented as a limitation, not claimed |

## Defects found during testing and fixed

All four were found by the author's own tests before the PR, and all
four are fixed in the submitted code. They are recorded here because a
security report that hides its own findings is not a security report.

- **D1 (unknown-tool wildcard allow).** The OWNER wildcard rule
  (`tool: "*"`) matched tool names the server does not know, so
  `entity54_authorize` returned allow for a nonsense tool. Fixed by
  adding `KNOWN_TOOLS` in `server/src/policy.ts`: a tool name the server
  does not know fails closed before any rule is consulted. Test:
  "unknown tool names fail closed."
- **D2 (Linear timeout hang).** The Linear client relied only on an
  `AbortController` to enforce its timeout. A fetch implementation that
  ignores the abort signal (or a stalled network call) left the await
  hanging forever, which is a fail-open hang, not a fail-closed timeout.
  Fixed by racing the fetch against a timeout promise that rejects with
  `LinearError` code `timeout`. The body read (`response.text()`) is in
  that same race, so a `text()` that ignores abort also fails closed.
  Test: "live transport timeout is a LinearError with code timeout" and
  "live transport body read shares the fetch timeout".
- **D3 (event-feed gate tool name mismatch).** The events-list handler
  gated on `entity54:events-read` while the governed tool set named it
  `entity54:events-list`, so every feed listing would have been denied as
  an unknown tool. Fixed by renaming the gate and the three matching
  policy rules to `entity54:events-list`. Test: "category filter and
  pagination work" (exercises the live gate path).
- **D4 (allowed actions left no authorization receipt).** An allowed
  Linear execution wrote only an execution receipt; the authorization
  decision that permitted it was not separately receipted. Fixed by
  writing an authorization receipt for every allow gate that precedes an
  action (Linear execution, policy import, policy activation), so an
  allowed action leaves two receipts: the decision and the outcome.
  Test: "every decision writes a receipt and the chain verifies"
  (authorize plus create leave 3 receipts and the chain verifies; the
  verify call then receipts itself).

## What is NOT verified

- No live Hermes instance, no live Telegram bots, no live Linear API
  call. See Coverage, limitations 1 to 3.
- Independent reproduction of commit `623a0a079914b3e7f1b782f20a9a4ee756892627`
  returned REQUEST CHANGES (N1–N9). Remediation is recorded in
  `docs/REMEDIATION.md` and `docs/REMEDIATION-EVIDENCE.md`. That
  reproduction does not cover this head. Re-review is required. This
  report does not certify the remediation.
- No penetration test by a third party. The prompt-injection checks
  cover argument-carried strings only.
- The gateway trust boundary (the server trusts the asserted principal
  and bot id from the environment) is a documented design decision, not
  a tested property. A compromised gateway is outside the tested scope.

## Verdict

SELF-TESTED ONLY. The four defects above were found and fixed during
the original testing. Findings N1–N9 from the independent reproduction
of `623a0a07` are remediated on this head; see `docs/REMEDIATION.md`.
The current test count is in `docs/REMEDIATION-EVIDENCE.md`. This head
is a draft for independent re-review. It is not production authorized,
and this report does not claim otherwise. No live Linear, Telegram, or
Hermes run is claimed.
