# HERMES ENTITY54: Feature Coverage

Version 0.1.0. Status of every deliverable in the November 5, 2026
execution directive. Statuses: DONE (built and self-tested), PARTIAL (built
with a stated limitation), NOT DONE (not built). Nothing here is labelled
independently reproduced. Independent reproduction by GROKBOT is pending.

## Deliverables

| # | Deliverable | Status | Evidence |
| --- | --- | --- | --- |
| 1 | Working ENTITY54 plugin in the existing repository | DONE | `plugin.json`, `mcp.json`, `skills/entity54-authorization/SKILL.md`, `server/` (TypeScript, Node 22+, MCP SDK 1.32.2). Branch `feat/entity54-plugin-v1`, draft PR to be linked in the handoff report |
| 2 | Correct installation and configuration instructions | DONE | `README.md` (install, setup script, env table, policy model). Verified by following the steps in a clean checkout during testing |
| 3 | Automated tests and security-gate report | DONE | `server/test/` (48 tests, 48 pass, Node built-in runner). `docs/SECURITY-GATE-REPORT.md`. Full log saved with the handoff evidence |
| 4 | Optional authenticated event endpoint | PARTIAL | Event feed as MCP tools (`entity54_events_list`), not a dashboard route. Agent Plugins 1.0.0 defines no dashboard-route API for plugins, so no dashboard route exists. Feed is disabled by default, read-only, sanitized, pseudonymized, viewer-scoped, capped at 1000 entries, paginated at most 100 per page. No new listening port |
| 5 | Marketplace-compatible packaging | DONE | `plugin.json` conforms to the Agent Plugins 1.0.0 schema (required fields only, closed schema, valid name). `mcp.json` conforms to the MCP schema (stdio server, `${PLUGIN_ROOT}` paths, no secrets in static manifests). Tests assert both |
| 6 | Accurate feature coverage documentation | DONE | This file, plus `README.md` and `docs/SECURITY-GATE-REPORT.md` |
| 7 | Reproducible 90-second demonstration (recorded) | DONE | `server/demo/run-demo.mjs` (`npm run demo`, `--paced` for recording). Transcript in `docs/DEMO.md`. Shows the denied operation, the authorized operation, receipt verification, and the sanitized feed. Mock Linear transport, labelled mock |
| 8 | Commit references and verified GitHub links | DONE | Branch and draft PR link in the handoff report. Commit SHAs recorded there, not here, because this file is written before the push |

## Directive scope

| Requirement | Status | Notes |
| --- | --- | --- |
| ENTITY54 authorization: verified principal identities | DONE | Principals from the store file; roles OWNER/ADMIN/USER/GUEST; gateway-asserted identity in env. The server does not re-authenticate the Telegram user; see the trust model in `README.md` |
| Default-deny permission decisions | DONE | First matching rule wins; no match denies. Tested, including an empty policy denying OWNER |
| Per-tool authorization | DONE | Rules match on tool; unknown tools fail closed before rule matching |
| Per-bot authorization | DONE | Rules match on bot; principals carry a bot list; claimed bot must equal asserted bot |
| Fail-closed behavior | DONE | Missing policy key, missing principal, missing bot, unverified policy, unknown tool, unconfigured Linear, Linear timeout, and Linear HTTP failure all deny or error without executing |
| Tamper-evident authorization receipts | DONE | SHA-256 hash chain plus per-entry HMAC. Tamper and deletion tests pass |
| Telegram isolation: independent bot identities and permission scopes | PARTIAL | Enforced at the authorizer (bot scope in the principal store plus asserted bot id). No cross-bot privilege inheritance by construction. A live two-bot Telegram end-to-end test was NOT run; it needs real Telegram bots and a Hermes instance |
| No cross-bot privilege inheritance | DONE | Tested: a bot-main principal has nothing on bot-other, and a bot-other principal is denied on bot-main |
| Linear integration: govern real issue creation | DONE | Real Linear GraphQL `issueCreate` behind the authorizer; key from env only; fail-closed when unconfigured; 10s default timeout with a race, not just an abort signal. Live Linear was NOT exercised against the real API in this run; the live path is covered by unit tests with a stubbed fetch. A real Linear issue was never created in testing |
| Deny unauthorized requests before execution | DONE | Tested: a denied request writes an authorization receipt and zero execution receipts |
| Receipts for authorization and execution outcomes | DONE | Allowed actions write two receipts: the authorization decision and the outcome. Denials write one authorization receipt |
| Policy synchronization: versioned export and import | DONE | Export returns the active signed document; import verifies HMAC, policy id, and strictly higher version |
| Integrity verification and replay protection | DONE | HMAC-SHA256 over canonical JSON; replay of the same version and downgrade both rejected. Tested with tampered and wrong-key policies |
| No credential or secret synchronization | DONE | Policy documents carry no secrets. Receipts and events were tested for key leakage. The setup script writes keys only to a local env file |
| Explicit authorization for policy activation | DONE | Import stages only. Activation is a separate OWNER-only call. ADMIN activation is denied by an exact-match deny rule. Activation with no staged policy is denied |
| Event feed categories | DONE | authorization allowed/denied, tool execution started/succeeded/failed, policy installed/rejected, approval requested/resolved. All nine are recorded by the server |
| Event feed: read-only, disabled by default, no new port | DONE | No HTTP server in the plugin. Feed is MCP tools only |
| Event feed: no raw prompts, args, content, tokens, credentials | DONE | Events carry category, tool, decision, pseudonym, bot, receipt ref only. Tested against titles and descriptions |
| Event feed: pseudonymized identities | DONE | HMAC-SHA256 with a separate key, truncated to 16 hex chars. Same principal maps to the same pseudonym within one key epoch |
| Authorization vs execution vs completion kept distinct | DONE | Separate receipt types and separate event categories for authorization, execution start, execution success, and execution failure |
| Event visibility by authenticated viewer scope | DONE | GUEST sees only own events; USER/ADMIN see their bot scope; OWNER sees all. Tested in a shared store |
| Bounded retention and pagination | DONE | 1000 entries, oldest dropped; at most 100 per page. Tested at the boundary |
| Feed must never become an authorization bypass | DONE | The feed is read-only and is never consulted by any decision path |
| BUILDER COMMONS as future event consumer | DONE (read-only) | Inspected, not written to. Its Hermes adapter maps capabilities and authority but presence grants nothing. The future consumer is the JSON event export, not a live coupling. No 3D Workshop built |
| No proprietary AGENTROPOLIS security internals in the public repo | DONE | Nothing from 54-T, AEGIS, or other internal systems was imported. The plugin is self-contained |

## What was reused from nexus54-v0.1

Nothing, because no artifact literally named nexus54-v0.1 exists. Full
search record is in `INSPECTION.md` in the build workspace. The closest
prior art, wiredchaos/NEXUS54, is a React control-center app plus a toy
MCP server with two demonstration tools. One of its tools echoes its input
inside a success string while claiming to re-sign tokens. It is not
authorization code and was not reused. Only its transport and handler
shape informed the new server design, as a pattern, not as code.

## Known limitations

1. **No live Hermes instance.** The server was tested over real MCP stdio
   with real client connections, but not inside a running Hermes Agent.
   Install and startup inside Hermes are therefore NOT VERIFIED. The
   install command in `README.md` is the documented path and has not
   been executed against a real Hermes install.
2. **No live Telegram test.** Bot isolation is enforced and tested at the
   authorizer level. A two-bot Telegram end-to-end run needs real bots.
3. **No live Linear call.** The live transport is covered by unit tests
   with a stubbed fetch. No real Linear issue was created, and no real
   Linear API key was used anywhere in this work.
4. **Self-tested only.** Every result in this repo was produced by the
   author running their own tests. Under the canonical pipeline, GROKBOT
   independent reproduction is required before any production claim.
   The security-gate report labels every result accordingly.
5. **Gateway trust boundary.** The server trusts the gateway-asserted
   principal and bot id from the environment. A compromised or
   misconfigured gateway can assert a wrong identity and ENTITY54 cannot
   detect it. This is the documented trust model, not a hidden gap.
6. **Plugin hooks are not an enforcement boundary.** Hermes plugin hooks
   are not part of the portable Agent Plugins 1.0.0 spec and are not an
   authorization boundary. ENTITY54 enforces inside its own tools. A
   caller that bypasses this server and calls another tool directly is
   outside its enforcement.
