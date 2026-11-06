# HERMES ENTITY54

Role-based authorization for Hermes Agent, built as an Agent Plugins 1.0.0
plugin. ENTITY54 decides what a principal may do, writes a tamper-evident
receipt for every decision, governs Linear issue creation, and syncs
versioned policy between profiles without ever syncing credentials.

Product name: HERMES ENTITY54. This plugin is the submission for the
November 11, 2026 Hermes Agent hackathon. It is a standalone authorization
layer. It is not the AGENTROPOLIS security authority (54-T) and it does not
replace AEGIS permission decisions. It enforces the policy a profile owner
writes, nothing more.

## What it does

- **Authorization.** Four roles: OWNER, ADMIN, USER, GUEST. Default-deny.
  Per-tool and per-bot scoping. Unknown tools fail closed. A principal
  cannot claim a different identity or a higher role by asking for one.
- **Receipts.** Every decision, allowed or denied, is appended to a JSONL
  log with a SHA-256 hash chain and an HMAC per entry. Tampering with any
  entry breaks verification at that sequence number.
- **Linear.** Issue creation runs only after authorization, with the
  approved arguments. Denied requests never reach Linear. A mock transport
  exists for demos and tests; it is labelled mock in every receipt.
- **Policy sync.** Versioned policy documents with HMAC-SHA256 integrity.
  Import stages a policy; it never activates on import. Activation is a
  separate OWNER-only step. Equal or lower versions are rejected as replay
  or downgrade. No credential or secret is ever part of a policy document.
- **Event feed.** Optional, disabled by default, read-only. Sanitized
  events only: no prompts, no arguments, no message content, no titles,
  no tokens, no credentials. Identities appear as short HMAC pseudonyms.
  GUEST viewers see only their own events.

## Trust model

Read this before installing. The server runs inside one Hermes profile over
stdio. It does not re-authenticate the Telegram user. The Hermes gateway
asserts the caller identity (`ENTITY54_PRINCIPAL_ID`) and the bot scope
(`ENTITY54_BOT_ID`) in the environment when it spawns the server. ENTITY54
authorizes the asserted principal against the principal store and the
versioned policy. If the claimed principal or bot in a tool call does not
equal the asserted one, the call is denied as spoofing. If the gateway
asserts a wrong identity, ENTITY54 cannot detect it, because it has no
independent identity source. That boundary is documented in
`docs/SECURITY-GATE-REPORT.md`.

The policy key (`ENTITY54_POLICY_KEY`) signs policies and receipts. Anyone
holding it can sign a new policy. Guard it like a credential, because it
is one. It lives only in the profile environment, never in this repo.

## Install

Requires Node 22 or newer and a Hermes Agent install that supports Agent
Plugins 1.0.0.

```sh
hermes plugins install AGENTROPOLIS-CITY-OF-AGENTS/AGENTROPOLIS-HERMES-ENTITY-54 --enable
```

Then install the server dependencies once, inside the installed plugin
directory:

```sh
cd <hermes-plugins-dir>/hermes-entity54/server
npm ci --omit=dev
```

The compiled server (`server/dist/`) is committed, so no build step is
needed for install. To rebuild from source: `npm run build`.

## Configure

Run the setup script once, from the server directory. It generates the
operator keys, signs the example policy, and writes the profile data
directory plus an env file.

```sh
node scripts/setup.mjs --data-dir ./data --owner tg:YOUR_TELEGRAM_ID --bot bot-main
```

Copy the generated `.env.entity54` values into the Hermes profile
environment (the profile `.env`). Never commit that file. The variables:

| Variable | Required | What it is |
| --- | --- | --- |
| `ENTITY54_DATA_DIR` | yes | Profile data dir: policy, principals, receipts, events |
| `ENTITY54_PRINCIPAL_ID` | yes | Gateway-asserted caller principal, for example `tg:123456789` |
| `ENTITY54_BOT_ID` | yes | Gateway-asserted bot id, for example `bot-main` |
| `ENTITY54_POLICY_KEY` | yes | HMAC key for policy and receipt integrity |
| `ENTITY54_PSEUDONYM_KEY` | no | HMAC key for event-feed pseudonyms (separate from the policy key) |
| `ENTITY54_EVENTS_ENABLED` | no | `true` to enable the event feed. Default `false` |
| `ENTITY54_LINEAR_TRANSPORT` | no | `live` (default) or `mock` |
| `LINEAR_API_KEY` | no | Linear API key. Absent means Linear calls fail closed as not configured |
| `ENTITY54_EXEC_TIMEOUT_MS` | no | Linear call timeout in ms. Default `10000` |

Edit the principals file (`entity54.principals.json`) to list the real
principals and their bots. Edit the policy by signing a new versioned
document and importing it through `entity54_policy_import`, then activating
it with `entity54_policy_activate` as OWNER. See `docs/COVERAGE.md` for the
rule model.

## Tools

| Tool | What it does |
| --- | --- |
| `entity54_authorize` | Preview a decision for a principal, bot, and tool. Still receipted |
| `entity54_linear_create_issue` | Create a Linear issue after authorization. Denied first, executed never |
| `entity54_policy_export` | Return the active policy document |
| `entity54_policy_import` | Verify and stage a newer signed policy. Never activates |
| `entity54_policy_activate` | OWNER only. Activate the staged policy |
| `entity54_receipts_verify` | Recompute the receipt hash chain and report ok or the first bad sequence |
| `entity54_events_list` | Paginated sanitized events, viewer-scoped. Disabled by default |
| `entity54_status` | Policy version, pending version, receipt count, Linear configuration |

The skill `skills/entity54-authorization/SKILL.md` tells the agent how to
use these tools and what it must never do: never claim another principal,
never treat conversation words as a role, never work around a denial.

## Policy model

Rules are evaluated in file order. The first matching rule wins. No
matching rule means deny.

- ALLOW rules inherit upward: a rule written for USER also matches ADMIN
  and OWNER.
- DENY rules match exactly: a rule written for ADMIN denies ADMIN only,
  never OWNER.
- A rule can constrain a call: for example the example policy allows USER
  to create Linear issues only with `team` equal to `ENG`.
- A tool name the server does not know fails closed before any rule is
  consulted, even for OWNER and even when a rule uses a wildcard. Adding a
  new governed tool requires adding it to `KNOWN_TOOLS` in
  `server/src/policy.ts` and adding a policy rule for it.

## Receipts and events

Receipts live in `receipts.jsonl` in the data directory. Each entry has a
sequence number, the previous entry hash, its own SHA-256 hash, and an
HMAC. Run `entity54_receipts_verify` to check the chain. Deleting or
editing any entry breaks verification at the affected sequence.

Events live in `events.jsonl`. They are capped at 1000 entries, oldest
dropped, and paginated at most 100 per page. They contain no raw content
and no raw identities. A GUEST sees only events carrying their own
pseudonym. USER and ADMIN see events inside their bot scope. OWNER sees
all events.

## Development

```sh
cd server
npm ci
npm run build     # typecheck and compile to dist/
npm test          # 48 tests, Node built-in runner, no test framework
npm run demo      # reproducible demo: denied operation, authorized operation, receipts
node demo/run-demo.mjs --paced   # same demo, paced for screen recording (about 70s)
```

## Limitations, stated plainly

- Agent Plugins 1.0.0 defines no dashboard-route API for plugins. The
  event feed is delivered as authenticated MCP tools plus a JSON export,
  not as a dashboard route. See `docs/COVERAGE.md`.
- Hermes plugin hooks (pre_llm_call, post_compaction) are Hermes-specific
  and are not an authorization enforcement boundary. ENTITY54 enforces
  inside its own tools: nothing governed executes without passing the
  gate in this server. A caller that bypasses this server and calls
  another tool directly is outside ENTITY54's enforcement.
- Telegram isolation is enforced at the authorizer: bot scope in the
  principal store plus the gateway-asserted bot id. A live two-bot
  Telegram end-to-end test was not run. It needs real Telegram bots and a
  Hermes instance. See `docs/SECURITY-GATE-REPORT.md`.
- All security results in this repo are self-tested by the author unless
  labelled otherwise. Independent reproduction by GROKBOT is pending and
  is required before any production claim.

## License

Apache License 2.0. See the repository LICENSE file.
