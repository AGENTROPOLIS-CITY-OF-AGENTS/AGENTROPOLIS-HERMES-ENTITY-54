// HERMES ENTITY54 — authorization MCP server (stdio).
//
// The server exposes eight tools. Every tool first resolves the caller
// against the gateway-asserted identity, then authorizes against the
// versioned policy, and only then acts. Every decision writes a
// tamper-evident receipt. Nothing in this file calls the model, and no
// instruction carried inside a tool argument, a tool result, or a message
// can change a role, a rule, or a decision. Authorization is deterministic
// code, not LLM judgment.
//
// The versioned policy is the single source of truth for every tool,
// including the policy tools themselves. There is no role check anywhere
// in this file that bypasses the policy.
//
// Tools:
// - entity54_authorize: read-only decision preview (still receipted).
// - entity54_linear_create_issue: governed Linear issue creation.
// - entity54_policy_export: versioned, signed policy export.
// - entity54_policy_import: verify + stage a newer policy (no activation).
// - entity54_policy_activate: OWNER-only activation of the staged policy.
// - entity54_receipts_verify: recompute the receipt hash chain.
// - entity54_events_list: sanitized, scope-filtered event feed (disabled by default).
// - entity54_status: install and configuration status (never returns keys).
import * as fs from "node:fs";
import * as path from "node:path";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema, } from "@modelcontextprotocol/sdk/types.js";
import { loadConfig, ensureDataDir, ConfigError, } from "./config.js";
import { loadPolicyFile, writePolicyFile, verifyPolicy, stagePolicyImport, } from "./policy.js";
import { ReceiptStore } from "./receipts.js";
import { EventStore, EVENT_CATEGORIES } from "./events.js";
import { loadPrincipals, resolveCaller, authorizeTool, AuthzError, } from "./authz.js";
import { createLinearClient, validateIssueInput, LinearError } from "./linear.js";
const SERVER_NAME = "entity54";
const SERVER_VERSION = "0.1.0";
function toolDef(name, description, properties, required) {
    return {
        name,
        description,
        inputSchema: { type: "object", properties, required },
    };
}
const TOOLS = [
    toolDef("entity54_authorize", "Check whether a principal is allowed to call a tool on a bot, under the active ENTITY54 policy. Default-deny. The decision is written to the receipt log.", {
        principal: { type: "string", description: "Caller principal id. Must equal the gateway-asserted principal." },
        bot: { type: "string", description: "Bot id. Must equal the gateway-asserted bot." },
        tool: { type: "string", description: "Tool name to check, for example linear:create-issue." },
    }, ["principal", "bot", "tool"]),
    toolDef("entity54_linear_create_issue", "Create a Linear issue, governed by ENTITY54 authorization. Unauthorized requests are denied BEFORE any Linear call. The outcome is written to the receipt log.", {
        principal: { type: "string" },
        bot: { type: "string" },
        teamId: { type: "string", description: "Linear team id." },
        title: { type: "string", description: "Issue title, 1 to 256 characters." },
        description: { type: "string", description: "Issue description, at most 10000 characters." },
        priority: { type: "integer", description: "Priority 0 to 4." },
    }, ["principal", "bot", "teamId", "title"]),
    toolDef("entity54_policy_export", "Export the active policy as versioned, HMAC-signed JSON. OWNER or ADMIN only.", {
        principal: { type: "string" },
        bot: { type: "string" },
    }, ["principal", "bot"]),
    toolDef("entity54_policy_import", "Verify and stage a newer signed policy. The candidate must verify against the policy key and carry a strictly higher version than the active policy. Staging does NOT activate it.", {
        principal: { type: "string" },
        bot: { type: "string" },
        policy: { type: "object", description: "The full signed policy document." },
    }, ["principal", "bot", "policy"]),
    toolDef("entity54_policy_activate", "Activate the staged policy. OWNER only. Writes an activation receipt. There is no silent activation path.", {
        principal: { type: "string" },
        bot: { type: "string" },
    }, ["principal", "bot"]),
    toolDef("entity54_receipts_verify", "Recompute the receipt hash chain and HMACs. Reports ok or the first bad sequence number.", {
        principal: { type: "string" },
        bot: { type: "string" },
    }, ["principal", "bot"]),
    toolDef("entity54_events_list", "List sanitized ENTITY54 events. Disabled by default. Events carry no raw content and pseudonymized identities. Visibility follows viewer scope.", {
        principal: { type: "string" },
        bot: { type: "string" },
        limit: { type: "integer", description: "Page size, at most 100." },
        offset: { type: "integer", description: "Page offset." },
        category: { type: "string", description: `One of: ${EVENT_CATEGORIES.join(", ")}.` },
    }, ["principal", "bot"]),
    toolDef("entity54_status", "Installation and configuration status. Never returns keys or secrets.", {
        principal: { type: "string" },
        bot: { type: "string" },
    }, ["principal", "bot"]),
];
function textResult(payload, isError = false) {
    return {
        content: [{ type: "text", text: JSON.stringify(payload, null, 2) }],
        isError,
    };
}
function asRecord(args) {
    if (typeof args !== "object" || args === null || Array.isArray(args)) {
        throw new AuthzError("invalid_args", "tool arguments must be an object");
    }
    return args;
}
function asString(value, field) {
    if (typeof value !== "string" || value.length === 0) {
        throw new AuthzError("invalid_args", `argument ${field} must be a non-empty string`);
    }
    return value;
}
export function loadState(config) {
    ensureDataDir(config.dataDir);
    const policyPath = path.join(config.dataDir, "entity54.policy.json");
    const pendingPath = path.join(config.dataDir, "entity54.policy.pending.json");
    const principalsPath = path.join(config.dataDir, "entity54.principals.json");
    const policy = loadPolicyFile(policyPath, config.policyKey);
    let pendingPolicy = null;
    if (fs.existsSync(pendingPath)) {
        pendingPolicy = verifyPolicy(JSON.parse(fs.readFileSync(pendingPath, "utf8")), config.policyKey);
    }
    const principals = loadPrincipals(principalsPath);
    const receipts = new ReceiptStore(config.dataDir, config.policyKey);
    const events = new EventStore(config.dataDir, config.pseudonymKey);
    return { config, policy, pendingPolicy, principals, receipts, events, policyPath, pendingPath, principalsPath };
}
export function createEntity54Server(state) {
    const { config } = state;
    const server = new Server({ name: SERVER_NAME, version: SERVER_VERSION }, { capabilities: { tools: {} } });
    const linear = createLinearClient({
        apiKey: config.linearApiKey,
        transport: config.linearTransport,
        timeoutMs: config.execTimeoutMs,
    });
    function denyReceipt(caller, bot, tool, reason) {
        const receipt = state.receipts.append({
            ts: new Date().toISOString(),
            type: "authorization",
            decision: "deny",
            principal: caller.id,
            role: caller.role,
            bot,
            tool,
            policyVersion: state.policy.version,
            detail: reason,
        });
        return receipt.seq;
    }
    // Write one authorization receipt (allow or deny) and the matching
    // sanitized event. Used by the authorize tool itself and by every
    // handler that acts after an allow gate, so an allowed action always
    // leaves two receipts: the authorization decision and the outcome.
    function decisionReceipt(caller, bot, tool, outcome) {
        const receipt = state.receipts.append({
            ts: new Date().toISOString(),
            type: "authorization",
            decision: outcome.decision,
            principal: caller.id,
            role: caller.role,
            bot,
            tool,
            policyVersion: state.policy.version,
            detail: outcome.reason,
        });
        state.events.record({
            category: outcome.decision === "allow" ? "authorization_allowed" : "authorization_denied",
            tool,
            decision: outcome.decision,
            principal: caller.id,
            bot,
            receiptRef: receipt.seq,
        });
        return receipt.seq;
    }
    // Authorize one tool call against the active policy. On deny, the denial
    // receipt is written here so no handler can forget it. Returns the
    // outcome; callers check allowed before acting.
    function gate(caller, bot, tool, args) {
        const outcome = authorizeTool(state.policy, caller, bot, tool, args);
        if (outcome.decision === "deny") {
            const receiptSeq = denyReceipt(caller, bot, tool, outcome.reason);
            state.events.record({
                category: "authorization_denied",
                tool,
                decision: "deny",
                principal: caller.id,
                bot,
                receiptRef: receiptSeq,
            });
            return { allowed: false, outcome, receiptSeq };
        }
        return { allowed: true, outcome, receiptSeq: null };
    }
    server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }));
    server.setRequestHandler(CallToolRequestSchema, async (request) => {
        const name = request.params.name;
        try {
            const args = asRecord(request.params.arguments ?? {});
            const claimedPrincipal = asString(args.principal, "principal");
            const claimedBot = asString(args.bot, "bot");
            const caller = resolveCaller(state.principals, {
                assertedPrincipal: config.principalId,
                assertedBot: config.botId,
                claimedPrincipal,
                claimedBot,
            });
            switch (name) {
                case "entity54_authorize": {
                    const readGate = gate(caller, claimedBot, "entity54:read", {});
                    if (!readGate.allowed) {
                        return textResult({ decision: "deny", reason: readGate.outcome.reason, receiptSeq: readGate.receiptSeq }, true);
                    }
                    const tool = asString(args.tool, "tool");
                    const outcome = authorizeTool(state.policy, caller, claimedBot, tool, {});
                    const receiptSeq = decisionReceipt(caller, claimedBot, tool, outcome);
                    return textResult({ decision: outcome.decision, ruleId: outcome.ruleId, reason: outcome.reason, receiptSeq, policyVersion: state.policy.version });
                }
                case "entity54_linear_create_issue": {
                    const tool = "linear:create-issue";
                    const checked = gate(caller, claimedBot, tool, {
                        team: typeof args.teamId === "string" ? args.teamId : "",
                    });
                    if (!checked.allowed) {
                        return textResult({ decision: "deny", reason: checked.outcome.reason, receiptSeq: checked.receiptSeq, executed: false }, true);
                    }
                    decisionReceipt(caller, claimedBot, tool, checked.outcome);
                    const input = validateIssueInput({ teamId: args.teamId, title: args.title, description: args.description, priority: args.priority });
                    state.events.record({
                        category: "tool_execution_started",
                        tool,
                        decision: "started",
                        principal: caller.id,
                        bot: claimedBot,
                        receiptRef: state.receipts.count(),
                    });
                    try {
                        const result = await linear.createIssue(input);
                        const receipt = state.receipts.append({
                            ts: new Date().toISOString(),
                            type: "execution",
                            decision: "success",
                            principal: caller.id,
                            role: caller.role,
                            bot: claimedBot,
                            tool,
                            policyVersion: state.policy.version,
                            detail: `issue ${result.issueId} created via ${result.transport} transport`,
                        });
                        state.events.record({
                            category: "tool_execution_succeeded",
                            tool,
                            decision: "success",
                            principal: caller.id,
                            bot: claimedBot,
                            receiptRef: receipt.seq,
                        });
                        return textResult({ decision: "allow", executed: true, issueId: result.issueId, url: result.url, transport: result.transport, receiptSeq: receipt.seq });
                    }
                    catch (error) {
                        const message = error instanceof Error ? error.message : "unknown error";
                        const errorCode = error instanceof LinearError ? error.code : "linear_http";
                        const receipt = state.receipts.append({
                            ts: new Date().toISOString(),
                            type: "execution",
                            decision: "failure",
                            principal: caller.id,
                            role: caller.role,
                            bot: claimedBot,
                            tool,
                            policyVersion: state.policy.version,
                            detail: `execution failed: ${message}`,
                        });
                        state.events.record({
                            category: "tool_execution_failed",
                            tool,
                            decision: "failure",
                            principal: caller.id,
                            bot: claimedBot,
                            receiptRef: receipt.seq,
                        });
                        return textResult({ decision: "allow", executed: false, reason: message, errorCode, receiptSeq: receipt.seq }, true);
                    }
                }
                case "entity54_policy_export": {
                    const checked = gate(caller, claimedBot, "policy:export", {});
                    if (!checked.allowed) {
                        return textResult({ decision: "deny", reason: checked.outcome.reason, receiptSeq: checked.receiptSeq }, true);
                    }
                    return textResult({ decision: "allow", policy: state.policy });
                }
                case "entity54_policy_import": {
                    const checked = gate(caller, claimedBot, "policy:import", {});
                    if (!checked.allowed) {
                        return textResult({ decision: "deny", reason: checked.outcome.reason, receiptSeq: checked.receiptSeq }, true);
                    }
                    decisionReceipt(caller, claimedBot, "policy:import", checked.outcome);
                    try {
                        const candidate = verifyPolicy(args.policy, config.policyKey);
                        const staged = stagePolicyImport(state.policy, candidate);
                        state.pendingPolicy = staged;
                        writePolicyFile(state.pendingPath, staged);
                        const receipt = state.receipts.append({
                            ts: new Date().toISOString(),
                            type: "policy",
                            decision: "staged",
                            principal: caller.id,
                            role: caller.role,
                            bot: claimedBot,
                            tool: "policy:import",
                            policyVersion: staged.version,
                            detail: `policy v${staged.version} staged, awaiting OWNER activation`,
                        });
                        state.events.record({
                            category: "approval_requested",
                            tool: "policy:import",
                            decision: "staged",
                            principal: caller.id,
                            bot: claimedBot,
                            receiptRef: receipt.seq,
                        });
                        return textResult({ decision: "staged", version: staged.version, receiptSeq: receipt.seq, note: "Staged only. Activation requires entity54_policy_activate by OWNER." });
                    }
                    catch (error) {
                        const message = error instanceof Error ? error.message : "unknown error";
                        const receipt = state.receipts.append({
                            ts: new Date().toISOString(),
                            type: "policy",
                            decision: "rejected",
                            principal: caller.id,
                            role: caller.role,
                            bot: claimedBot,
                            tool: "policy:import",
                            policyVersion: state.policy.version,
                            detail: `import rejected: ${message}`,
                        });
                        state.events.record({
                            category: "policy_rejected",
                            tool: "policy:import",
                            decision: "rejected",
                            principal: caller.id,
                            bot: claimedBot,
                            receiptRef: receipt.seq,
                        });
                        return textResult({ decision: "rejected", reason: message, receiptSeq: receipt.seq }, true);
                    }
                }
                case "entity54_policy_activate": {
                    const checked = gate(caller, claimedBot, "policy:activate", {});
                    if (!checked.allowed) {
                        return textResult({ decision: "deny", reason: checked.outcome.reason, receiptSeq: checked.receiptSeq }, true);
                    }
                    decisionReceipt(caller, claimedBot, "policy:activate", checked.outcome);
                    if (!state.pendingPolicy) {
                        const receiptSeq = denyReceipt(caller, claimedBot, "policy:activate", "no staged policy to activate");
                        return textResult({ decision: "deny", reason: "no staged policy to activate", receiptSeq }, true);
                    }
                    const activated = state.pendingPolicy;
                    state.policy = activated;
                    state.pendingPolicy = null;
                    writePolicyFile(state.policyPath, activated);
                    if (fs.existsSync(state.pendingPath)) {
                        fs.unlinkSync(state.pendingPath);
                    }
                    const receipt = state.receipts.append({
                        ts: new Date().toISOString(),
                        type: "policy",
                        decision: "activated",
                        principal: caller.id,
                        role: caller.role,
                        bot: claimedBot,
                        tool: "policy:activate",
                        policyVersion: activated.version,
                        detail: `policy v${activated.version} activated`,
                    });
                    state.events.record({
                        category: "policy_installed",
                        tool: "policy:activate",
                        decision: "activated",
                        principal: caller.id,
                        bot: claimedBot,
                        receiptRef: receipt.seq,
                    });
                    state.events.record({
                        category: "approval_resolved",
                        tool: "policy:activate",
                        decision: "activated",
                        principal: caller.id,
                        bot: claimedBot,
                        receiptRef: receipt.seq,
                    });
                    return textResult({ decision: "activated", version: activated.version, receiptSeq: receipt.seq });
                }
                case "entity54_receipts_verify": {
                    const checked = gate(caller, claimedBot, "entity54:receipts-verify", {});
                    if (!checked.allowed) {
                        return textResult({ decision: "deny", reason: checked.outcome.reason, receiptSeq: checked.receiptSeq }, true);
                    }
                    const result = state.receipts.verify();
                    return textResult({ ok: result.ok, checked: result.checked, badSeq: result.badSeq, reason: result.reason });
                }
                case "entity54_events_list": {
                    if (!config.eventsEnabled) {
                        return textResult({ decision: "deny", reason: "event feed is disabled. Set ENTITY54_EVENTS_ENABLED=true to enable it." }, true);
                    }
                    const checked = gate(caller, claimedBot, "entity54:events-list", {});
                    if (!checked.allowed) {
                        return textResult({ decision: "deny", reason: checked.outcome.reason, receiptSeq: checked.receiptSeq }, true);
                    }
                    let category;
                    if (args.category !== undefined) {
                        if (typeof args.category !== "string" || !EVENT_CATEGORIES.includes(args.category)) {
                            return textResult({ decision: "deny", reason: `unknown event category: ${String(args.category)}` }, true);
                        }
                        category = args.category;
                    }
                    const limit = typeof args.limit === "number" ? args.limit : 25;
                    const offset = typeof args.offset === "number" ? args.offset : 0;
                    const page = state.events.list({
                        viewerPrincipal: caller.id,
                        viewerRole: caller.role,
                        viewerBot: claimedBot,
                        limit,
                        offset,
                        category,
                    });
                    return textResult({ events: page.events, total: page.total, limit, offset });
                }
                case "entity54_status": {
                    const checked = gate(caller, claimedBot, "entity54:read", {});
                    if (!checked.allowed) {
                        return textResult({ decision: "deny", reason: checked.outcome.reason, receiptSeq: checked.receiptSeq }, true);
                    }
                    return textResult({
                        server: SERVER_NAME,
                        version: SERVER_VERSION,
                        policyId: state.policy.policyId,
                        policyVersion: state.policy.version,
                        pendingPolicyVersion: state.pendingPolicy ? state.pendingPolicy.version : null,
                        caller: { principal: caller.id, role: caller.role, bot: claimedBot },
                        receipts: state.receipts.count(),
                        eventsEnabled: config.eventsEnabled,
                        eventsStored: state.events.count(),
                        linearConfigured: config.linearApiKey !== null,
                        linearTransport: config.linearTransport,
                    });
                }
                default:
                    return textResult({ decision: "deny", reason: `unknown tool: ${name}` }, true);
            }
        }
        catch (error) {
            const message = error instanceof Error ? error.message : "unknown error";
            const code = error instanceof AuthzError ? error.code : "internal_error";
            try {
                state.receipts.append({
                    ts: new Date().toISOString(),
                    type: "authorization",
                    decision: "deny",
                    principal: typeof request.params.arguments === "object" && request.params.arguments !== null
                        ? String(request.params.arguments.principal ?? "unknown")
                        : "unknown",
                    role: "unknown",
                    bot: typeof request.params.arguments === "object" && request.params.arguments !== null
                        ? String(request.params.arguments.bot ?? "unknown")
                        : "unknown",
                    tool: name,
                    policyVersion: state.policy.version,
                    detail: `denied (${code}): ${message}`,
                });
            }
            catch {
                // Receipt write failure must not mask the denial.
            }
            return textResult({ decision: "deny", code, reason: message, executed: false }, true);
        }
    });
    return server;
}
async function main() {
    let config;
    try {
        config = loadConfig(process.env);
    }
    catch (error) {
        if (error instanceof ConfigError) {
            console.error(`ENTITY54 startup refused: ${error.message}`);
            process.exit(2);
        }
        throw error;
    }
    let state;
    try {
        state = loadState(config);
    }
    catch (error) {
        console.error(`ENTITY54 startup refused: ${error instanceof Error ? error.message : "unknown error"}`);
        process.exit(2);
    }
    const server = createEntity54Server(state);
    const transport = new StdioServerTransport();
    await server.connect(transport);
    console.error(`ENTITY54 ${SERVER_VERSION} running on stdio; policy ${state.policy.policyId} v${state.policy.version}; principal ${config.principalId}; bot ${config.botId}`);
}
main().catch((error) => {
    console.error("ENTITY54 fatal:", error instanceof Error ? error.message : error);
    process.exit(1);
});
