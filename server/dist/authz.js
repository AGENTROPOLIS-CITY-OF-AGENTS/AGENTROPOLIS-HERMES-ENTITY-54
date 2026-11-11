// ENTITY54 authorization core.
//
// Trust model, stated plainly because everything else rests on it:
// - The MCP server runs inside one Hermes profile over stdio. Only that
//   configured Hermes process can invoke it. ENTITY54_PRINCIPAL_ID and
//   ENTITY54_BOT_ID are configured environment assertions, not independently
//   authenticated end-user identity or verified gateway claims. ENTITY54
//   does not authenticate the Telegram user or prove gateway provenance.
//   ENTITY54 applies local principal-store and policy checks to these
//   configured assertions. Operators must secure their origin and scope.
// - Authentication is not authorization. A verified principal with no
//   matching allow rule is denied.
// - Claim mismatch: any tool argument that names a principal different from
//   the configured environment assertion is rejected, and the
//   rejection itself is written to the receipt log.
// - Telegram isolation: roles and rules are scoped per bot. A principal
//   verified on bot A holds nothing on bot B unless the policy explicitly
//   grants it there. There is no cross-bot inheritance.
import * as fs from "node:fs";
import * as path from "node:path";
import { isRole } from "./config.js";
import { evaluatePolicy } from "./policy.js";
export class AuthzError extends Error {
    code;
    constructor(code, message) {
        super(message);
        this.code = code;
    }
}
export function loadPrincipals(filePath) {
    let raw;
    try {
        raw = fs.readFileSync(filePath, "utf8");
    }
    catch {
        throw new AuthzError("principals_missing", `principal store not found: ${filePath}`);
    }
    let parsed;
    try {
        parsed = JSON.parse(raw);
    }
    catch {
        throw new AuthzError("principals_invalid", `principal store is not valid JSON: ${filePath}`);
    }
    if (!Array.isArray(parsed)) {
        throw new AuthzError("principals_invalid", "principal store must be a JSON array");
    }
    const principals = [];
    for (const item of parsed) {
        if (typeof item !== "object" || item === null || Array.isArray(item)) {
            throw new AuthzError("principals_invalid", "each principal must be an object");
        }
        const p = item;
        if (typeof p.id !== "string" || p.id.length === 0) {
            throw new AuthzError("principals_invalid", "each principal needs a non-empty string id");
        }
        if (p.channel !== "telegram" && p.channel !== "hermes-profile" && p.channel !== "dashboard") {
            throw new AuthzError("principals_invalid", `principal ${p.id}: unknown channel`);
        }
        if (typeof p.channelUserId !== "string" || p.channelUserId.length === 0) {
            throw new AuthzError("principals_invalid", `principal ${p.id}: channelUserId required`);
        }
        if (!isRole(p.role)) {
            throw new AuthzError("principals_invalid", `principal ${p.id}: unknown role`);
        }
        if (!Array.isArray(p.bots) || p.bots.some((bot) => typeof bot !== "string")) {
            throw new AuthzError("principals_invalid", `principal ${p.id}: bots must be an array of strings`);
        }
        principals.push({
            id: p.id,
            channel: p.channel,
            channelUserId: p.channelUserId,
            role: p.role,
            bots: p.bots,
            displayName: typeof p.displayName === "string" ? p.displayName : undefined,
        });
    }
    return principals;
}
export function writePrincipals(filePath, principals) {
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    fs.writeFileSync(filePath, `${JSON.stringify(principals, null, 2)}\n`, "utf8");
}
// Resolve the caller: claimed identity must match the configured environment
// assertion (not independently authenticated), principal must exist, and bot
// must be in the principal's bot scope. Any failure is fail-closed.
export function resolveCaller(principals, ctx) {
    if (ctx.claimedPrincipal !== ctx.assertedPrincipal) {
        throw new AuthzError("spoofing", `claimed principal ${ctx.claimedPrincipal} does not match configured principal ${ctx.assertedPrincipal}`);
    }
    if (ctx.claimedBot !== ctx.assertedBot) {
        throw new AuthzError("spoofing", `claimed bot ${ctx.claimedBot} does not match configured bot ${ctx.assertedBot}`);
    }
    const principal = principals.find((item) => item.id === ctx.assertedPrincipal);
    if (!principal) {
        throw new AuthzError("unknown_principal", `configured principal ${ctx.assertedPrincipal} is not in the principal store`);
    }
    if (!principal.bots.includes("*") && !principal.bots.includes(ctx.assertedBot)) {
        throw new AuthzError("bot_scope", `principal ${principal.id} has no scope on bot ${ctx.assertedBot}`);
    }
    return principal;
}
// Authorize a tool call. Pure policy evaluation plus constraint checking.
// Any error thrown by the policy layer is a deny, never an allow.
export function authorizeTool(policy, principal, bot, tool, args) {
    let outcome;
    try {
        outcome = evaluatePolicy(policy, {
            principal: principal.id,
            role: principal.role,
            bot,
            tool,
        });
    }
    catch (error) {
        return {
            decision: "deny",
            ruleId: null,
            reason: `policy evaluation failed: ${error instanceof Error ? error.message : "unknown error"}`,
            constraints: {},
        };
    }
    if (outcome.decision === "deny") {
        return outcome;
    }
    for (const [key, expected] of Object.entries(outcome.constraints)) {
        const actual = args[key];
        if (actual !== expected) {
            return {
                decision: "deny",
                ruleId: outcome.ruleId,
                reason: `constraint mismatch: argument ${key} must be ${expected}`,
                constraints: outcome.constraints,
            };
        }
    }
    return outcome;
}
