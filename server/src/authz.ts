// ENTITY54 authorization core.
//
// Trust model, stated plainly because everything else rests on it:
// - The MCP server runs inside one Hermes profile over stdio. Only that
//   profile's gateway can talk to it. The gateway asserts the caller
//   identity (ENTITY54_PRINCIPAL_ID) and bot scope (ENTITY54_BOT_ID) in the
//   server environment at spawn time. ENTITY54 does NOT re-authenticate the
//   Telegram user; the gateway already did that (allowlist, session keyed
//   by user id). ENTITY54 authorizes the gateway-asserted principal
//   against the principal store and the versioned policy.
// - Authentication is not authorization. A verified principal with no
//   matching allow rule is denied.
// - Spoofing: any tool argument that claims a principal different from the
//   gateway-asserted one is rejected as a spoofing attempt, and the
//   rejection itself is written to the receipt log.
// - Telegram isolation: roles and rules are scoped per bot. A principal
//   verified on bot A holds nothing on bot B unless the policy explicitly
//   grants it there. There is no cross-bot inheritance.
import * as fs from "node:fs";
import * as path from "node:path";
import { isRole, type Role } from "./config.js";
import { evaluatePolicy, type PolicyDoc } from "./policy.js";

export interface Principal {
  id: string;
  channel: "telegram" | "hermes-profile" | "dashboard";
  channelUserId: string;
  role: Role;
  bots: string[];
  displayName?: string;
}

export class AuthzError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.code = code;
  }
}

export function loadPrincipals(filePath: string): Principal[] {
  let raw: string;
  try {
    raw = fs.readFileSync(filePath, "utf8");
  } catch {
    throw new AuthzError("principals_missing", `principal store not found: ${filePath}`);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new AuthzError("principals_invalid", `principal store is not valid JSON: ${filePath}`);
  }
  if (!Array.isArray(parsed)) {
    throw new AuthzError("principals_invalid", "principal store must be a JSON array");
  }
  const principals: Principal[] = [];
  for (const item of parsed as unknown[]) {
    if (typeof item !== "object" || item === null || Array.isArray(item)) {
      throw new AuthzError("principals_invalid", "each principal must be an object");
    }
    const p = item as Record<string, unknown>;
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
      bots: p.bots as string[],
      displayName: typeof p.displayName === "string" ? p.displayName : undefined,
    });
  }
  return principals;
}

export function writePrincipals(filePath: string, principals: Principal[]): void {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, `${JSON.stringify(principals, null, 2)}\n`, "utf8");
}

export interface CallerContext {
  assertedPrincipal: string;
  assertedBot: string;
  claimedPrincipal: string;
  claimedBot: string;
}

// Resolve the caller: the claimed identity must equal the gateway-asserted
// identity, the principal must exist in the store, and the asserted bot
// must be in the principal's bot scope. Any failure is fail-closed.
export function resolveCaller(
  principals: Principal[],
  ctx: CallerContext
): Principal {
  if (ctx.claimedPrincipal !== ctx.assertedPrincipal) {
    throw new AuthzError(
      "spoofing",
      `claimed principal ${ctx.claimedPrincipal} does not match gateway-asserted principal ${ctx.assertedPrincipal}`
    );
  }
  if (ctx.claimedBot !== ctx.assertedBot) {
    throw new AuthzError(
      "spoofing",
      `claimed bot ${ctx.claimedBot} does not match gateway-asserted bot ${ctx.assertedBot}`
    );
  }
  const principal = principals.find((item) => item.id === ctx.assertedPrincipal);
  if (!principal) {
    throw new AuthzError(
      "unknown_principal",
      `gateway-asserted principal ${ctx.assertedPrincipal} is not in the principal store`
    );
  }
  if (!principal.bots.includes("*") && !principal.bots.includes(ctx.assertedBot)) {
    throw new AuthzError(
      "bot_scope",
      `principal ${principal.id} has no scope on bot ${ctx.assertedBot}`
    );
  }
  return principal;
}

export interface AuthorizationOutcome {
  decision: "allow" | "deny";
  ruleId: string | null;
  reason: string;
  constraints: Record<string, string>;
}

// Authorize a tool call. Pure policy evaluation plus constraint checking.
// Any error thrown by the policy layer is a deny, never an allow.
export function authorizeTool(
  policy: PolicyDoc,
  principal: Principal,
  bot: string,
  tool: string,
  args: Record<string, unknown>
): AuthorizationOutcome {
  let outcome;
  try {
    outcome = evaluatePolicy(policy, {
      principal: principal.id,
      role: principal.role,
      bot,
      tool,
    });
  } catch (error) {
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
