// ENTITY54 config. Every value comes from the environment; nothing secret
// is ever read from the repository. A missing policy key is fatal: the
// server refuses to start rather than authorizing against an unverified
// policy. This is the fail-closed rule applied to startup itself.
import * as fs from "node:fs";
import * as path from "node:path";
export const ROLE_RANK = {
    GUEST: 0,
    USER: 1,
    ADMIN: 2,
    OWNER: 3,
};
export const ROLES = ["OWNER", "ADMIN", "USER", "GUEST"];
export function isRole(value) {
    return typeof value === "string" && ROLES.includes(value);
}
export class ConfigError extends Error {
}
export function loadConfig(env) {
    const dataDir = env.ENTITY54_DATA_DIR ?? path.join(process.cwd(), "data");
    const principalId = (env.ENTITY54_PRINCIPAL_ID ?? "").trim();
    const botId = (env.ENTITY54_BOT_ID ?? "").trim();
    const policyKey = (env.ENTITY54_POLICY_KEY ?? "").trim();
    if (!principalId) {
        throw new ConfigError("ENTITY54_PRINCIPAL_ID is required: the gateway-asserted caller principal (for example tg:123456789). Refusing to start without an asserted identity.");
    }
    if (!botId) {
        throw new ConfigError("ENTITY54_BOT_ID is required: the gateway-asserted bot id (for example bot-main). Refusing to start without an asserted bot scope.");
    }
    if (!policyKey) {
        throw new ConfigError("ENTITY54_POLICY_KEY is required: HMAC key for policy and receipt integrity. Generate one with: node scripts/setup.mjs. Refusing to start without it.");
    }
    const eventsEnabled = env.ENTITY54_EVENTS_ENABLED === "true";
    const pseudonymKey = (env.ENTITY54_PSEUDONYM_KEY ?? "").trim() || null;
    // Fail closed: an enabled feed with no pseudonym key hashes every
    // principal to the same token, so a GUEST filter would match every event.
    if (eventsEnabled && !pseudonymKey) {
        throw new ConfigError("ENTITY54_PSEUDONYM_KEY is required when ENTITY54_EVENTS_ENABLED=true. Refusing to start: without a pseudonym key every principal would share one token and viewer scope would fail open. Generate a key with: node scripts/setup.mjs.");
    }
    const linearTransport = env.ENTITY54_LINEAR_TRANSPORT === "mock" ? "mock" : "live";
    const execTimeoutMs = Number.parseInt(env.ENTITY54_EXEC_TIMEOUT_MS ?? "10000", 10);
    return {
        dataDir,
        principalId,
        botId,
        policyKey,
        pseudonymKey,
        eventsEnabled,
        linearApiKey: (env.LINEAR_API_KEY ?? "").trim() || null,
        linearTransport,
        execTimeoutMs: Number.isFinite(execTimeoutMs) && execTimeoutMs > 0 ? execTimeoutMs : 10000,
    };
}
export function ensureDataDir(dataDir) {
    fs.mkdirSync(dataDir, { recursive: true });
}
// Denial reason for entity54_events_list, or null when the feed may be read.
// Startup already refuses an enabled feed with no key. This check is the
// second gate so a mismatched config cannot list events.
export function eventsFeedDenial(eventsEnabled, pseudonymKey) {
    if (!eventsEnabled) {
        return "event feed is disabled. Set ENTITY54_EVENTS_ENABLED=true to enable it.";
    }
    if (!pseudonymKey) {
        return "event feed requires ENTITY54_PSEUDONYM_KEY. Refusing to list events without a pseudonym key.";
    }
    return null;
}
