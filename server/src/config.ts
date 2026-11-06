// ENTITY54 config. Every value comes from the environment; nothing secret
// is ever read from the repository. A missing policy key is fatal: the
// server refuses to start rather than authorizing against an unverified
// policy. This is the fail-closed rule applied to startup itself.
import * as fs from "node:fs";
import * as path from "node:path";

export type Role = "OWNER" | "ADMIN" | "USER" | "GUEST";

export const ROLE_RANK: Record<Role, number> = {
  GUEST: 0,
  USER: 1,
  ADMIN: 2,
  OWNER: 3,
};

export const ROLES: readonly Role[] = ["OWNER", "ADMIN", "USER", "GUEST"];

export function isRole(value: unknown): value is Role {
  return typeof value === "string" && (ROLES as readonly string[]).includes(value);
}

export interface Entity54Config {
  dataDir: string;
  principalId: string;
  botId: string;
  policyKey: string;
  pseudonymKey: string | null;
  eventsEnabled: boolean;
  linearApiKey: string | null;
  linearTransport: "live" | "mock";
  execTimeoutMs: number;
}

export class ConfigError extends Error {}

export function loadConfig(env: NodeJS.ProcessEnv): Entity54Config {
  const dataDir = env.ENTITY54_DATA_DIR ?? path.join(process.cwd(), "data");
  const principalId = (env.ENTITY54_PRINCIPAL_ID ?? "").trim();
  const botId = (env.ENTITY54_BOT_ID ?? "").trim();
  const policyKey = (env.ENTITY54_POLICY_KEY ?? "").trim();
  if (!principalId) {
    throw new ConfigError(
      "ENTITY54_PRINCIPAL_ID is required: the gateway-asserted caller principal (for example tg:123456789). Refusing to start without an asserted identity."
    );
  }
  if (!botId) {
    throw new ConfigError(
      "ENTITY54_BOT_ID is required: the gateway-asserted bot id (for example bot-main). Refusing to start without an asserted bot scope."
    );
  }
  if (!policyKey) {
    throw new ConfigError(
      "ENTITY54_POLICY_KEY is required: HMAC key for policy and receipt integrity. Generate one with: node scripts/setup.mjs. Refusing to start without it."
    );
  }
  const eventsEnabled = env.ENTITY54_EVENTS_ENABLED === "true";
  const linearTransport = env.ENTITY54_LINEAR_TRANSPORT === "mock" ? "mock" : "live";
  const execTimeoutMs = Number.parseInt(env.ENTITY54_EXEC_TIMEOUT_MS ?? "10000", 10);
  return {
    dataDir,
    principalId,
    botId,
    policyKey,
    pseudonymKey: (env.ENTITY54_PSEUDONYM_KEY ?? "").trim() || null,
    eventsEnabled,
    linearApiKey: (env.LINEAR_API_KEY ?? "").trim() || null,
    linearTransport,
    execTimeoutMs: Number.isFinite(execTimeoutMs) && execTimeoutMs > 0 ? execTimeoutMs : 10000,
  };
}

export function ensureDataDir(dataDir: string): void {
  fs.mkdirSync(dataDir, { recursive: true });
}
