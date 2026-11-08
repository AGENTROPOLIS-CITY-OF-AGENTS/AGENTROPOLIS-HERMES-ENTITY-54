// ENTITY54 first-run setup. Generates the operator keys, signs the example
// policy and principals with them, and writes the profile data directory
// plus a .env file the operator copies into the Hermes profile environment.
//
// Run once, from the server directory:
//   node scripts/setup.mjs --data-dir ./data --owner tg:YOUR_TELEGRAM_ID
//
// The script never prints the full keys to stdout in a form that should be
// pasted anywhere public; it writes them to the local .env file only.
// Keys are 32 random bytes, hex-encoded.
import * as fs from "node:fs";
import * as path from "node:path";
import { randomBytes, createHmac } from "node:crypto";

function canonical(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value) ?? "null";
  if (Array.isArray(value)) return `[${value.map((item) => canonical(item)).join(",")}]`;
  const keys = Object.keys(value).sort();
  return `{${keys.map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
}

function sign(doc, key) {
  const { integrity, ...unsigned } = doc;
  const value = createHmac("sha256", key).update(canonical(unsigned), "utf8").digest("hex");
  return { ...unsigned, integrity: { alg: "HMAC-SHA256", value } };
}

const args = process.argv.slice(2);
function flag(name, fallback) {
  const hit = args.find((arg) => arg.startsWith(`${name}=`));
  return hit ? hit.slice(name.length + 1) : fallback;
}

const dataDir = path.resolve(flag("--data-dir", "./data"));
const ownerId = flag("--owner", "tg:000000000");
const ownerBot = flag("--bot", "bot-main");
const ownerChannelUserId = ownerId.includes(":") ? ownerId.split(":").slice(1).join(":") : ownerId;

const policyKey = randomBytes(32).toString("hex");
const pseudonymKey = randomBytes(32).toString("hex");

const policyTemplatePath = path.resolve("../config/entity54.policy.example.json");
const principalsTemplatePath = path.resolve("../config/entity54.principals.example.json");

const policyTemplate = JSON.parse(fs.readFileSync(policyTemplatePath, "utf8"));
const principalsTemplate = JSON.parse(fs.readFileSync(principalsTemplatePath, "utf8"));

const principals = principalsTemplate.map((principal) => {
  if (principal.role === "OWNER") {
    return { ...principal, id: ownerId, channelUserId: ownerChannelUserId, bots: [ownerBot] };
  }
  return { ...principal, bots: [ownerBot] };
});

const policy = sign(
  { ...policyTemplate, issuedAt: new Date().toISOString() },
  policyKey
);

fs.mkdirSync(dataDir, { recursive: true });
fs.writeFileSync(path.join(dataDir, "entity54.policy.json"), `${JSON.stringify(policy, null, 2)}\n`);
fs.writeFileSync(path.join(dataDir, "entity54.principals.json"), `${JSON.stringify(principals, null, 2)}\n`);

const envLines = [
  "# ENTITY54 profile environment. Copy these into the Hermes profile .env.",
  "# Never commit this file. Never paste the keys into a chat, a ticket, or a repo.",
  `ENTITY54_DATA_DIR=${dataDir}`,
  `ENTITY54_PRINCIPAL_ID=${ownerId}`,
  `ENTITY54_BOT_ID=${ownerBot}`,
  `ENTITY54_POLICY_KEY=${policyKey}`,
  `ENTITY54_PSEUDONYM_KEY=${pseudonymKey}`,
  "# Required when ENTITY54_EVENTS_ENABLED=true. Startup refuses an enabled feed without this key.",
  "ENTITY54_EVENTS_ENABLED=false",
  "# LINEAR_API_KEY=   # set only if Linear issue creation is wanted",
  "ENTITY54_LINEAR_TRANSPORT=live",
  "",
];
fs.writeFileSync(path.join(dataDir, ".env.entity54"), envLines.join("\n"));

console.log(`ENTITY54 setup complete.`);
console.log(`  data dir: ${dataDir}`);
console.log(`  policy: ${policy.policyId} v${policy.version} (signed)`);
console.log(`  owner principal: ${ownerId} on bot ${ownerBot}`);
console.log(`  env file: ${path.join(dataDir, ".env.entity54")} (keep private; copy into the Hermes profile .env)`);
console.log(`  next: start the server with the env loaded, then run entity54_status.`);
