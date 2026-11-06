// Shared test helpers for ENTITY54. Each test spawns a real server process
// over MCP stdio with its own temp data dir, its own keys, and a signed
// policy. Nothing here talks to a real Hermes instance or a real Linear
// workspace: the Linear transport is "mock" unless a test says otherwise.
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { signPolicy } from "../dist/policy.js";

export const TEST_KEY = "test-policy-key-0123456789abcdef";
export const TEST_PSEUDONYM_KEY = "test-pseudonym-key-0123456789abcdef";

export const TEST_PRINCIPALS = [
  { id: "tg:100", channel: "telegram", channelUserId: "100", role: "OWNER", bots: ["bot-main"], displayName: "Test Owner" },
  { id: "tg:200", channel: "telegram", channelUserId: "200", role: "ADMIN", bots: ["bot-main"], displayName: "Test Admin" },
  { id: "tg:300", channel: "telegram", channelUserId: "300", role: "USER", bots: ["bot-main"], displayName: "Test User" },
  { id: "tg:400", channel: "telegram", channelUserId: "400", role: "GUEST", bots: ["bot-main"], displayName: "Test Guest" },
  { id: "tg:500", channel: "telegram", channelUserId: "500", role: "USER", bots: ["bot-other"], displayName: "Test Other-Bot User" },
];

export function testPolicyDoc(overrides = {}) {
  const base = JSON.parse(
    fs.readFileSync(new URL("../../config/entity54.policy.example.json", import.meta.url), "utf8")
  );
  const unsigned = { ...base, ...overrides };
  delete unsigned.integrity;
  return signPolicy(unsigned, TEST_KEY);
}

export function makeDataDir({ policy, principals = TEST_PRINCIPALS } = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "entity54-test-"));
  const doc = policy ?? testPolicyDoc();
  fs.writeFileSync(path.join(dir, "entity54.policy.json"), `${JSON.stringify(doc, null, 2)}\n`);
  fs.writeFileSync(path.join(dir, "entity54.principals.json"), `${JSON.stringify(principals, null, 2)}\n`);
  return dir;
}

export async function startServer({
  principal = "tg:100",
  bot = "bot-main",
  eventsEnabled = false,
  transport = "mock",
  policy,
  principals,
  extraEnv = {},
} = {}) {
  const dataDir = makeDataDir({ policy, principals });
  const serverPath = new URL("../dist/index.js", import.meta.url).pathname;
  const env = {
    ...process.env,
    ENTITY54_DATA_DIR: dataDir,
    ENTITY54_PRINCIPAL_ID: principal,
    ENTITY54_BOT_ID: bot,
    ENTITY54_POLICY_KEY: TEST_KEY,
    ENTITY54_PSEUDONYM_KEY: TEST_PSEUDONYM_KEY,
    ENTITY54_EVENTS_ENABLED: eventsEnabled ? "true" : "false",
    ENTITY54_LINEAR_TRANSPORT: transport,
    ...extraEnv,
  };
  delete env.LINEAR_API_KEY;
  const clientTransport = new StdioClientTransport({
    command: process.execPath,
    args: [serverPath],
    env,
    stderr: "ignore",
  });
  const client = new Client({ name: "entity54-test-client", version: "0.1.0" }, { capabilities: {} });
  await client.connect(clientTransport);
  return {
    client,
    dataDir,
    key: TEST_KEY,
    async call(name, args) {
      const result = await client.callTool({ name, arguments: args });
      const text = result.content?.[0]?.text ?? "";
      let parsed = null;
      try {
        parsed = JSON.parse(text);
      } catch {
        parsed = null;
      }
      return { isError: Boolean(result.isError), text, parsed };
    },
    async close() {
      await client.close();
    },
  };
}

export function readReceipts(dataDir) {
  const file = path.join(dataDir, "receipts.jsonl");
  if (!fs.existsSync(file)) return [];
  return fs.readFileSync(file, "utf8").split("\n").filter(Boolean).map((line) => JSON.parse(line));
}

export function readEvents(dataDir) {
  const file = path.join(dataDir, "events.jsonl");
  if (!fs.existsSync(file)) return [];
  return fs.readFileSync(file, "utf8").split("\n").filter(Boolean).map((line) => JSON.parse(line));
}
