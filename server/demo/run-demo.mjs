// HERMES ENTITY54 reproducible demo.
//
// Runs the whole story end to end against a fresh temp data dir with a
// demo-signed policy and the mock Linear transport:
//   1. A GUEST tries to create a Linear issue and is DENIED before any
//      execution happens.
//   2. The OWNER authorizes and creates a Linear issue (mock transport)
//      and the operation is EXECUTED.
//   3. The receipt chain is verified and the sanitized event feed is shown.
//
// Usage, from the server directory:
//   node demo/run-demo.mjs            (fast, prints the transcript)
//   node demo/run-demo.mjs --paced    (pauses between steps, about 70s,
//                                      for screen recording)
//
// Nothing here touches a real Hermes instance, a real Telegram bot, or a
// real Linear workspace. The mock transport is labelled mock in every
// receipt, so the demo can never be mistaken for a real issue.
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { signPolicy } from "../dist/policy.js";

const PACED = process.argv.includes("--paced");
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const step = async (ms) => {
  if (PACED) await sleep(ms);
};

const DEMO_KEY = "demo-policy-key-0123456789abcdef";
const DEMO_PSEUDONYM_KEY = "demo-pseudonym-key-0123456789abcdef";
const SERVER_PATH = new URL("../dist/index.js", import.meta.url).pathname;

function header(title) {
  console.log("");
  console.log(`=== ${title} ===`);
}

function show(label, value) {
  console.log(`${label}: ${JSON.stringify(value, null, 2)}`);
}

async function startServer(dataDir, principal, bot = "bot-main") {
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [SERVER_PATH],
    env: {
      ...process.env,
      ENTITY54_DATA_DIR: dataDir,
      ENTITY54_PRINCIPAL_ID: principal,
      ENTITY54_BOT_ID: bot,
      ENTITY54_POLICY_KEY: DEMO_KEY,
      ENTITY54_PSEUDONYM_KEY: DEMO_PSEUDONYM_KEY,
      ENTITY54_EVENTS_ENABLED: "true",
      ENTITY54_LINEAR_TRANSPORT: "mock",
    },
    stderr: "ignore",
  });
  const client = new Client({ name: "entity54-demo", version: "0.1.0" }, { capabilities: {} });
  await client.connect(transport);
  return {
    client,
    async call(name, args) {
      const result = await client.callTool({ name, arguments: args });
      const text = result.content?.[0]?.text ?? "";
      let parsed = null;
      try {
        parsed = JSON.parse(text);
      } catch {
        parsed = null;
      }
      return { isError: Boolean(result.isError), parsed };
    },
    async close() {
      await client.close();
    },
  };
}

async function main() {
  const startedAt = new Date();
  console.log("HERMES ENTITY54 demo: denied operation, authorized operation, receipts.");
  console.log(`Started ${startedAt.toISOString()}. Mock Linear transport. No real Hermes, Telegram, or Linear involved.`);

  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "entity54-demo-"));
  const policyTemplate = JSON.parse(fs.readFileSync(new URL("../../config/entity54.policy.example.json", import.meta.url), "utf8"));
  const principals = JSON.parse(fs.readFileSync(new URL("../../config/entity54.principals.example.json", import.meta.url), "utf8"));
  const { integrity: _ignored, ...unsigned } = policyTemplate;
  const policy = signPolicy({ ...unsigned, issuedAt: new Date().toISOString() }, DEMO_KEY);
  fs.writeFileSync(path.join(dataDir, "entity54.policy.json"), `${JSON.stringify(policy, null, 2)}\n`);
  fs.writeFileSync(path.join(dataDir, "entity54.principals.json"), `${JSON.stringify(principals, null, 2)}\n`);
  console.log(`Data dir: ${dataDir}`);
  console.log(`Policy: ${policy.policyId} v${policy.version}, signed with the demo key.`);
  await step(5000);

  header("STEP 1: GUEST tries to create a Linear issue");
  console.log("Caller: tg:333333333 (GUEST) on bot-main. Tool: entity54_linear_create_issue, team ENG.");
  const guest = await startServer(dataDir, "tg:333333333");
  const denied = await guest.call("entity54_linear_create_issue", {
    principal: "tg:333333333", bot: "bot-main", teamId: "ENG", title: "Guest tries to file an issue",
  });
  show("Result", denied.parsed);
  console.log("DENIED. executed is false, so no Linear call happened. The denial is receipted.");
  await guest.close();
  await step(15000);

  header("STEP 2: OWNER authorizes the same operation");
  console.log("Caller: tg:000000000 (OWNER) on bot-main. Tool: entity54_authorize, linear:create-issue.");
  const owner = await startServer(dataDir, "tg:000000000");
  const allowed = await owner.call("entity54_authorize", {
    principal: "tg:000000000", bot: "bot-main", tool: "linear:create-issue",
  });
  show("Result", allowed.parsed);
  console.log("ALLOWED by rule owner-all. The allow decision is receipted before anything executes.");
  await step(15000);

  header("STEP 3: OWNER creates the Linear issue (mock transport)");
  const created = await owner.call("entity54_linear_create_issue", {
    principal: "tg:000000000", bot: "bot-main", teamId: "ENG",
    title: "ENTITY54 demo issue", description: "Created by the reproducible demo.",
  });
  show("Result", created.parsed);
  console.log("EXECUTED. transport is mock and the issue id is mock-issue-1: this is a demo, not a real Linear issue.");
  await step(15000);

  header("STEP 4: the receipt chain verifies");
  const verified = await owner.call("entity54_receipts_verify", { principal: "tg:000000000", bot: "bot-main" });
  show("Result", verified.parsed);
  console.log("ok is true: every receipt hash and HMAC checks out, in order.");
  await step(10000);

  header("STEP 5: the sanitized event feed");
  const events = await owner.call("entity54_events_list", { principal: "tg:000000000", bot: "bot-main", limit: 10 });
  show("Result", events.parsed);
  console.log("No titles, no descriptions, no raw principal ids. Identities are short pseudonym hashes.");
  await step(10000);

  header("RECEIPTS ON DISK");
  const receipts = fs.readFileSync(path.join(dataDir, "receipts.jsonl"), "utf8").trim().split("\n").map((line) => JSON.parse(line));
  for (const receipt of receipts) {
    console.log(`  #${receipt.seq} ${receipt.type} ${receipt.decision} ${receipt.tool} (${receipt.role}, policy v${receipt.policyVersion})`);
  }
  console.log("");
  console.log(`Demo complete in ${Math.round((Date.now() - startedAt.getTime()) / 1000)}s.`);
  console.log("Receipts file: " + path.join(dataDir, "receipts.jsonl"));
  console.log("Re-run any time with: node demo/run-demo.mjs");
  await owner.close();
}

main().catch((error) => {
  console.error(`Demo failed: ${error instanceof Error ? error.message : String(error)}`);
  process.exit(1);
});
