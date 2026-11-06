// Receipt tests: hash-chain integrity, HMAC integrity, tamper detection,
// and the guarantee that a denial is receipted before any execution.
import test from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as path from "node:path";
import { startServer, readReceipts, TEST_KEY } from "./helpers.mjs";
import { ReceiptStore } from "../dist/receipts.js";
import * as os from "node:os";

test("every decision writes a receipt and the chain verifies", async () => {
  const s = await startServer({ principal: "tg:100" });
  try {
    await s.call("entity54_authorize", { principal: "tg:100", bot: "bot-main", tool: "linear:create-issue" });
    await s.call("entity54_linear_create_issue", { principal: "tg:100", bot: "bot-main", teamId: "ENG", title: "Receipt chain issue" });
    const verify = await s.call("entity54_receipts_verify", { principal: "tg:100", bot: "bot-main" });
    assert.equal(verify.isError, false);
    assert.equal(verify.parsed.ok, true);
    assert.equal(verify.parsed.checked, 3);
    const receipts = readReceipts(s.dataDir);
    // The successful verify call receipts itself after the check, so the
    // checked count is the chain that was verified and the file has one more.
    assert.equal(receipts.length, 4);
    assert.equal(receipts[3].tool, "entity54:receipts-verify");
    assert.equal(receipts[3].decision, "allow");
    assert.equal(receipts[0].seq, 1);
    assert.equal(receipts[0].prevHash, "GENESIS");
    assert.equal(receipts[1].prevHash, receipts[0].hash);
    assert.equal(receipts[2].prevHash, receipts[1].hash);
    assert.equal(receipts[3].prevHash, receipts[2].hash);
  } finally {
    await s.close();
  }
});

test("a denied operation writes an authorization receipt and no execution receipt", async () => {
  const s = await startServer({ principal: "tg:400" });
  try {
    const res = await s.call("entity54_linear_create_issue", { principal: "tg:400", bot: "bot-main", teamId: "ENG", title: "Guest issue" });
    assert.equal(res.parsed.decision, "deny");
    assert.equal(res.parsed.executed, false);
    const receipts = readReceipts(s.dataDir);
    assert.equal(receipts.length, 1);
    assert.equal(receipts[0].type, "authorization");
    assert.equal(receipts[0].decision, "deny");
    assert.equal(receipts[0].tool, "linear:create-issue");
  } finally {
    await s.close();
  }
});

test("tampering with a receipt detail breaks verification at that sequence", async () => {
  const s = await startServer({ principal: "tg:100" });
  try {
    await s.call("entity54_authorize", { principal: "tg:100", bot: "bot-main", tool: "linear:create-issue" });
    await s.call("entity54_linear_create_issue", { principal: "tg:100", bot: "bot-main", teamId: "ENG", title: "Tamper test" });
    const file = path.join(s.dataDir, "receipts.jsonl");
    const lines = fs.readFileSync(file, "utf8").split("\n").filter(Boolean);
    const tampered = JSON.parse(lines[1]);
    tampered.detail = "issue forged-issue-1 created via live transport";
    lines[1] = JSON.stringify(tampered);
    fs.writeFileSync(file, `${lines.join("\n")}\n`);
    const verify = await s.call("entity54_receipts_verify", { principal: "tg:100", bot: "bot-main" });
    assert.equal(verify.parsed.ok, false);
    assert.equal(verify.parsed.badSeq, 2);
    assert.match(verify.parsed.reason, /hash mismatch/);
  } finally {
    await s.close();
  }
});

test("deleting a receipt breaks the chain at the next sequence", async () => {
  const s = await startServer({ principal: "tg:100" });
  try {
    await s.call("entity54_authorize", { principal: "tg:100", bot: "bot-main", tool: "linear:create-issue" });
    await s.call("entity54_linear_create_issue", { principal: "tg:100", bot: "bot-main", teamId: "ENG", title: "Delete test" });
    await s.call("entity54_authorize", { principal: "tg:100", bot: "bot-main", tool: "entity54:read" });
    const file = path.join(s.dataDir, "receipts.jsonl");
    const lines = fs.readFileSync(file, "utf8").split("\n").filter(Boolean);
    lines.splice(1, 1);
    fs.writeFileSync(file, `${lines.join("\n")}\n`);
    const verify = await s.call("entity54_receipts_verify", { principal: "tg:100", bot: "bot-main" });
    assert.equal(verify.parsed.ok, false);
    assert.equal(verify.parsed.badSeq, 3);
  } finally {
    await s.close();
  }
});

function sample(detail) {
  return {
    ts: "2026-11-06T00:00:00.000Z",
    type: "authorization",
    decision: "deny",
    principal: "tg:100",
    role: "OWNER",
    bot: "bot-main",
    tool: "entity54:read",
    policyVersion: 1,
    detail,
  };
}

function freshStore() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "entity54-anchor-"));
  return { dir, store: new ReceiptStore(dir, TEST_KEY) };
}

test("an intact receipt chain passes verification against its anchor", () => {
  const { store } = freshStore();
  assert.deepEqual(store.verify(), { ok: true, checked: 0, badSeq: null, reason: "chain intact" });
  store.append(sample("one"));
  store.append(sample("two"));
  const result = store.verify();
  assert.equal(result.ok, true);
  assert.equal(result.checked, 2);
  assert.equal(result.badSeq, null);
  assert.equal(result.reason, "chain intact");
});

test("deleting the last receipt fails verification", () => {
  const { dir, store } = freshStore();
  store.append(sample("one"));
  store.append(sample("two"));
  store.append(sample("three"));
  store.append(sample("four"));
  const file = path.join(dir, "receipts.jsonl");
  const lines = fs.readFileSync(file, "utf8").split("\n").filter(Boolean);
  lines.pop();
  fs.writeFileSync(file, `${lines.join("\n")}\n`);
  const result = store.verify();
  assert.equal(result.ok, false);
  assert.match(result.reason, /tail truncation/);
  assert.equal(result.badSeq, 4);
});

test("emptying the receipt log fails verification when an anchor exists", () => {
  const { dir, store } = freshStore();
  store.append(sample("one"));
  store.append(sample("two"));
  fs.writeFileSync(path.join(dir, "receipts.jsonl"), "");
  const result = store.verify();
  assert.equal(result.ok, false);
  assert.match(result.reason, /tail truncation/);
  assert.match(result.reason, /empty/);
  const reloaded = new ReceiptStore(dir, TEST_KEY);
  assert.equal(reloaded.verify().ok, false);
  assert.throws(() => reloaded.append(sample("heal")), /failed closed/);
});

test("deleting a middle receipt still fails verification", () => {
  const { dir, store } = freshStore();
  store.append(sample("one"));
  store.append(sample("two"));
  store.append(sample("three"));
  store.append(sample("four"));
  const file = path.join(dir, "receipts.jsonl");
  const lines = fs.readFileSync(file, "utf8").split("\n").filter(Boolean);
  lines.splice(1, 1);
  fs.writeFileSync(file, `${lines.join("\n")}\n`);
  const result = store.verify();
  assert.equal(result.ok, false);
  assert.equal(result.badSeq, 3);
  assert.match(result.reason, /hash mismatch|chain break/);
});

test("a tampered receipt anchor fails verification", () => {
  const { dir, store } = freshStore();
  store.append(sample("one"));
  const anchorPath = path.join(dir, "receipts.anchor.json");
  const anchor = JSON.parse(fs.readFileSync(anchorPath, "utf8"));
  anchor.lastSeq = 99;
  fs.writeFileSync(anchorPath, `${JSON.stringify(anchor)}\n`);
  const result = store.verify();
  assert.equal(result.ok, false);
  assert.match(result.reason, /anchor HMAC mismatch/);
});

test("allowed export, status, verify, and a disabled event list are receipted", async () => {
  const s = await startServer({ principal: "tg:100" });
  try {
    const exported = await s.call("entity54_policy_export", { principal: "tg:100", bot: "bot-main" });
    assert.equal(exported.isError, false);
    assert.equal(typeof exported.parsed.receiptSeq, "number");
    const status = await s.call("entity54_status", { principal: "tg:100", bot: "bot-main" });
    assert.equal(status.isError, false);
    assert.equal(typeof status.parsed.receiptSeq, "number");
    const verified = await s.call("entity54_receipts_verify", { principal: "tg:100", bot: "bot-main" });
    assert.equal(verified.parsed.ok, true);
    assert.equal(typeof verified.parsed.receiptSeq, "number");
    const events = await s.call("entity54_events_list", { principal: "tg:100", bot: "bot-main" });
    assert.equal(events.isError, true);
    assert.match(events.parsed.reason, /disabled/);
    assert.equal(typeof events.parsed.receiptSeq, "number");
    const receipts = readReceipts(s.dataDir);
    assert.ok(receipts.some((r) => r.tool === "policy:export" && r.decision === "allow"));
    assert.ok(receipts.some((r) => r.tool === "entity54:status" && r.decision === "allow"));
    assert.ok(receipts.some((r) => r.tool === "entity54:receipts-verify" && r.decision === "allow"));
    assert.ok(receipts.some((r) => r.tool === "entity54:events-list" && r.decision === "deny"));
  } finally {
    await s.close();
  }
});

test("an unexposed MCP tool name is denied and receipted", async () => {
  const s = await startServer({ principal: "tg:100" });
  try {
    const res = await s.call("entity54_delete_everything", { principal: "tg:100", bot: "bot-main" });
    assert.equal(res.isError, true);
    assert.equal(res.parsed.decision, "deny");
    assert.match(res.parsed.reason, /unknown tool/);
    const receipts = readReceipts(s.dataDir);
    assert.equal(receipts.length, 1);
    assert.equal(receipts[0].decision, "deny");
    assert.equal(receipts[0].principal, "tg:100");
    assert.equal(receipts[0].role, "OWNER");
    assert.equal(receipts[0].bot, "bot-main");
    assert.equal(receipts[0].tool, "entity54_delete_everything");
  } finally {
    await s.close();
  }
});

test("outer-catch denials record the gateway-asserted identity and the claimed identity separately", async () => {
  const s = await startServer({ principal: "tg:100" });
  try {
    const spoof = await s.call("entity54_authorize", { principal: "tg:999", bot: "bot-main", tool: "linear:create-issue" });
    assert.equal(spoof.parsed.decision, "deny");
    assert.equal(spoof.parsed.code, "spoofing");
    const receipts = readReceipts(s.dataDir);
    assert.equal(receipts.length, 1);
    assert.equal(receipts[0].principal, "tg:100");
    assert.equal(receipts[0].role, "OWNER");
    assert.equal(receipts[0].bot, "bot-main");
    assert.match(receipts[0].detail, /claimedPrincipal=tg:999/);
    assert.match(receipts[0].detail, /claimedBot=bot-main/);
    assert.equal(receipts[0].role === "unknown", false);
  } finally {
    await s.close();
  }
});

test("invalid Linear input after an allow is an execution failure with the caller role", async () => {
  const s = await startServer({ principal: "tg:100" });
  try {
    const res = await s.call("entity54_linear_create_issue", {
      principal: "tg:100", bot: "bot-main", teamId: "ENG", title: "",
    });
    assert.equal(res.parsed.decision, "allow");
    assert.equal(res.parsed.executed, false);
    assert.equal(res.parsed.errorCode, "invalid_input");
    const receipts = readReceipts(s.dataDir);
    const failure = receipts.find((r) => r.type === "execution" && r.decision === "failure");
    assert.ok(failure);
    assert.equal(failure.role, "OWNER");
    assert.equal(failure.principal, "tg:100");
    assert.match(failure.detail, /title is required/);
    assert.equal(receipts.some((r) => r.role === "unknown"), false);
    assert.equal(receipts.some((r) => r.detail.includes("internal_error")), false);
  } finally {
    await s.close();
  }
});

test("receipts never contain a Linear API key or a policy key", async () => {
  const s = await startServer({ principal: "tg:100" });
  try {
    await s.call("entity54_linear_create_issue", { principal: "tg:100", bot: "bot-main", teamId: "ENG", title: "Key leak check" });
    const raw = fs.readFileSync(path.join(s.dataDir, "receipts.jsonl"), "utf8");
    const anchor = fs.readFileSync(path.join(s.dataDir, "receipts.anchor.json"), "utf8");
    assert.equal(raw.includes("test-policy-key"), false);
    assert.equal(raw.includes("LINEAR_API_KEY"), false);
    assert.equal(anchor.includes("test-policy-key"), false);
  } finally {
    await s.close();
  }
});
