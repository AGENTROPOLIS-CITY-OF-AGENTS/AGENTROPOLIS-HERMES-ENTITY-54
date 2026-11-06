// Receipt tests: hash-chain integrity, HMAC integrity, tamper detection,
// and the guarantee that a denial is receipted before any execution.
import test from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as path from "node:path";
import { startServer, readReceipts } from "./helpers.mjs";

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
    assert.equal(receipts.length, 3);
    assert.equal(receipts[0].seq, 1);
    assert.equal(receipts[0].prevHash, "GENESIS");
    assert.equal(receipts[1].prevHash, receipts[0].hash);
    assert.equal(receipts[2].prevHash, receipts[1].hash);
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

test("receipts never contain a Linear API key or a policy key", async () => {
  const s = await startServer({ principal: "tg:100" });
  try {
    await s.call("entity54_linear_create_issue", { principal: "tg:100", bot: "bot-main", teamId: "ENG", title: "Key leak check" });
    const raw = fs.readFileSync(path.join(s.dataDir, "receipts.jsonl"), "utf8");
    assert.equal(raw.includes("test-policy-key"), false);
    assert.equal(raw.includes("LINEAR_API_KEY"), false);
  } finally {
    await s.close();
  }
});
