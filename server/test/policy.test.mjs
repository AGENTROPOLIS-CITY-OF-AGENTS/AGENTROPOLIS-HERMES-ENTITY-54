// Policy tests: export, import integrity, replay and downgrade rejection,
// staged-only activation, and OWNER-only activation.
import test from "node:test";
import assert from "node:assert/strict";
import { startServer, testPolicyDoc, TEST_KEY } from "./helpers.mjs";
import { signPolicy } from "../dist/policy.js";

function policyV2() {
  return testPolicyDoc({
    version: 2,
    rules: [
      { id: "owner-all", effect: "allow", role: "OWNER", tool: "*", bot: "*" },
      { id: "admin-linear", effect: "allow", role: "ADMIN", tool: "linear:create-issue", bot: "*" },
      { id: "deny-policy-activation-below-owner", effect: "deny", role: "ADMIN", tool: "policy:activate", bot: "*" },
    ],
  });
}

test("ADMIN can export the active policy; GUEST cannot", async () => {
  const s = await startServer({ principal: "tg:200" });
  try {
    const res = await s.call("entity54_policy_export", { principal: "tg:200", bot: "bot-main" });
    assert.equal(res.isError, false);
    assert.equal(res.parsed.policy.policyId, "entity54-default");
    assert.equal(res.parsed.policy.version, 1);
    assert.equal(res.parsed.policy.integrity.alg, "HMAC-SHA256");
  } finally {
    await s.close();
  }
  const g = await startServer({ principal: "tg:400" });
  try {
    const res = await g.call("entity54_policy_export", { principal: "tg:400", bot: "bot-main" });
    assert.equal(res.isError, true);
    assert.equal(res.parsed.decision, "deny");
  } finally {
    await g.close();
  }
});

test("valid newer policy stages but does not activate until OWNER activates it", async () => {
  const s = await startServer({ principal: "tg:200" });
  try {
    const staged = await s.call("entity54_policy_import", { principal: "tg:200", bot: "bot-main", policy: policyV2() });
    assert.equal(staged.isError, false);
    assert.equal(staged.parsed.decision, "staged");
    assert.equal(staged.parsed.version, 2);
    const status = await s.call("entity54_status", { principal: "tg:200", bot: "bot-main" });
    assert.equal(status.parsed.policyVersion, 1);
    assert.equal(status.parsed.pendingPolicyVersion, 2);
    const userCheck = await s.call("entity54_authorize", { principal: "tg:200", bot: "bot-main", tool: "linear:create-issue" });
    assert.equal(userCheck.parsed.decision, "allow");
  } finally {
    await s.close();
  }
});

test("OWNER activation switches the active policy; the new rules take effect", async () => {
  const s = await startServer({ principal: "tg:100" });
  try {
    const staged = await s.call("entity54_policy_import", { principal: "tg:100", bot: "bot-main", policy: policyV2() });
    assert.equal(staged.parsed.decision, "staged");
    const activated = await s.call("entity54_policy_activate", { principal: "tg:100", bot: "bot-main" });
    assert.equal(activated.isError, false);
    assert.equal(activated.parsed.decision, "activated");
    assert.equal(activated.parsed.version, 2);
    const status = await s.call("entity54_status", { principal: "tg:100", bot: "bot-main" });
    assert.equal(status.parsed.policyVersion, 2);
    assert.equal(status.parsed.pendingPolicyVersion, null);
  } finally {
    await s.close();
  }
});

test("ADMIN cannot activate a staged policy", async () => {
  const admin = await startServer({ principal: "tg:200" });
  try {
    await admin.call("entity54_policy_import", { principal: "tg:200", bot: "bot-main", policy: policyV2() });
    const activated = await admin.call("entity54_policy_activate", { principal: "tg:200", bot: "bot-main" });
    assert.equal(activated.isError, true);
    assert.equal(activated.parsed.decision, "deny");
    const status = await admin.call("entity54_status", { principal: "tg:200", bot: "bot-main" });
    assert.equal(status.parsed.policyVersion, 1);
    assert.equal(status.parsed.pendingPolicyVersion, 2);
  } finally {
    await admin.close();
  }
});

test("replay of the same version is rejected", async () => {
  const s = await startServer({ principal: "tg:100" });
  try {
    const same = testPolicyDoc({ version: 1 });
    const res = await s.call("entity54_policy_import", { principal: "tg:100", bot: "bot-main", policy: same });
    assert.equal(res.isError, true);
    assert.equal(res.parsed.decision, "rejected");
    assert.match(res.parsed.reason, /not newer than active/);
  } finally {
    await s.close();
  }
});

test("downgrade to an older version is rejected after activation", async () => {
  const s = await startServer({ principal: "tg:100" });
  try {
    await s.call("entity54_policy_import", { principal: "tg:100", bot: "bot-main", policy: policyV2() });
    await s.call("entity54_policy_activate", { principal: "tg:100", bot: "bot-main" });
    const old = testPolicyDoc({ version: 1 });
    const res = await s.call("entity54_policy_import", { principal: "tg:100", bot: "bot-main", policy: old });
    assert.equal(res.isError, true);
    assert.equal(res.parsed.decision, "rejected");
    assert.match(res.parsed.reason, /not newer than active/);
  } finally {
    await s.close();
  }
});

test("a tampered policy with a stale HMAC is rejected", async () => {
  const s = await startServer({ principal: "tg:100" });
  try {
    const doc = policyV2();
    doc.rules.push({ id: "attacker-all", effect: "allow", role: "GUEST", tool: "*", bot: "*" });
    const res = await s.call("entity54_policy_import", { principal: "tg:100", bot: "bot-main", policy: doc });
    assert.equal(res.isError, true);
    assert.equal(res.parsed.decision, "rejected");
    assert.match(res.parsed.reason, /integrity check failed/);
  } finally {
    await s.close();
  }
});

test("a policy signed with a different key is rejected", async () => {
  const s = await startServer({ principal: "tg:100" });
  try {
    const base = testPolicyDoc({ version: 2 });
    const wrongKey = signPolicy(
      { policyId: base.policyId, version: 2, issuedAt: base.issuedAt, rules: base.rules },
      "a-completely-different-key"
    );
    const res = await s.call("entity54_policy_import", { principal: "tg:100", bot: "bot-main", policy: wrongKey });
    assert.equal(res.isError, true);
    assert.equal(res.parsed.decision, "rejected");
    assert.match(res.parsed.reason, /integrity check failed/);
  } finally {
    await s.close();
  }
});

test("activation with no staged policy is denied", async () => {
  const s = await startServer({ principal: "tg:100" });
  try {
    const res = await s.call("entity54_policy_activate", { principal: "tg:100", bot: "bot-main" });
    assert.equal(res.isError, true);
    assert.match(res.parsed.reason, /no staged policy/);
  } finally {
    await s.close();
  }
});

test("a staged policy cannot be replaced by an equal or lower version", async () => {
  function policyVersion(version) {
    return testPolicyDoc({
      version,
      rules: [{ id: "owner-all", effect: "allow", role: "OWNER", tool: "*", bot: "*" }],
    });
  }
  const s = await startServer({ principal: "tg:200" });
  try {
    const staged = await s.call("entity54_policy_import", { principal: "tg:200", bot: "bot-main", policy: policyVersion(5) });
    assert.equal(staged.isError, false);
    assert.equal(staged.parsed.decision, "staged");
    assert.equal(staged.parsed.version, 5);
    const lower = await s.call("entity54_policy_import", { principal: "tg:200", bot: "bot-main", policy: policyVersion(3) });
    assert.equal(lower.isError, true);
    assert.equal(lower.parsed.decision, "rejected");
    assert.match(lower.parsed.reason, /not newer than staged version 5/);
    const status = await s.call("entity54_status", { principal: "tg:200", bot: "bot-main" });
    assert.equal(status.parsed.policyVersion, 1);
    assert.equal(status.parsed.pendingPolicyVersion, 5);
    const higher = await s.call("entity54_policy_import", { principal: "tg:200", bot: "bot-main", policy: policyVersion(6) });
    assert.equal(higher.isError, false);
    assert.equal(higher.parsed.decision, "staged");
    assert.equal(higher.parsed.version, 6);
  } finally {
    await s.close();
  }
});

test("startup refuses an unsigned example policy", async () => {
  const { spawn } = await import("node:child_process");
  const { makeDataDir } = await import("./helpers.mjs");
  const fs = await import("node:fs");
  const path = await import("node:path");
  const dir = makeDataDir();
  const unsigned = JSON.parse(fs.readFileSync(new URL("../../config/entity54.policy.example.json", import.meta.url), "utf8"));
  fs.writeFileSync(path.join(dir, "entity54.policy.json"), `${JSON.stringify(unsigned, null, 2)}\n`);
  const child = spawn(process.execPath, [new URL("../dist/index.js", import.meta.url).pathname], {
    env: {
      ...process.env,
      ENTITY54_DATA_DIR: dir,
      ENTITY54_PRINCIPAL_ID: "tg:100",
      ENTITY54_BOT_ID: "bot-main",
      ENTITY54_POLICY_KEY: TEST_KEY,
    },
    stdio: ["ignore", "ignore", "pipe"],
  });
  const code = await new Promise((resolve) => {
    const timer = setTimeout(() => { child.kill(); resolve(null); }, 5000);
    child.on("exit", (c) => { clearTimeout(timer); resolve(c); });
  });
  assert.notEqual(code, 0, "server must exit non-zero on an unverified policy");
});
