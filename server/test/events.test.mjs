// Event feed tests: disabled by default, sanitized content, pseudonymized
// identities, viewer-scoped visibility, pagination, retention cap.
import test from "node:test";
import assert from "node:assert/strict";
import { startServer, readEvents } from "./helpers.mjs";
import { EventStore } from "../dist/events.js";
import { pseudonym } from "../dist/crypto.js";
import { loadConfig, ConfigError, eventsFeedDenial } from "../dist/config.js";
import * as os from "node:os";
import * as path from "node:path";
import * as fs from "node:fs";

test("the feed is disabled by default and refuses to list", async () => {
  const s = await startServer({ principal: "tg:100" });
  try {
    const res = await s.call("entity54_events_list", { principal: "tg:100", bot: "bot-main" });
    assert.equal(res.isError, true);
    assert.match(res.parsed.reason, /disabled/);
  } finally {
    await s.close();
  }
});

test("when enabled, events are sanitized: no titles, no content, no raw ids", async () => {
  const s = await startServer({ principal: "tg:100", eventsEnabled: true });
  try {
    await s.call("entity54_linear_create_issue", {
      principal: "tg:100", bot: "bot-main", teamId: "ENG",
      title: "Secret project codename Zebra", description: "Do not leak this sentence",
    });
    await s.call("entity54_authorize", { principal: "tg:100", bot: "bot-main", tool: "entity54:read" });
    const res = await s.call("entity54_events_list", { principal: "tg:100", bot: "bot-main", limit: 10 });
    assert.equal(res.isError, false);
    assert.ok(res.parsed.total >= 3);
    const raw = JSON.stringify(res.parsed);
    assert.equal(raw.includes("Secret project codename Zebra"), false);
    assert.equal(raw.includes("Do not leak this sentence"), false);
    assert.equal(raw.includes("tg:100"), false);
    assert.equal(raw.includes("test-policy-key"), false);
    for (const event of res.parsed.events) {
      assert.match(event.principalHash, /^[0-9a-f]{16}$/);
      assert.ok([
        "authorization_allowed", "authorization_denied", "tool_execution_started",
        "tool_execution_succeeded", "tool_execution_failed", "policy_installed",
        "policy_rejected", "approval_requested", "approval_resolved",
      ].includes(event.category));
      assert.equal(typeof event.tool, "string");
      assert.ok(!("title" in event));
      assert.ok(!("description" in event));
    }
  } finally {
    await s.close();
  }
});

test("the same principal always maps to the same pseudonym", async () => {
  const s = await startServer({ principal: "tg:100", eventsEnabled: true });
  try {
    await s.call("entity54_authorize", { principal: "tg:100", bot: "bot-main", tool: "entity54:read" });
    await s.call("entity54_authorize", { principal: "tg:100", bot: "bot-main", tool: "entity54:read" });
    const res = await s.call("entity54_events_list", { principal: "tg:100", bot: "bot-main", limit: 10 });
    const hashes = new Set(res.parsed.events.map((e) => e.principalHash));
    assert.equal(hashes.size, 1);
  } finally {
    await s.close();
  }
});

test("a GUEST viewer sees only their own events in a shared store (unit)", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "entity54-events-"));
  const key = "test-pseudonym-key-0123456789abcdef";
  const store = new EventStore(dir, key, 1000);
  store.record({ category: "authorization", tool: "entity54:read", principal: "tg:100", bot: "bot-main", decision: "allow", receiptSeq: 1, detail: "read" });
  store.record({ category: "authorization", tool: "entity54:read", principal: "tg:400", bot: "bot-main", decision: "allow", receiptSeq: 2, detail: "read" });
  store.record({ category: "authorization", tool: "linear:create-issue", principal: "tg:400", bot: "bot-main", decision: "deny", receiptSeq: 3, detail: "denied" });
  const guestHash = pseudonym(key, "tg:400");
  const guestView = store.list({
    viewerPrincipal: "tg:400", viewerRole: "GUEST", viewerBot: "bot-main", limit: 100, offset: 0,
  });
  assert.equal(guestView.total, 2);
  assert.ok(guestView.events.every((e) => e.principalHash === guestHash));
  const raw = JSON.stringify(guestView);
  assert.equal(raw.includes("tg:100"), false);
  assert.equal(raw.includes("tg:400"), false);
});

test("category filter and pagination work", async () => {
  const s = await startServer({ principal: "tg:100", eventsEnabled: true });
  try {
    await s.call("entity54_authorize", { principal: "tg:100", bot: "bot-main", tool: "entity54:read" });
    await s.call("entity54_linear_create_issue", { principal: "tg:100", bot: "bot-main", teamId: "ENG", title: "Pagination issue" });
    const auth = await s.call("entity54_events_list", { principal: "tg:100", bot: "bot-main", category: "authorization_allowed", limit: 100 });
    assert.ok(auth.parsed.events.every((e) => e.category === "authorization_allowed"));
    const page1 = await s.call("entity54_events_list", { principal: "tg:100", bot: "bot-main", limit: 1, offset: 0 });
    assert.equal(page1.parsed.events.length, 1);
    assert.ok(page1.parsed.total >= 3);
    assert.equal(page1.parsed.limit, 1);
    assert.equal(page1.parsed.offset, 0);
  } finally {
    await s.close();
  }
});

test("GUEST sees no events when the pseudonym key is unset (P5b)", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "entity54-events-"));
  const store = new EventStore(dir, null);
  store.record({ category: "tool_execution_succeeded", tool: "linear:create-issue", principal: "tg:100", bot: "bot-main", decision: "success", receiptRef: 1 });
  store.record({ category: "authorization_allowed", tool: "entity54:read", principal: "tg:300", bot: "bot-main", decision: "allow", receiptRef: 2 });
  store.record({ category: "authorization_denied", tool: "linear:create-issue", principal: "tg:400", bot: "bot-main", decision: "deny", receiptRef: 3 });
  const guest = store.list({
    viewerPrincipal: "tg:400", viewerRole: "GUEST", viewerBot: "bot-main", limit: 100, offset: 0,
  });
  assert.equal(guest.total, 0);
  assert.deepEqual(guest.events, []);
  const owner = store.list({
    viewerPrincipal: "tg:100", viewerRole: "OWNER", viewerBot: "bot-main", limit: 100, offset: 0,
  });
  assert.equal(owner.total, 0);
  const user = store.list({
    viewerPrincipal: "tg:300", viewerRole: "USER", viewerBot: "bot-main", limit: 100, offset: 0,
  });
  assert.equal(user.total, 0);
  const raw = fs.readFileSync(path.join(dir, "events.jsonl"), "utf8");
  assert.equal(raw.includes("\"unkeyed\""), false);
  assert.equal(raw.includes("tg:100"), false);
  assert.equal(raw.includes("tg:300"), false);
  assert.equal(raw.includes("tg:400"), false);
});

test("with a pseudonym key, a GUEST sees only their own events", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "entity54-events-"));
  const key = "test-pseudonym-key-0123456789abcdef";
  const store = new EventStore(dir, key);
  store.record({ category: "tool_execution_succeeded", tool: "linear:create-issue", principal: "tg:100", bot: "bot-main", decision: "success", receiptRef: 1 });
  store.record({ category: "authorization_allowed", tool: "entity54:read", principal: "tg:300", bot: "bot-main", decision: "allow", receiptRef: 2 });
  store.record({ category: "authorization_denied", tool: "linear:create-issue", principal: "tg:400", bot: "bot-main", decision: "deny", receiptRef: 3 });
  store.record({ category: "authorization_allowed", tool: "entity54:events-list", principal: "tg:400", bot: "bot-main", decision: "allow", receiptRef: 4 });
  const guestHash = pseudonym(key, "tg:400");
  const guest = store.list({
    viewerPrincipal: "tg:400", viewerRole: "GUEST", viewerBot: "bot-main", limit: 100, offset: 0,
  });
  assert.equal(guest.total, 2);
  assert.ok(guest.events.every((event) => event.principalHash === guestHash));
  assert.equal(JSON.stringify(guest).includes("tg:100"), false);
  const owner = store.list({
    viewerPrincipal: "tg:100", viewerRole: "OWNER", viewerBot: "bot-main", limit: 100, offset: 0,
  });
  assert.equal(owner.total, 4);
});

test("enabling the event feed without a pseudonym key is refused", () => {
  assert.throws(
    () => loadConfig({
      ENTITY54_PRINCIPAL_ID: "tg:100",
      ENTITY54_BOT_ID: "bot-main",
      ENTITY54_POLICY_KEY: "test-policy-key",
      ENTITY54_EVENTS_ENABLED: "true",
    }),
    (err) => err instanceof ConfigError && /PSEUDONYM_KEY/.test(err.message)
  );
  const disabled = loadConfig({
    ENTITY54_PRINCIPAL_ID: "tg:100",
    ENTITY54_BOT_ID: "bot-main",
    ENTITY54_POLICY_KEY: "test-policy-key",
  });
  assert.equal(disabled.eventsEnabled, false);
  assert.equal(disabled.pseudonymKey, null);
  assert.match(eventsFeedDenial(true, null), /PSEUDONYM_KEY/);
  assert.equal(eventsFeedDenial(true, "key"), null);
  assert.match(eventsFeedDenial(false, null), /disabled/);
});

test("startup refuses ENTITY54_EVENTS_ENABLED=true without ENTITY54_PSEUDONYM_KEY", async () => {
  const { spawn } = await import("node:child_process");
  const { makeDataDir } = await import("./helpers.mjs");
  const dir = makeDataDir();
  const env = {
    ...process.env,
    ENTITY54_DATA_DIR: dir,
    ENTITY54_PRINCIPAL_ID: "tg:100",
    ENTITY54_BOT_ID: "bot-main",
    ENTITY54_POLICY_KEY: "test-policy-key-0123456789abcdef",
    ENTITY54_EVENTS_ENABLED: "true",
  };
  delete env.ENTITY54_PSEUDONYM_KEY;
  const child = spawn(process.execPath, [new URL("../dist/index.js", import.meta.url).pathname], {
    env,
    stdio: ["ignore", "ignore", "pipe"],
  });
  let stderr = "";
  child.stderr.on("data", (chunk) => { stderr += chunk.toString(); });
  const code = await new Promise((resolve) => {
    const timer = setTimeout(() => { child.kill(); resolve(null); }, 5000);
    child.on("exit", (c) => { clearTimeout(timer); resolve(c); });
  });
  assert.equal(code, 2);
  assert.match(stderr, /PSEUDONYM_KEY/);
});

test("events_list echoes the clamped limit and offset", async () => {
  const s = await startServer({ principal: "tg:100", eventsEnabled: true });
  try {
    const low = await s.call("entity54_events_list", { principal: "tg:100", bot: "bot-main", limit: -5, offset: -3 });
    assert.equal(low.isError, false);
    assert.equal(low.parsed.limit, 1);
    assert.equal(low.parsed.offset, 0);
    const high = await s.call("entity54_events_list", { principal: "tg:100", bot: "bot-main", limit: 100000, offset: 5 });
    assert.equal(high.isError, false);
    assert.equal(high.parsed.limit, 100);
    assert.equal(high.parsed.offset, 5);
  } finally {
    await s.close();
  }
});

test("retention is capped at 1000 events (unit)", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "entity54-events-"));
  const store = new EventStore(dir, "test-pseudonym-key-0123456789abcdef", 1000);
  for (let i = 0; i < 1050; i++) {
    store.record({ category: "authorization", tool: "entity54:read", principal: "tg:100", bot: "bot-main", decision: "allow", receiptSeq: i + 1, detail: "read" });
  }
  const { total } = store.list({ viewerPrincipal: "tg:100", viewerRole: "OWNER", viewerBot: "bot-main", limit: 1, offset: 0 });
  assert.equal(total, 1000);
  const stored = readEvents(dir);
  assert.equal(stored.length, 1000);
  assert.equal(stored[0].seq, 51);
  assert.equal(stored[stored.length - 1].seq, 1050);
});
