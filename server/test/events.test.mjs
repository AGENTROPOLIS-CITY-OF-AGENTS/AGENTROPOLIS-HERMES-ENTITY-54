// Event feed tests: disabled by default, sanitized content, pseudonymized
// identities, viewer-scoped visibility, pagination, retention cap.
import test from "node:test";
import assert from "node:assert/strict";
import { startServer, readEvents } from "./helpers.mjs";
import { EventStore } from "../dist/events.js";
import { pseudonym } from "../dist/crypto.js";
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
