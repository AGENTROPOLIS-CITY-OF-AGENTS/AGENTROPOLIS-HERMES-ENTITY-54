// Linear tests: mock transport behavior, authorization before execution,
// fail-closed when unconfigured, timeout, and HTTP failure handling.
import test from "node:test";
import assert from "node:assert/strict";
import { startServer, readReceipts } from "./helpers.mjs";
import { createLinearClient, LinearError, validateIssueInput } from "../dist/linear.js";

test("mock transport returns a labelled mock issue for an allowed principal", async () => {
  const s = await startServer({ principal: "tg:200" });
  try {
    const res = await s.call("entity54_linear_create_issue", {
      principal: "tg:200", bot: "bot-main", teamId: "ENG", title: "Mock issue", description: "demo",
    });
    assert.equal(res.isError, false);
    assert.equal(res.parsed.executed, true);
    assert.equal(res.parsed.transport, "mock");
    assert.equal(res.parsed.issueId, "mock-issue-1");
    assert.equal(res.parsed.url, "mock://linear/mock-issue-1");
  } finally {
    await s.close();
  }
});

test("a denied Linear request never executes: no execution receipt exists", async () => {
  const s = await startServer({ principal: "tg:400" });
  try {
    const res = await s.call("entity54_linear_create_issue", {
      principal: "tg:400", bot: "bot-main", teamId: "ENG", title: "Guest Linear issue",
    });
    assert.equal(res.parsed.executed, false);
    const receipts = readReceipts(s.dataDir);
    assert.equal(receipts.filter((r) => r.type === "execution").length, 0);
    assert.equal(receipts.filter((r) => r.type === "authorization").length, 1);
  } finally {
    await s.close();
  }
});

test("live transport without a Linear key fails closed after authorization", async () => {
  const s = await startServer({ principal: "tg:100", transport: "live" });
  try {
    const res = await s.call("entity54_linear_create_issue", {
      principal: "tg:100", bot: "bot-main", teamId: "ENG", title: "No key issue",
    });
    assert.equal(res.isError, true);
    assert.equal(res.parsed.decision, "allow");
    assert.equal(res.parsed.executed, false);
    assert.equal(res.parsed.errorCode, "not_configured");
    assert.match(res.parsed.reason, /LINEAR_API_KEY/);
    const receipts = readReceipts(s.dataDir);
    assert.equal(receipts.some((r) => r.type === "execution" && r.decision === "failure"), true);
  } finally {
    await s.close();
  }
});

test("live transport parses a stubbed issueCreate response (no network)", async () => {
  const client = createLinearClient({
    transport: "live",
    apiKey: "lin_api_test",
    timeoutMs: 1000,
    fetchImpl: async () => new Response(JSON.stringify({
      data: { issueCreate: { success: true, issue: { id: "real-issue-42", identifier: "ENG-42", url: "https://linear.app/team/issue/ENG-42" } } },
    }), { status: 200, headers: { "content-type": "application/json" } }),
  });
  const issue = await client.createIssue({ teamId: "ENG", title: "Unit issue" });
  assert.equal(issue.issueId, "real-issue-42");
  assert.equal(issue.url, "https://linear.app/team/issue/ENG-42");
  assert.equal(issue.transport, "live");
});

test("live transport HTTP failure is a LinearError, not a silent success", async () => {
  const client = createLinearClient({
    transport: "live",
    apiKey: "lin_api_test",
    timeoutMs: 1000,
    fetchImpl: async () => new Response("forbidden", { status: 403 }),
  });
  await assert.rejects(
    () => client.createIssue({ teamId: "ENG", title: "Unit issue" }),
    (err) => err instanceof LinearError && err.code === "linear_http"
  );
});

test("live transport timeout is a LinearError with code timeout", async () => {
  const client = createLinearClient({
    transport: "live",
    apiKey: "lin_api_test",
    timeoutMs: 50,
    fetchImpl: () => new Promise(() => {}),
  });
  await assert.rejects(
    () => client.createIssue({ teamId: "ENG", title: "Unit issue" }),
    (err) => err instanceof LinearError && err.code === "timeout"
  );
});

test("live transport body read shares the fetch timeout", async () => {
  const client = createLinearClient({
    transport: "live",
    apiKey: "lin_api_test",
    timeoutMs: 50,
    fetchImpl: async () => ({
      ok: true,
      status: 200,
      text: () => new Promise(() => {}),
    }),
  });
  const result = await Promise.race([
    client.createIssue({ teamId: "ENG", title: "Unit issue" }).then(
      () => "resolved",
      (err) => err
    ),
    new Promise((resolve) => setTimeout(() => resolve("hung"), 1500)),
  ]);
  assert.equal(result instanceof LinearError, true);
  assert.equal(result.code, "timeout");
});

test("live transport without a key throws not_configured before any fetch", async () => {
  const client = createLinearClient({ transport: "live", timeoutMs: 1000 });
  await assert.rejects(
    () => client.createIssue({ teamId: "ENG", title: "Unit issue" }),
    (err) => err instanceof LinearError && err.code === "not_configured"
  );
});

test("issue input validation rejects empty title, overlong title, bad priority", () => {
  assert.throws(() => validateIssueInput({ teamId: "ENG", title: "" }), /title is required/);
  assert.throws(() => validateIssueInput({ teamId: "ENG", title: "x".repeat(257) }), /256 characters/);
  assert.throws(() => validateIssueInput({ teamId: "ENG", title: "ok", priority: 9 }), /priority must be an integer from 0 to 4/);
  assert.throws(() => validateIssueInput({ teamId: "", title: "ok" }), /teamId is required/);
  const clean = validateIssueInput({ teamId: "ENG", title: "  ok  ", description: "d", priority: 2 });
  assert.equal(clean.title, "ok");
  assert.equal(clean.priority, 2);
});
