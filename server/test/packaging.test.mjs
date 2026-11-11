// Packaging tests: plugin.json and mcp.json conform to the Agent Plugins
// 1.0.0 standard, no secrets in static manifests, skill present, and the
// server refuses to start without its policy key.
import test from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import { spawn } from "node:child_process";
import { makeDataDir } from "./helpers.mjs";
import { fileURLToPath } from "node:url";

const PLUGIN_ROOT = fileURLToPath(new URL("../..", import.meta.url));

function readJson(rel) {
  return JSON.parse(fs.readFileSync(`${PLUGIN_ROOT}${rel}`, "utf8"));
}

test("plugin.json conforms to Agent Plugins 1.0.0 (required fields, closed schema)", () => {
  const doc = readJson("plugin.json");
  assert.equal(doc.$schema, "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json");
  // Schema name pattern, fetched from agent-plugins.org 2026-11-05:
  // ^(?!.*(?:--|\.\.))[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$, max length 64.
  assert.match(doc.name, /^(?!.*(?:--|\.\.))[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/);
  assert.ok(doc.name.length >= 1 && doc.name.length <= 64);
  assert.equal(typeof doc.description, "string");
  assert.ok(doc.description.length > 0);
  assert.match(doc.version, /^\d+\.\d+\.\d+$/);
  // The schema types author as an object with name, email, url only.
  assert.equal(typeof doc.author, "object");
  assert.equal(doc.author !== null && !Array.isArray(doc.author), true);
  for (const key of Object.keys(doc.author)) {
    assert.ok(["name", "email", "url"].includes(key), `unexpected author key: ${key}`);
    assert.equal(typeof doc.author[key], "string");
  }
  const allowed = new Set(["$schema", "name", "description", "version", "author", "license", "homepage", "repository", "keywords", "extensions"]);
  for (const key of Object.keys(doc)) {
    assert.ok(allowed.has(key), `unexpected key in plugin.json: ${key}`);
  }
});

test("mcp.json conforms to the MCP schema and declares a stdio server", () => {
  const doc = readJson("mcp.json");
  assert.equal(doc.$schema, "https://agent-plugins.org/schemas/1.0.0/mcp.schema.json");
  const server = doc.mcpServers?.entity54;
  assert.ok(server, "mcpServers.entity54 must exist");
  assert.equal(server.type, "stdio");
  assert.equal(server.command, "node");
  assert.ok(server.args.some((a) => a.includes("${PLUGIN_ROOT}/server/dist/index.js")));
  // Schema cwd pattern: ^(?:\./|\$\{PLUGIN_ROOT\}(?:/|$)|\$\{PLUGIN_DATA\}(?:/|$))
  assert.match(server.cwd, /^(?:\.\/|\$\{PLUGIN_ROOT\}(?:\/|$)|\$\{PLUGIN_DATA\}(?:\/|$))/);
  assert.equal(server.env?.ENTITY54_DATA_DIR, "${PLUGIN_DATA}/entity54");
  for (const [key, value] of Object.entries(server.env ?? {})) {
    assert.equal(key.startsWith("PLUGIN_"), false);
    assert.equal(String(value).includes("lin_api"), false);
    assert.equal(String(value).includes("sk-"), false);
  }
  // Schema: stdio server allows only type, command, args, env, cwd.
  for (const key of Object.keys(server)) {
    assert.ok(["type", "command", "args", "env", "cwd"].includes(key), `unexpected mcp server key: ${key}`);
  }
});

test("static manifests contain no secrets", () => {
  for (const rel of ["plugin.json", "mcp.json"]) {
    const raw = fs.readFileSync(`${PLUGIN_ROOT}${rel}`, "utf8");
    assert.equal(raw.includes("lin_api"), false, rel);
    assert.equal(raw.includes("sk-"), false, rel);
    assert.equal(raw.includes("ghp_"), false, rel);
    assert.equal(raw.includes("test-policy-key"), false, rel);
  }
});

test("the authorization skill exists and names the authorize tool", () => {
  const skill = fs.readFileSync(`${PLUGIN_ROOT}skills/entity54-authorization/SKILL.md`, "utf8");
  assert.match(skill, /entity54_authorize/);
  assert.match(skill, /default-deny/i);
  assert.match(skill, /never present a different principal/i);
});

test("the server build output exists", () => {
  assert.ok(fs.existsSync(`${PLUGIN_ROOT}server/dist/index.js`));
  assert.ok(fs.existsSync(`${PLUGIN_ROOT}server/dist/policy.js`));
  assert.ok(fs.existsSync(`${PLUGIN_ROOT}server/dist/receipts.js`));
  assert.ok(fs.existsSync(`${PLUGIN_ROOT}server/dist/events.js`));
  assert.ok(fs.existsSync(`${PLUGIN_ROOT}server/dist/linear.js`));
});

test("startup refuses to run without ENTITY54_POLICY_KEY", async () => {
  const dir = makeDataDir();
  const env = { ...process.env, ENTITY54_DATA_DIR: dir, ENTITY54_PRINCIPAL_ID: "tg:100", ENTITY54_BOT_ID: "bot-main" };
  delete env.ENTITY54_POLICY_KEY;
  const child = spawn(process.execPath, [`${PLUGIN_ROOT}server/dist/index.js`], { env, stdio: ["ignore", "ignore", "pipe"] });
  const code = await new Promise((resolve) => {
    const timer = setTimeout(() => { child.kill(); resolve(null); }, 5000);
    child.on("exit", (c) => { clearTimeout(timer); resolve(c); });
  });
  assert.notEqual(code, 0, "server must exit non-zero without a policy key");
});

test("startup refuses to run without an asserted principal", async () => {
  const dir = makeDataDir();
  const env = { ...process.env, ENTITY54_DATA_DIR: dir, ENTITY54_BOT_ID: "bot-main", ENTITY54_POLICY_KEY: "test-policy-key-0123456789abcdef" };
  delete env.ENTITY54_PRINCIPAL_ID;
  const child = spawn(process.execPath, [`${PLUGIN_ROOT}server/dist/index.js`], { env, stdio: ["ignore", "ignore", "pipe"] });
  const code = await new Promise((resolve) => {
    const timer = setTimeout(() => { child.kill(); resolve(null); }, 5000);
    child.on("exit", (c) => { clearTimeout(timer); resolve(c); });
  });
  assert.notEqual(code, 0, "server must exit non-zero without an asserted principal");
});
