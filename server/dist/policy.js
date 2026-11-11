// Versioned ENTITY54 policy: deterministic evaluation, HMAC integrity,
// replay and downgrade protection.
//
// A policy document is only trusted when its HMAC verifies against the
// operator key. Import requires a strictly higher version than the active
// policy, so a replayed or downgraded policy is rejected. Import stages a
// policy as pending; activation is a separate OWNER-only step.
import * as fs from "node:fs";
import * as path from "node:path";
import { ROLE_RANK, isRole } from "./config.js";
import { canonical, hmacEqual, hmacHex } from "./crypto.js";
// Rules are evaluated in file order. A rule matches when its principal,
// role, bot, and tool all match the request. Role matching is asymmetric
// by design:
// - ALLOW rules inherit upward: a rule written for USER also matches ADMIN
//   and OWNER, because a higher role holds every permission of the roles
//   below it.
// - DENY rules match exactly: a rule written for ADMIN denies ADMIN only,
//   never OWNER. A deny for a role below the caller is not applied, because
//   the caller's own allow rules govern them and any gap ends in
//   default-deny anyway. This keeps denies precise and prevents a
//   low-role deny from silently revoking a higher role.
// The first matching rule wins. No matching rule means DENY (default-deny).
function ruleMatches(rule, request) {
    if (rule.principal !== undefined && rule.principal !== "*" && rule.principal !== request.principal) {
        return false;
    }
    if (rule.role !== undefined && rule.role !== "*") {
        if (rule.effect === "allow") {
            if (ROLE_RANK[request.role] < ROLE_RANK[rule.role]) {
                return false;
            }
        }
        else if (request.role !== rule.role) {
            return false;
        }
    }
    if (rule.bot !== undefined && rule.bot !== "*" && rule.bot !== request.bot) {
        return false;
    }
    if (rule.tool !== "*" && rule.tool !== request.tool) {
        return false;
    }
    return true;
}
export class PolicyError extends Error {
}
export function signPolicy(doc, key) {
    const unsigned = {
        policyId: doc.policyId,
        version: doc.version,
        issuedAt: doc.issuedAt,
        rules: doc.rules,
    };
    const value = hmacHex(key, canonical(unsigned));
    return { ...unsigned, integrity: { alg: "HMAC-SHA256", value } };
}
export function verifyPolicy(doc, key) {
    const checked = validatePolicyDoc(doc);
    const { integrity, ...unsigned } = checked;
    if (integrity.alg !== "HMAC-SHA256") {
        throw new PolicyError(`unsupported policy integrity alg: ${integrity.alg}`);
    }
    const expected = hmacHex(key, canonical(unsigned));
    if (!hmacEqual(expected, integrity.value)) {
        throw new PolicyError("policy integrity check failed: HMAC does not match. The policy may have been tampered with, or it was signed with a different key.");
    }
    return checked;
}
export function validatePolicyDoc(doc) {
    if (typeof doc !== "object" || doc === null || Array.isArray(doc)) {
        throw new PolicyError("policy must be a JSON object");
    }
    const record = doc;
    if (typeof record.policyId !== "string" || record.policyId.length === 0) {
        throw new PolicyError("policy.policyId must be a non-empty string");
    }
    if (typeof record.version !== "number" || !Number.isInteger(record.version) || record.version < 1) {
        throw new PolicyError("policy.version must be a positive integer");
    }
    if (typeof record.issuedAt !== "string" || Number.isNaN(Date.parse(record.issuedAt))) {
        throw new PolicyError("policy.issuedAt must be an ISO timestamp string");
    }
    if (!Array.isArray(record.rules)) {
        throw new PolicyError("policy.rules must be an array");
    }
    for (const rule of record.rules) {
        if (typeof rule !== "object" || rule === null || Array.isArray(rule)) {
            throw new PolicyError("each policy rule must be an object");
        }
        const r = rule;
        if (typeof r.id !== "string" || r.id.length === 0) {
            throw new PolicyError("each policy rule needs a non-empty string id");
        }
        if (r.effect !== "allow" && r.effect !== "deny") {
            throw new PolicyError(`rule ${r.id}: effect must be "allow" or "deny"`);
        }
        if (typeof r.tool !== "string" || r.tool.length === 0) {
            throw new PolicyError(`rule ${r.id}: tool must be a non-empty string`);
        }
        if (r.role !== undefined && r.role !== "*" && !isRole(r.role)) {
            throw new PolicyError(`rule ${r.id}: unknown role ${String(r.role)}`);
        }
        if (r.principal !== undefined && typeof r.principal !== "string") {
            throw new PolicyError(`rule ${r.id}: principal must be a string`);
        }
        if (r.bot !== undefined && typeof r.bot !== "string") {
            throw new PolicyError(`rule ${r.id}: bot must be a string`);
        }
        if (r.constraints !== undefined) {
            if (typeof r.constraints !== "object" || r.constraints === null || Array.isArray(r.constraints)) {
                throw new PolicyError(`rule ${r.id}: constraints must be an object`);
            }
            for (const [key, value] of Object.entries(r.constraints)) {
                if (typeof value !== "string") {
                    throw new PolicyError(`rule ${r.id}: constraint ${key} must be a string`);
                }
            }
        }
    }
    if (typeof record.integrity !== "object" || record.integrity === null || Array.isArray(record.integrity)) {
        throw new PolicyError("policy.integrity must be an object with alg and value");
    }
    const integrity = record.integrity;
    if (typeof integrity.alg !== "string" || typeof integrity.value !== "string") {
        throw new PolicyError("policy.integrity needs string alg and value");
    }
    return doc;
}
// The governed tool set. A tool name the server does not know fails closed
// before any rule is consulted, even for OWNER and even when a rule uses a
// wildcard. Adding a new governed tool requires adding it here and adding
// a policy rule for it; a policy alone can never authorize an unknown tool.
export const KNOWN_TOOLS = new Set([
    "linear:create-issue",
    "policy:export",
    "policy:import",
    "policy:activate",
    "entity54:read",
    "entity54:status",
    "entity54:receipts-verify",
    "entity54:events-list",
]);
export function evaluatePolicy(policy, request) {
    if (!KNOWN_TOOLS.has(request.tool)) {
        return {
            decision: "deny",
            ruleId: null,
            reason: `unknown tool ${request.tool}`,
            constraints: {},
        };
    }
    for (const rule of policy.rules) {
        if (ruleMatches(rule, request)) {
            return {
                decision: rule.effect,
                ruleId: rule.id,
                reason: rule.effect === "allow"
                    ? `allowed by rule ${rule.id}`
                    : `denied by rule ${rule.id}`,
                constraints: rule.constraints ?? {},
            };
        }
    }
    return {
        decision: "deny",
        ruleId: null,
        reason: "default-deny: no policy rule matches this request",
        constraints: {},
    };
}
export function loadPolicyFile(filePath, key) {
    let raw;
    try {
        raw = fs.readFileSync(filePath, "utf8");
    }
    catch {
        throw new PolicyError(`policy file not found: ${filePath}`);
    }
    let parsed;
    try {
        parsed = JSON.parse(raw);
    }
    catch {
        throw new PolicyError(`policy file is not valid JSON: ${filePath}`);
    }
    return verifyPolicy(parsed, key);
}
export function writePolicyFile(filePath, doc) {
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    fs.writeFileSync(filePath, `${JSON.stringify(doc, null, 2)}\n`, "utf8");
}
// Import staging: the candidate must verify AND carry a strictly higher
// version than the active policy. Equal or lower versions are replay or
// downgrade attempts and are rejected. A candidate must also be strictly
// newer than any policy already staged. Staging replaces pending only
// upward. Activation remains a separate OWNER-only step. An ADMIN cannot
// replace a higher staged version with a lower one.
export function stagePolicyImport(active, candidate, pending = null) {
    if (candidate.policyId !== active.policyId) {
        throw new PolicyError(`policy id mismatch: candidate ${candidate.policyId} does not match active ${active.policyId}`);
    }
    if (candidate.version <= active.version) {
        throw new PolicyError(`policy version ${candidate.version} is not newer than active version ${active.version}; replay or downgrade rejected`);
    }
    if (pending !== null && candidate.version <= pending.version) {
        throw new PolicyError(`policy version ${candidate.version} is not newer than staged version ${pending.version}; replacing a staged policy with an equal or lower version is rejected`);
    }
    return candidate;
}
