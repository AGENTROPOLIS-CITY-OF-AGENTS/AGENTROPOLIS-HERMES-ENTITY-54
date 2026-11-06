// Sanitized ENTITY54 event feed. Events are the only ENTITY54 output that
// is ever shown to a viewer other than the profile owner, so they carry no
// raw content at all: no prompts, no tool arguments, no message text, no
// titles, no tokens, no credentials. Identities are pseudonymized with a
// keyed HMAC (separate from the policy key) so the same principal maps to
// the same short token within one key epoch without ever exposing the raw
// platform identity in the feed.
//
// The feed is disabled by default and must be explicitly enabled. It is
// read-only, bounded (1000 entries, oldest dropped), and paginated.
// Visibility is enforced by viewer scope: a GUEST sees only events that
// carry their own pseudonym; USER and ADMIN see events inside their bot
// scope; OWNER sees all events. The feed can never authorize
// anything: it is a view over past decisions, never an input to a decision.
// Listing without a pseudonym key returns no events. A missing key must
// not collapse every principal to one shared token.
import * as fs from "node:fs";
import * as path from "node:path";
import { pseudonym, sha256Hex } from "./crypto.js";
export const EVENT_CATEGORIES = [
    "authorization_allowed",
    "authorization_denied",
    "tool_execution_started",
    "tool_execution_succeeded",
    "tool_execution_failed",
    "policy_installed",
    "policy_rejected",
    "approval_requested",
    "approval_resolved",
];
export const MAX_EVENTS = 1000;
export const MAX_PAGE = 100;
export class EventStore {
    filePath;
    pseudonymKey;
    events = [];
    nextSeq = 1;
    constructor(dataDir, pseudonymKey) {
        this.filePath = path.join(dataDir, "events.jsonl");
        this.pseudonymKey = pseudonymKey;
        this.load();
    }
    load() {
        if (!fs.existsSync(this.filePath)) {
            return;
        }
        const lines = fs.readFileSync(this.filePath, "utf8").split("\n").filter((line) => line.trim().length > 0);
        this.events = lines.map((line) => JSON.parse(line));
        const last = this.events[this.events.length - 1];
        if (last !== undefined) {
            this.nextSeq = last.seq + 1;
        }
    }
    persist() {
        const body = this.events.map((event) => JSON.stringify(event)).join("\n");
        fs.writeFileSync(this.filePath, body.length > 0 ? `${body}\n` : "", "utf8");
    }
    hashPrincipal(principal) {
        if (!this.pseudonymKey) {
            // Not a viewer pseudonym and not a shared sentinel. Listing is
            // refused while unkeyed, so this value is never used for scope.
            return `nokey:${sha256Hex(`entity54-unkeyed-v1:${principal}`).slice(0, 16)}`;
        }
        return pseudonym(this.pseudonymKey, principal);
    }
    record(input) {
        const event = {
            seq: this.nextSeq,
            ts: new Date().toISOString(),
            category: input.category,
            tool: input.tool,
            decision: input.decision,
            principalHash: this.hashPrincipal(input.principal),
            bot: input.bot,
            receiptRef: input.receiptRef,
        };
        this.nextSeq += 1;
        this.events.push(event);
        if (this.events.length > MAX_EVENTS) {
            this.events = this.events.slice(this.events.length - MAX_EVENTS);
            this.persist();
        }
        else {
            fs.appendFileSync(this.filePath, `${JSON.stringify(event)}\n`, "utf8");
        }
        return event;
    }
    count() {
        return this.events.length;
    }
    list(input) {
        const safeLimit = Math.max(1, Math.min(MAX_PAGE, Math.floor(input.limit) || 25));
        const safeOffset = Math.max(0, Math.floor(input.offset) || 0);
        // Fail closed. Without a key, every historical "unkeyed" token would
        // match every viewer. Return nothing for every role.
        if (!this.pseudonymKey) {
            return { events: [], total: 0, limit: safeLimit, offset: safeOffset };
        }
        const viewerHash = this.hashPrincipal(input.viewerPrincipal);
        let visible = this.events;
        if (input.viewerRole === "GUEST") {
            visible = visible.filter((event) => event.principalHash === viewerHash);
        }
        else if (input.viewerRole === "USER" || input.viewerRole === "ADMIN") {
            visible = visible.filter((event) => event.bot === input.viewerBot);
        }
        if (input.category) {
            visible = visible.filter((event) => event.category === input.category);
        }
        const total = visible.length;
        const page = visible.slice(safeOffset, safeOffset + safeLimit);
        return { events: page, total, limit: safeLimit, offset: safeOffset };
    }
}
