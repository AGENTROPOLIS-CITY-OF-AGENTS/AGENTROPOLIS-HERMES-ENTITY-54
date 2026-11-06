// Tamper-evident authorization receipts. Every authorization decision,
// execution outcome, policy change, and approval is appended to a JSONL
// log. Each entry carries the SHA-256 hash of the previous entry, forming a
// hash chain, plus an HMAC over its own hash. Any edit, deletion, or
// reordering breaks the chain, and verify() reports the first bad sequence
// number.
//
// The chain alone cannot see a missing tail: a prefix is still internally
// valid. receipts.anchor.json stores the last sequence and hash under its
// own HMAC. verify() compares the log head to that anchor. Deleting the
// last receipt, emptying the log, or editing the anchor fails closed.
// Deleting both the log and the anchor is indistinguishable from a fresh
// store; that residual is documented in docs/REMEDIATION.md.
// Receipts are the audit record: they live in the profile data
// directory and are never served to unauthenticated viewers.
import * as fs from "node:fs";
import * as path from "node:path";
import { canonical, hmacEqual, hmacHex, sha256Hex } from "./crypto.js";
export const RECEIPT_LOG_FILE = "receipts.jsonl";
export const RECEIPT_ANCHOR_FILE = "receipts.anchor.json";
export class ReceiptStore {
    filePath;
    anchorPath;
    key;
    lastSeq = 0;
    lastHash = "GENESIS";
    compromised = false;
    compromiseReason = "";
    constructor(dataDir, key) {
        this.filePath = path.join(dataDir, RECEIPT_LOG_FILE);
        this.anchorPath = path.join(dataDir, RECEIPT_ANCHOR_FILE);
        this.key = key;
        this.load();
    }
    anchorMac(lastSeq, lastHash) {
        return hmacHex(this.key, canonical({ v: 1, lastSeq, lastHash }));
    }
    readAnchor() {
        if (!fs.existsSync(this.anchorPath)) {
            return { status: "missing" };
        }
        let parsed;
        try {
            parsed = JSON.parse(fs.readFileSync(this.anchorPath, "utf8"));
        }
        catch {
            return { status: "bad", reason: "anchor is not valid JSON" };
        }
        if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
            return { status: "bad", reason: "anchor is not an object" };
        }
        const record = parsed;
        if (record.v !== 1 ||
            typeof record.lastSeq !== "number" ||
            !Number.isInteger(record.lastSeq) ||
            record.lastSeq < 0 ||
            typeof record.lastHash !== "string" ||
            record.lastHash.length === 0 ||
            typeof record.hmac !== "string") {
            return { status: "bad", reason: "anchor fields are invalid" };
        }
        const expected = this.anchorMac(record.lastSeq, record.lastHash);
        if (!hmacEqual(expected, record.hmac)) {
            return { status: "bad", reason: "anchor HMAC mismatch" };
        }
        return { status: "ok", lastSeq: record.lastSeq, lastHash: record.lastHash };
    }
    writeAnchor(lastSeq, lastHash) {
        const payload = {
            v: 1,
            lastSeq,
            lastHash,
            hmac: this.anchorMac(lastSeq, lastHash),
        };
        const tmp = `${this.anchorPath}.${process.pid}.tmp`;
        fs.writeFileSync(tmp, `${JSON.stringify(payload)}\n`, { encoding: "utf8", mode: 0o600 });
        fs.renameSync(tmp, this.anchorPath);
    }
    load() {
        const entries = this.readAll();
        if (entries.length > 0) {
            const last = entries[entries.length - 1];
            if (last !== undefined) {
                this.lastSeq = last.seq;
                this.lastHash = last.hash;
            }
        }
        const anchor = this.readAnchor();
        const headSeq = entries.length === 0 ? 0 : this.lastSeq;
        const headHash = entries.length === 0 ? "GENESIS" : this.lastHash;
        if (anchor.status === "missing") {
            if (entries.length > 0) {
                this.compromised = true;
                this.compromiseReason = "anchor missing";
            }
            return;
        }
        if (anchor.status === "bad") {
            this.compromised = true;
            this.compromiseReason = anchor.reason;
            return;
        }
        if (anchor.lastSeq !== headSeq || anchor.lastHash !== headHash) {
            this.compromised = true;
            this.compromiseReason = `anchor expects seq ${anchor.lastSeq} but log head is seq ${headSeq}`;
            // Keep the anchored head so a later append cannot continue a truncated log.
            this.lastSeq = anchor.lastSeq;
            this.lastHash = anchor.lastHash;
        }
    }
    append(entry) {
        if (this.compromised) {
            throw new Error(`receipt log failed closed: ${this.compromiseReason}`);
        }
        const seq = this.lastSeq + 1;
        const prevHash = this.lastHash;
        const body = { ...entry, seq, prevHash };
        const hash = sha256Hex(canonical(body));
        const hmac = hmacHex(this.key, hash);
        const receipt = { ...body, hash, hmac };
        fs.appendFileSync(this.filePath, `${JSON.stringify(receipt)}\n`, "utf8");
        this.writeAnchor(seq, hash);
        this.lastSeq = seq;
        this.lastHash = hash;
        return receipt;
    }
    count() {
        return this.lastSeq;
    }
    readAll() {
        if (!fs.existsSync(this.filePath)) {
            return [];
        }
        return fs
            .readFileSync(this.filePath, "utf8")
            .split("\n")
            .filter((line) => line.trim().length > 0)
            .map((line) => JSON.parse(line));
    }
    verify() {
        let entries;
        try {
            entries = this.readAll();
        }
        catch {
            return { ok: false, checked: 0, badSeq: null, reason: "receipt log is not valid JSONL" };
        }
        let prevHash = "GENESIS";
        for (const entry of entries) {
            const { seq, hash, hmac, ...rest } = entry;
            const recomputed = sha256Hex(canonical({ ...rest, seq, prevHash }));
            if (recomputed !== hash) {
                return { ok: false, checked: seq, badSeq: seq, reason: `hash mismatch at seq ${seq}` };
            }
            if (hmacHex(this.key, hash) !== hmac) {
                return { ok: false, checked: seq, badSeq: seq, reason: `HMAC mismatch at seq ${seq}` };
            }
            if (entry.prevHash !== prevHash) {
                return { ok: false, checked: seq, badSeq: seq, reason: `chain break at seq ${seq}` };
            }
            prevHash = hash;
        }
        const anchor = this.readAnchor();
        const headSeq = entries.length === 0 ? 0 : entries[entries.length - 1]?.seq ?? 0;
        const headHash = entries.length === 0 ? "GENESIS" : entries[entries.length - 1]?.hash ?? "GENESIS";
        if (anchor.status === "missing") {
            if (entries.length === 0) {
                return { ok: true, checked: 0, badSeq: null, reason: "chain intact" };
            }
            return { ok: false, checked: entries.length, badSeq: headSeq, reason: "anchor missing" };
        }
        if (anchor.status === "bad") {
            return { ok: false, checked: entries.length, badSeq: headSeq > 0 ? headSeq : null, reason: anchor.reason };
        }
        if (anchor.lastSeq !== headSeq || anchor.lastHash !== headHash) {
            const reason = entries.length === 0
                ? `tail truncation: anchor expects seq ${anchor.lastSeq} but the log is empty`
                : `tail truncation: anchor expects seq ${anchor.lastSeq} but log head is seq ${headSeq}`;
            return { ok: false, checked: entries.length, badSeq: anchor.lastSeq, reason };
        }
        return { ok: true, checked: entries.length, badSeq: null, reason: "chain intact" };
    }
}
