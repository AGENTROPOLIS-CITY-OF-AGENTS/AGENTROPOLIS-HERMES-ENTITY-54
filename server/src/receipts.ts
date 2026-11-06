// Tamper-evident authorization receipts. Every authorization decision,
// execution outcome, policy change, and approval is appended to a JSONL
// log. Each entry carries the SHA-256 hash of the previous entry, forming a
// hash chain, plus an HMAC over its own hash. Any edit, deletion, or
// reordering breaks the chain, and verify() reports the first bad sequence
// number. Receipts are the audit record: they live in the profile data
// directory and are never served to unauthenticated viewers.
import * as fs from "node:fs";
import * as path from "node:path";
import { canonical, hmacHex, sha256Hex } from "./crypto.js";

export type ReceiptType = "authorization" | "execution" | "policy" | "approval";

export interface Receipt {
  seq: number;
  ts: string;
  type: ReceiptType;
  decision: "allow" | "deny" | "success" | "failure" | "staged" | "activated" | "rejected";
  principal: string;
  role: string;
  bot: string;
  tool: string;
  policyVersion: number;
  detail: string;
  prevHash: string;
  hash: string;
  hmac: string;
}

export type NewReceipt = Omit<Receipt, "seq" | "prevHash" | "hash" | "hmac">;

export class ReceiptStore {
  private filePath: string;
  private key: string;
  private lastSeq = 0;
  private lastHash = "GENESIS";

  constructor(dataDir: string, key: string) {
    this.filePath = path.join(dataDir, "receipts.jsonl");
    this.key = key;
    this.load();
  }

  private load(): void {
    if (!fs.existsSync(this.filePath)) {
      return;
    }
    const lines = fs.readFileSync(this.filePath, "utf8").split("\n").filter((line) => line.trim().length > 0);
    for (const line of lines) {
      const entry = JSON.parse(line) as Receipt;
      this.lastSeq = entry.seq;
      this.lastHash = entry.hash;
    }
  }

  append(entry: NewReceipt): Receipt {
    const seq = this.lastSeq + 1;
    const prevHash = this.lastHash;
    const body = { ...entry, seq, prevHash };
    const hash = sha256Hex(canonical(body));
    const hmac = hmacHex(this.key, hash);
    const receipt: Receipt = { ...body, hash, hmac };
    fs.appendFileSync(this.filePath, `${JSON.stringify(receipt)}\n`, "utf8");
    this.lastSeq = seq;
    this.lastHash = hash;
    return receipt;
  }

  count(): number {
    return this.lastSeq;
  }

  readAll(): Receipt[] {
    if (!fs.existsSync(this.filePath)) {
      return [];
    }
    return fs
      .readFileSync(this.filePath, "utf8")
      .split("\n")
      .filter((line) => line.trim().length > 0)
      .map((line) => JSON.parse(line) as Receipt);
  }

  verify(): { ok: boolean; checked: number; badSeq: number | null; reason: string } {
    const entries = this.readAll();
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
    return { ok: true, checked: entries.length, badSeq: null, reason: "chain intact" };
  }
}
