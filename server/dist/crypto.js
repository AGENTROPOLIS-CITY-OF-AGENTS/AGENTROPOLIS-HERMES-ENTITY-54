// Deterministic cryptographic helpers. All integrity in ENTITY54 rests on
// two primitives: SHA-256 hash chaining for receipts and HMAC-SHA256 for
// policy integrity and identity pseudonymization. Canonical JSON (sorted
// keys, no whitespace) is the only serialization that is ever signed, so a
// signature verifies regardless of key order in the stored file.
import { createHash, createHmac, timingSafeEqual } from "node:crypto";
export function canonical(value) {
    if (value === null || typeof value !== "object") {
        return JSON.stringify(value) ?? "null";
    }
    if (Array.isArray(value)) {
        return `[${value.map((item) => canonical(item)).join(",")}]`;
    }
    const record = value;
    const keys = Object.keys(record).sort();
    const parts = keys.map((key) => `${JSON.stringify(key)}:${canonical(record[key])}`);
    return `{${parts.join(",")}}`;
}
export function sha256Hex(input) {
    return createHash("sha256").update(input, "utf8").digest("hex");
}
export function hmacHex(key, input) {
    return createHmac("sha256", key).update(input, "utf8").digest("hex");
}
export function hmacEqual(a, b) {
    const bufA = Buffer.from(a, "utf8");
    const bufB = Buffer.from(b, "utf8");
    if (bufA.length !== bufB.length) {
        return false;
    }
    return timingSafeEqual(bufA, bufB);
}
// Pseudonym for event-feed identities: HMAC with a key kept separate from
// the policy key, truncated to 16 hex chars. The same principal maps to the
// same pseudonym within one key epoch, so correlation is possible without
// ever exposing the raw platform identity in the feed.
export function pseudonym(key, identity) {
    return hmacHex(key, `entity54-pseudonym-v1:${identity}`).slice(0, 16);
}
