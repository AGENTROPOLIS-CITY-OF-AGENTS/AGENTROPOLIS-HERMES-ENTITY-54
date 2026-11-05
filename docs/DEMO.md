# HERMES ENTITY54 Demo

Reproducible demonstration: a denied operation, an authorized operation,
and the receipts that prove both. Runs against a fresh temp data dir with
a demo-signed policy and the mock Linear transport. Nothing here touches
a real Hermes instance, a real Telegram bot, or a real Linear workspace.

## Run it

```sh
cd server
npm ci
npm run build
npm run demo
```

Fast mode prints the whole transcript in about 1 second. For screen
recording, use the paced mode, which pauses between steps for about 70
seconds total:

```sh
node demo/run-demo.mjs --paced
```

## What it shows

1. **Denied operation.** A GUEST (`tg:333333333`) tries to create a
   Linear issue. The answer is deny, `executed` is false, and no Linear
   call happens. The denial is receipt number 1.
2. **Authorized operation.** The OWNER (`tg:000000000`) previews the same
   operation with `entity54_authorize` and is allowed by rule `owner-all`
   (receipt number 2). Then the OWNER creates the issue. The allow
   decision is receipt number 3 and the execution is receipt number 4.
   The issue id is `mock-issue-1` with the URL `mock://linear/mock-issue-1`:
   this is a demo, not a real Linear issue.
3. **Receipt verification.** `entity54_receipts_verify` reports ok true
   with 4 receipts checked and no bad sequence.
4. **Sanitized event feed.** Five events are listed: the denial, two
   allows, execution started, execution succeeded. No titles, no
   descriptions, no raw principal ids. Identities are 16-hex-char
   pseudonyms.
5. **Receipts on disk.** The transcript ends with the receipt log as
   stored in `receipts.jsonl`, one line per receipt.

## Expected transcript (fast mode)

```
HERMES ENTITY54 demo: denied operation, authorized operation, receipts.
...
=== STEP 1: GUEST tries to create a Linear issue ===
Result: {
  "decision": "deny",
  "reason": "default-deny: no policy rule matches this request",
  "receiptSeq": 1,
  "executed": false
}
...
=== STEP 2: OWNER authorizes the same operation ===
Result: {
  "decision": "allow",
  "ruleId": "owner-all",
  "reason": "allowed by rule owner-all",
  "receiptSeq": 2,
  "policyVersion": 1
}
...
=== STEP 3: OWNER creates the Linear issue (mock transport) ===
Result: {
  "decision": "allow",
  "executed": true,
  "issueId": "mock-issue-1",
  "url": "mock://linear/mock-issue-1",
  "transport": "mock",
  "receiptSeq": 4
}
...
=== STEP 4: the receipt chain verifies ===
Result: {
  "ok": true,
  "checked": 4,
  "badSeq": null,
  "reason": "chain intact"
}
...
=== RECEIPTS ON DISK ===
  #1 authorization deny linear:create-issue (GUEST, policy v1)
  #2 authorization allow linear:create-issue (OWNER, policy v1)
  #3 authorization allow linear:create-issue (OWNER, policy v1)
  #4 execution success linear:create-issue (OWNER, policy v1)
```

The full output from the qualifying run is saved with the handoff
evidence as `entity54-demo-output-2026-11-05.txt`. Timestamps and the
temp data dir path change on every run. The decisions, receipt numbers,
and issue id do not.

## Recording

Paced mode is built for recording: run it in a terminal, capture the
screen, and the transcript paces itself. The recorded video for the
submission is delivered alongside this PR, not inside the repo, because
the GitHub connector cannot push binary files: `entity54-demo-90s.mp4`,
91.0 seconds, 1280x720, 24fps, H.264, 1,349,805 bytes, SHA256
b0a964ecae9e0d0682c72357ba3fefae18b832d180485a96d3859684c7cccd74.
It lives with the handoff evidence and can be added to the repo later if
NEURO wants it there.

The video renders the real fast-run transcript (including its "Demo
complete in 1s" line, which is the genuine output of the fast run) on a
90-second pacing. It was rendered frame by frame from that transcript
with `demo-video/render-frames.py`, because the sandbox Chromium refuses
to start in this environment ("Hatch WebGL domain policy is required for
browser startup", both under Xvfb and headless). The frames were
verified visually at the start, middle, and end before assembly.
