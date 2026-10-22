---
'tss-api': patch
---

Fix race conditions and crashes in TSS operation handling

- Reject keygen and sign for the same crypto running at once (HTTP 409)
- Make duplicate-request checks and registration atomic
- Protect operation and channel maps with a lock
- Validate crypto and derivation path before registering an operation
- Cancel the timeout goroutine when an operation ends or fails to start
- Stop closing the error channel on cleanup, which could crash the process
- Prevent CreateParty errors from deadlocking or crashing the operation
