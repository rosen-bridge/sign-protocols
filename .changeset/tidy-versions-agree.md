---
'@rosen-bridge/communication': patch
'@rosen-bridge/tss': patch
---

Fix guards on different patch versions of `@rosen-bridge/tss` not counting each other's sign approvals: approvals are now verified with the protocol version of the guard that signed them (threaded from the message envelope through to `getApprovedGuards` and forwarded in the start payload), instead of the local guard's version
