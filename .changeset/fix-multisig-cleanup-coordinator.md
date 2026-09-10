---
'@rosen-bridge/ergo-multi-sig': patch
---

Fix `MultiSigHandler.cleanup()` skipping timed out transactions coordinated by another guard, leaving them queued indefinitely instead of being expired
