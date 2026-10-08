---
'@rosen-bridge/ergo-multi-sig': minor
'@rosen-bridge/communication': minor
---

Add optional asynchronous authorization before native commitments and partial signatures, with transaction and signing-round validation after the callback completes and immediately before transport handoff. Refused attempts reject subsequent signing calls without replacing their state.

Add an optional synchronous per-message assertion to the communicator after envelope signing and serialization. The Ergo contribution hook requires communication 3.1.0 or later; release these packages together.
