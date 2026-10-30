---
'@rosen-bridge/ergo-multi-sig': minor
---

Harden multi-sig commitment lifecycle

- Use each generated commitment for at most one partial signature
- Validate sign requests against the current round before contributing
- Ignore commitment requests from guards without the current turn
- Serialize commitment generation with other transaction state updates
- Retry a transaction whose commitment generation failed and keep handling the remaining transactions
- Do not start a round or initiate sign in the last seconds of a turn (new `turnNoWork` config, 10 seconds by default)
