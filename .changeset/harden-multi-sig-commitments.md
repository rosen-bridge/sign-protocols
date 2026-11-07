---
'@rosen-bridge/ergo-multi-sig': patch
---

Harden multi-sig commitment lifecycle

- Use each commitment for at most one partial signature
- Validate sign requests against the current round
- Ignore commitment requests from guards without the current turn
- Skip initiating sign when the turn ends before enough commitments arrive
- Serialize commitment generation with other transaction state updates
- Retry failed commitment generation and keep handling remaining transactions
