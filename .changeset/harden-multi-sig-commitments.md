---
'@rosen-bridge/ergo-multi-sig': major
---

Harden multi-sig commitment lifecycle

- Use each generated commitment for at most one partial signature
- Validate sign requests against the current round before contributing
- Ignore commitment requests from guards without the current turn
- Serialize commitment generation with other transaction state updates
- Retry a transaction whose commitment generation failed and keep handling the remaining transactions
- Wait `turnStartDelay` seconds after a turn starts before starting a round (new config, 5 seconds by default; must be shorter than `turnTime`, otherwise the constructor throws)
- Remove the unused `multiSigFirstSignDelay` config option; callers that still pass it must drop it
- Breaking: the multi-sig protocol version follows the package major version, so guards on the previous major cannot exchange multi-sig messages with this one; upgrade all guards together
