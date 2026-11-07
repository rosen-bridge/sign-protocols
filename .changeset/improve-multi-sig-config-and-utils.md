---
'@rosen-bridge/ergo-multi-sig': minor
---

Improve multi-sig handler configuration and utilities

- Add `turnStartDelay` config to delay starting a round after a turn begins (default 5 seconds)
- Throw in the constructor if `turnStartDelay` is not shorter than `turnTime`
- Add `MultiSigUtils.isSamePublishedCommitment`
- Return whether a new commitment was generated from `generateCommitment`
