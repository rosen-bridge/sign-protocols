---
'@rosen-bridge/communication': major
---

Embed the signer's protocol version in message signatures so signatures relayed between operators can be verified across minor/patch versions

- `signPayload` now returns `<protocolVersion>:<raw signature>` instead of the raw signature
- `handleMessage` rejects messages whose `version` does not match the version embedded in `sign`
- Signatures in the previous format are no longer accepted
