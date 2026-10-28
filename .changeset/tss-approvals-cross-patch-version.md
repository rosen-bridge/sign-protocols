---
'@rosen-bridge/tss': patch
---

Fix approvals from guards running a different minor/patch version being dropped by `TssSigner`, by verifying each approval against its signer's protocol version
