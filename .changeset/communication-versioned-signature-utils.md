---
'@rosen-bridge/communication': minor
---

Add utilities for versioned signatures (`<version>:<raw signature>`)

- Add `encodeVersionedSignature`/`decodeVersionedSignature` utilities and the `VersionedSignature` interface
- Add protected `verifyPayloadSignatureAndVersion` to verify a versioned signature, received directly or relayed by another operator, against the version it carries; signatures with a different major version are rejected
