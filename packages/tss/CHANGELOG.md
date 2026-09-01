# @rosen-bridge/tss

## 6.0.0

### Major Changes

- `TssSigner` now declares a `protocolVersion`, taken from this package's own version and signed/enforced by `Communicator`

### Patch Changes

- Verify the signature (and, for ECDSA, its recovery id) against the chain's trusted public key before accepting a TSS sign result delivered via `handleSignData`
- Add more logs
- Update dependencies
  - @rosen-bridge/detection@3.0.0
  - @rosen-bridge/communication@3.0.0

## 5.2.0

### Minor Changes

- Make the `TssSigner.getPk` function public

### Patch Changes

- Replace the `await-semaphore` dependency with `@rosen-bridge/semaphore`
- Update dependencies
  - @rosen-clients/rate-limited-axios@2.0.1

## 5.1.0

### Minor Changes

- Add `isInSign` function to `TssSigner` which checks if a message is in sign

### Patch Changes

- Update dependencies
  - @rosen-bridge/abstract-logger@4.0.0
  - @rosen-bridge/communication@2.0.2
  - @rosen-bridge/detection@2.0.2
  - @rosen-clients/rate-limited-axios@1.1.1

## 5.0.1

### Patch Changes

- Remove dependency @noble/hashes@1.7.1
- Update dependencies
  - @rosen-bridge/detection@2.0.1
  - @rosen-bridge/encryption@1.0.1
  - @rosen-bridge/communication@2.0.1

## 5.0.0

### Major Changes

- Update node to 22.18.0

### Minor Changes

- Update dependencies:
  - secp256k1@5.0.1
  - @types/secp256k1@4.0.7

### Patch Changes

- Update dependencies:
  - @rosen-bridge/abstract-logger@3.0.1
  - @rosen-bridge/communication@2.0.0
  - @rosen-bridge/encryption@1.0.0
  - @rosen-bridge/detection@2.0.0

## 4.1.2

### Patch Changes

- Update license to MIT
- Updated dependencies
  - @rosen-bridge/communication@1.0.2
  - @rosen-bridge/encryption@0.1.2
  - @rosen-bridge/detection@1.0.2

## 4.1.1

### Patch Changes

- Remove unused packages and update dependencies

- Updated dependencies
  - @rosen-bridge/communication@1.0.1
  - @rosen-bridge/detection@1.0.1
  - @rosen-bridge/encryption@0.1.1

## 4.1.0

### Minor Changes

- Add sign cache

## 4.0.0

### Major Changes

- Refactor constructor interfaces, add messageEnc and remove unnecessary secrets
- Split communication, detection and encryption packages

### Patch Changes

- Updated dependencies
  - @rosen-bridge/communication@1.0.0
  - @rosen-bridge/detection@1.0.0

## 3.0.1

### Patch Changes

- fix signPromised return type

## 3.0.0

### Major Changes

- change `sign` function to protected
  change `signPromised` function to abstract
  add `chainCode` and `derivationPath` to `signPromised` arguments and remove them from constructor

## 2.0.1

### Patch Changes

- move common function (randomKey) to abstract class EncryptionHandler

## 2.0.0

### Major Changes

- add chainCode as required to TssSigner class config
- change TssSigner to abstract with abstract `getSignExtraData` and `handleSuccessfulSign` functions

### Minor Changes

- add EcdsaSigner class that implements TssSigner with ECDSA signer
- add EddsaSigner class that implements TssSigner with EdDSA signer
- add `crypto` and `chainCode` parameters to sign request
- add `crypto` parameter to update threshold request
