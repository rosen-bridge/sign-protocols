# @rosen-bridge/ergo-multi-sig

## 3.0.0

### Major Changes

- `MultiSigHandler` now declares a `protocolVersion`, taken from this package's own version and signed/enforced by `Communicator`

### Patch Changes

- Update dependencies
  - @rosen-bridge/detection@3.0.0
  - @rosen-bridge/communication@3.0.0

## 2.2.1

### Patch Changes

- Replace the `await-semaphore` dependency with `@rosen-bridge/semaphore`

## 2.2.0

### Minor Changes

- Add `isInSign` function to `MultiSigHandler` which checks if a transaction is in sign by it's ID

### Patch Changes

- Update dependencies
  - @rosen-bridge/abstract-logger@4.0.0
  - @rosen-bridge/communication@2.0.2
  - @rosen-bridge/detection@2.0.2

## 2.1.0

### Minor Changes

- Handles semaphore better to avoid locks.

### Patch Changes

- Remove dependency lodash-es@4.17.21
- Update dependencies
  - @rosen-bridge/detection@2.0.1
  - @rosen-bridge/encryption@1.0.1
  - @rosen-bridge/communication@2.0.1

## 2.0.0

### Major Changes

- Update node to 22.18.0

### Patch Changes

- Avoid calculating turnTime everytime
- Update dependencies:
  - @rosen-bridge/abstract-logger@3.0.1
  - @rosen-bridge/communication@2.0.0
  - @rosen-bridge/encryption@1.0.0
  - @rosen-bridge/detection@2.0.0

## 1.0.7

### Patch Changes

- Avoid sending messeges to own guard which causes signing issues
- Sign() only starts the signing process when it is the correct turn

## 1.0.6

### Patch Changes

- Improve transaction state cleaning when turn changes

## 1.0.4

### Patch Changes

- Fix input verification of singed tx

## 1.0.3

### Patch Changes

- Update license to MIT
- Updated dependencies
  - @rosen-bridge/communication@1.0.2
  - @rosen-bridge/encryption@0.1.2
  - @rosen-bridge/detection@1.0.2

## 1.0.2

### Patch Changes

- Fix key mixing of TSS and Ergo

## 1.0.1

### Patch Changes

- Remove unused packages and update dependencies

- Updated dependencies
  - @rosen-bridge/communication@1.0.1
  - @rosen-bridge/detection@1.0.1
  - @rosen-bridge/encryption@0.1.1

## 1.0.0

### Major Changes

- Made Ergo MultiSignature procedure more efficient
- Refactor constructor interfaces, add messageEnc and remove unnecessary secrets

### Patch Changes

- Updated dependencies
  - @rosen-bridge/communication@1.0.0
  - @rosen-bridge/detection@1.0.0
