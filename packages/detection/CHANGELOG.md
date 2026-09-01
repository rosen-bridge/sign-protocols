# @rosen-bridge/detection

## 3.0.0

### Major Changes

- `GuardDetection` now declares a `protocolVersion`, taken from this package's own version and signed/enforced by `Communicator`

### Patch Changes

- Update dependencies
  - @rosen-bridge/communication@3.0.0

## 2.0.2

### Patch Changes

- Update dependencies
  - @rosen-bridge/abstract-logger@4.0.0
  - @rosen-bridge/communication@2.0.2

## 2.0.1

### Patch Changes

- Add logs to the `GuardDetection.update` function
- Remove dependency @noble/hashes@1.7.1
- Update dependencies
  - @rosen-bridge/encryption@1.0.1
  - @rosen-bridge/communication@2.0.1

## 2.0.0

### Major Changes

- Update node to 22.18.0

### Patch Changes

- Update dependencies:
  - @rosen-bridge/abstract-logger@3.0.1
  - @rosen-bridge/communication@2.0.0
  - @rosen-bridge/encryption@1.0.0

## 1.0.2

### Patch Changes

- Update license to MIT
- Updated dependencies
  - @rosen-bridge/communication@1.0.2
  - @rosen-bridge/encryption@0.1.2

## 1.0.1

### Patch Changes

- Add index parameter to ActiveGuard
- Remove unused packages and update dependencies

- Updated dependencies
  - @rosen-bridge/communication@1.0.1
  - @rosen-bridge/encryption@0.1.1

## 1.0.0

### Major Changes

- Refactor constructor interfaces, add messageEnc and remove unnecessary secrets

### Patch Changes

- Updated dependencies
  - @rosen-bridge/communication@1.0.0
