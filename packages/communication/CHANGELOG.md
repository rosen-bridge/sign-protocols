# @rosen-bridge/communication

## 3.0.0

### Major Changes

- `Communicator` now requires each extending class to declare its own semantic-version `protocolVersion`; the version is included in the signed message payload and `handleMessage` rejects any message whose major version doesn't match the local one (minor/patch differences are treated as compatible)

## 2.0.2

### Patch Changes

- Update dependency @rosen-bridge/abstract-logger@4.0.0

## 2.0.1

### Patch Changes

- Update dependencies
  - @rosen-bridge/encryption@1.0.1

## 2.0.0

### Major Changes

- Update node to 22.18.0

### Patch Changes

- Update dependencies:
  - @rosen-bridge/abstract-logger@3.0.1
  - @rosen-bridge/encryption@1.0.0

## 1.0.2

### Patch Changes

- Update license to MIT
- Updated dependencies
  - @rosen-bridge/encryption@0.1.2

## 1.0.1

### Patch Changes

- Fix the getIndex method to throw an error in case of inconsistencies between guardPks and the guard messageEnc.
- Remove unused packages and update dependencies
- Updated dependencies
  - @rosen-bridge/encryption@0.1.1

## 1.0.0

### Major Changes

- Refactor constructor interfaces, add messageEnc and remove unnecessary secrets
