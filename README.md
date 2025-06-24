# Rosen Bridge Sign Protocols

A monorepo containing all the packages related to Rosen Bridge Signing process. It contains the following packages:

1. [keygen-service](./services/keygen-service/README.md): Keygen service is a tool top of [tss-api](./services/tss-api/README.md) for setup keygen ceremony for new guards.
2. [tss-api](./services/tss-api/README.md): A service for keygen, sign and regroup operations on eddsa and ecdsa protocols in threshold signature.
3. [communication](./packages/communication/README.md): A package that abstractly manages communication between endpoints.
4. [encryption](./packages/encryption/README.md): unify encryption interface.
5. [detection](./packages/detection/README.md): A package that finds available endpoints in private network.
6. [tss](./packages/tss/README.md): A package for building and validating TSS signatures.
7. [ergo-multi-sig](./packages/ergo-multi-sig/README.md): A package that manage multi signature protocol for ergo network.

For more info on how each of the packages works, refer to their specific page.
