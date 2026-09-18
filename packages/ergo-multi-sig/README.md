# @rosen-bridge/ergo-multi-sig

## Table of contents

- [Introduction](#introduction)
- [Installation](#installation)
- [Contribution authorization](#contribution-authorization)

## Introduction

multi signature protocol for ergo network

## Installation

npm:

```sh
npm i @rosen-bridge/ergo-multi-sig
```

yarn:

```sh
yarn add @rosen-bridge/ergo-multi-sig
```

## Contribution authorization

`ErgoMultiSigConfig.beforeContribution` optionally performs asynchronous external
authorization immediately before a guard creates a commitment or partial
signature. Its immutable request contains `txId`, `reducedHex`, and `kind`
(`commitment`, `coordinator-sign`, or `peer-sign`). Reject the promise to terminate
the queued attempt. The callback must not reenter the handler and should enforce
its own I/O deadlines.

After the callback resolves, the handler checks that the retained transaction,
input bytes, signing round, and committee have not changed before invoking the
native wallet. Calls without this callback keep the existing execution path.
`contributionValidationVersion === 1` identifies support for this contract.

This callback supplies no chain validation or persistent economic bookkeeping by
itself. The caller owns those checks, recovery policy, and durable assignments.
