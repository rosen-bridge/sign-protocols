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
native wallet. It checks the same context again after signing the message envelope,
immediately before handing it to `submit`. This requires `@rosen-bridge/communication`
3.1.0 or later. The check cannot cancel work already handed to a transport.
Without the callback, native contributions require no external authorization.
Overlapping commitment requests for the same queued entry and coordinator share
one pending operation, including its authorization result. Later requests run a
new authorization check; a rejected queued entry remains rejected. A new `sign()`
call for that entry rejects immediately without replacing its callbacks or nonce
state. Existing queue cleanup applies; the caller owns when to retry after cleanup.
`contributionValidationVersion === 1` identifies support for this contract.

This callback supplies no chain validation or persistent economic bookkeeping by
itself. The caller owns those checks, recovery policy, and durable assignments.
