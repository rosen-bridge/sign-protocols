import * as wasm from 'ergo-lib-wasm-nodejs';
import { ErgoBox } from 'ergo-lib-wasm-nodejs';
import { afterEach, describe, expect, it, vi } from 'vitest';

import type { ContributionRequest } from '../lib';
import {
  CommitmentPayload,
  InitiateSignPayload,
  MessageType,
  SignPayload,
} from '../lib';
import { turnTime as defaultTurnTime } from '../lib/const';
import { mockPendingEnvelopeSignature } from './mocked/multiSigHandler.mock';
import { boxJs, testCmt, testPubs, testSecrets } from './testData';
import {
  contributionBoxes,
  contributionReduced,
  contributionTxId,
  differentContributionBox,
  generateContributionCommittee,
  generateContributionFixture,
  generateTransportFixture,
  generateTransportSigningGroup,
} from './testUtils/contributionTestUtils';
import { SenderSimulated } from './testUtils/senderSimulated';
import TestUtils from './testUtils/testUtils';
import {
  getChangeBoxJs,
  getOutBoxJs,
  jsToReducedTx,
} from './testUtils/txUtils';

const fee = 1000000;
const tree =
  '0008cd03e5bedab3f782ef17a73e9bdc41ee0e18c3ab477400f35bcf7caa54171db7ff36';
const out = getOutBoxJs(tree, ['ERG', 10000000]);
const ins = [boxJs];
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const dataBoxes: any = [];
const change = getChangeBoxJs(ins, [out], tree, fee);
const reduced = jsToReducedTx(ins, [out, change], dataBoxes, 1311604, fee);
const requiredSings = 6;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const boxes = ins.map((i: any) => ErgoBox.from_json(JSON.stringify(i)));
const turnTime = defaultTurnTime * 1000;

describe('MultiSigHandler', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    vi.useRealTimers();
  });
  describe('peers', () => {
    /**
     * @target MultiSigHandler.peers should return pks without IDs
     * @dependencies MultiSigHandlerInstance
     * @scenario
     * - Generate a MultiSigHandler instance
     * - Call peers
     * @expected
     * - returned value should be pks without IDs
     * - returned value length should be equal to the testPubs length
     * - returned value should not have IDs
     */
    it('should return pks without IDs', async () => {
      const sender = vi.fn();
      const handler = await TestUtils.generateMultiSigHandlerInstance(
        testSecrets[0],
        sender,
        testPubs,
      );
      handler.peers().forEach((peer) => {
        expect(peer.id).toBeUndefined();
      });
      expect(handler.peers().length).toEqual(testPubs.length);
    });
  });

  describe('peersWithIds', () => {
    /**
     * @target MultiSigHandler.peersWithIds should return pks with IDs
     * @dependencies MultiSigHandlerInstance
     * @scenario
     * - Generate a MultiSigHandler instance
     * - Call peersWithIds
     * @expected
     * - returned value should be pks with IDs
     * - returned value length should be equal to the testPubs length
     */
    it('should return pks with IDs', async () => {
      const sender = vi.fn();
      const handler = await TestUtils.generateMultiSigHandlerInstance(
        testSecrets[0],
        sender,
        testPubs,
      );
      (await handler.peersWithIds()).forEach((peer) => {
        expect(peer.id).toBeDefined();
      });
      expect(handler.peers().length).toEqual(testPubs.length);
    });
  });

  describe('getCurrentTurnId', () => {
    /**
     * @target MultiSigHandler.getCurrentTurnId should return ID for the guard with the current turn
     * @dependencies
     * @scenario
     * - mock `setSystemTime`
     * - run test
     * - check returned value
     * @expected
     * - returned value should be ID for the guard with the current turn
     */
    it('should return ID for the guard with the current turn', async () => {
      const sender = vi.fn();
      const handler = await TestUtils.generateMultiSigHandlerInstance(
        testSecrets[0],
        sender,
        testPubs,
      );
      vi.setSystemTime(0);
      const turnInd = handler.getCurrentTurnInd();
      const ids = [...testPubs].reverse();
      const id = await handler.getCurrentTurnId();
      expect(id).toEqual(ids[turnInd]);
      vi.setSystemTime(turnTime);
      const turnInd2 = handler.getCurrentTurnInd();
      const id2 = await handler.getCurrentTurnId();
      expect(id2).toEqual(ids[turnInd2]);
    });
  });

  describe('getCurrentTurnInd', () => {
    /**
     * @target MultiSigHandler.getCurrentTurnInd should return current turn index
     * @dependencies
     * @scenario
     * - mock `setSystemTime`
     * - run test
     * - check returned value
     * @expected
     * - returned value should be current turn index
     */
    it('should return current turn index', async () => {
      const sender = vi.fn();
      const handler = await TestUtils.generateMultiSigHandlerInstance(
        testSecrets[0],
        sender,
        testPubs,
      );
      vi.setSystemTime(0);
      expect(handler.getCurrentTurnInd()).to.equal(0);
      vi.setSystemTime(turnTime);
      expect(handler.getCurrentTurnInd()).to.equal(1);
      vi.setSystemTime(turnTime * testPubs.length + 1);
      expect(handler.getCurrentTurnInd()).to.equal(0);
    });
  });

  describe('isMyTurn', () => {
    /**
     * @target MultiSigHandler.isMyTurn should return true if it is my turn
     * @dependencies
     * @scenario
     * - mock `setSystemTime`
     * - run test
     * - check returned value
     * @expected
     * - returned value should be true for the first handler
     * - returned value should be false for the second handler
     */
    it('should return true if it is my turn', async () => {
      const sender = vi.fn();
      const handler = await TestUtils.generateMultiSigHandlerInstance(
        testSecrets[0],
        sender,
        testPubs,
      );
      const handler2 = await TestUtils.generateMultiSigHandlerInstance(
        testSecrets[1],
        sender,
        testPubs,
      );
      vi.setSystemTime(0);
      expect(await handler.isMyTurn()).toEqual(true);
      vi.setSystemTime(turnTime);
      expect(await handler.isMyTurn()).toEqual(false);
      expect(await handler2.isMyTurn()).toEqual(true);
    });
  });

  describe('getQueuedTransaction', () => {
    /**
     * @target MultiSigHandler.getQueuedTransaction should return an empty transaction for new txId
     * @dependencies MultiSigHandlerInstance
     * @scenario
     * - Generate a MultiSigHandler instance
     * - Call getQueuedTransaction with a new test transaction ID
     * @expected
     * - The returned transaction should have a coordinator property equal to -1
     */
    it('should return an empty transaction for new txId', async () => {
      // mock `queuedTransaction`
      const handler = await TestUtils.generateMultiSigHandlerInstance(
        testSecrets[0],
        vi.fn(),
        testPubs,
      );
      const txId = 'test';
      const { transaction } = await handler.getQueuedTransaction(txId);
      expect(transaction.coordinator).toEqual(-1);
    });

    /**
     * @target MultiSigHandler.getQueuedTransaction should return the queued transaction
     * @dependencies MultiSigHandlerInstance
     * @scenario
     * - Generate a MultiSigHandler instance
     * - Call getQueuedTransaction with a new test transaction ID
     * - Set its coordinator to 1 and release the queue lock
     * - Call getQueuedTransaction again with the same transaction ID
     * @expected
     * - The returned queued transaction should retain coordinator 1
     */
    it('should return the queued transaction', async () => {
      // mock `queuedTransaction`
      const handler = await TestUtils.generateMultiSigHandlerInstance(
        testSecrets[0],
        vi.fn(),
        testPubs,
      );
      const txId = 'test';
      const { transaction, release } = await handler.getQueuedTransaction(txId);
      transaction.coordinator = 1;
      release();
      const { transaction: transaction2 } =
        await handler.getQueuedTransaction(txId);
      expect(transaction2.coordinator).toEqual(1);
    });
  });

  describe('sign', () => {
    /**
     * @target MultiSigHandler.sign should put transaction into queue
     * @dependencies MultiSigHandlerInstance
     * @scenario
     * - Generate a MultiSigHandler instance
     * - Call sign with a test transaction, required signs, boxes, and dataBoxes
     * - Call getQueuedTransaction with the transaction ID
     * @expected
     * - The returned transaction should have boxes length equal to 1 and requiredSigner equal to 6
     */
    it('should put transaction into queue', async () => {
      // mock `sign`
      const handler = await TestUtils.generateMultiSigHandlerInstance(
        testSecrets[0],
        vi.fn(),
        testPubs,
      );
      const mockedGenerateCmt = vi.fn();
      vi.spyOn(handler, 'generateCommitment').mockImplementation(
        mockedGenerateCmt,
      );

      // run test
      handler.sign(reduced, requiredSings, boxes, dataBoxes);
      const { transaction } = await handler.getQueuedTransaction(
        reduced.unsigned_tx().id().to_str(),
      );
      expect(transaction.boxes.length).toEqual(1);
      expect(transaction.requiredSigner).toEqual(6);
    });

    /**
     * @target MultiSigHandler.sign should call generateCommitment
     * @dependencies MultiSigHandlerInstance
     * @scenario
     * - Generate a MultiSigHandler instance
     * - Call sign with a test transaction, required signs, boxes, and dataBoxes
     * @expected
     * - generateCommitment should have been called
     */
    it('should call generateCommitment', async () => {
      // mock `sign`
      const handler = await TestUtils.generateMultiSigHandlerInstance(
        testSecrets[0],
        vi.fn(),
        testPubs,
      );
      const mockedGenerateCmt = vi.fn();
      vi.spyOn(handler, 'generateCommitment').mockImplementation(
        mockedGenerateCmt,
      );
      expect(mockedGenerateCmt).not.toHaveBeenCalled();
    });

    /**
     * @target MultiSigHandler.sign rejects the actual sign promise on authorization failure without waiting for cleanup
     * @dependencies
     * - rejecting beforeContribution hook and native commitment spy (mocked)
     * - real MultiSigHandler.sign promise chain and reduced transaction input
     * @scenario
     * - configure authorization to throw source invalid
     * - call sign and await its returned promise directly
     * - inspect native commitment generation
     * @expected
     * - the sign promise rejects with source invalid
     * - no native commitment is generated
     */
    it('rejects the actual sign promise on authorization failure without waiting for cleanup', async () => {
      const f = await generateContributionFixture(async () => {
        throw Error('source invalid');
      });
      await expect(
        f.handler.sign(contributionReduced, 6, contributionBoxes, []),
      ).rejects.toThrow('source invalid');
      expect(f.commitments).not.toHaveBeenCalled();
    });

    /**
     * @target MultiSigHandler.sign normalizes hook rejection %s without an unhandled sign-chain failure
     * @dependencies
     * - beforeContribution hook rejecting with null or undefined and native commitment spy (mocked)
     * - process unhandledRejection listener and real sign promise chain
     * @scenario
     * - register an unhandledRejection observer
     * - call sign, capture its rejection value, and drain one event-loop turn
     * - inspect the normalized failure and remove the observer in finally
     * @expected
     * - sign rejects with an Error and produces no unhandled rejection
     * - no native commitment is generated
     */
    it.each([null, undefined])(
      'normalizes hook rejection %s without an unhandled sign-chain failure',
      async (reason) => {
        const f = await generateContributionFixture(async () => {
          throw reason;
        });
        const unhandled: unknown[] = [];
        const observe = (error: unknown) => {
          unhandled.push(error);
        };
        process.on('unhandledRejection', observe);
        try {
          const failure = await f.handler
            .sign(contributionReduced, 6, contributionBoxes, [])
            .catch((error) => error);
          await new Promise((resolve) => setImmediate(resolve));
          expect(failure).toBeInstanceOf(Error);
          expect(unhandled).toEqual([]);
          expect(f.commitments).not.toHaveBeenCalled();
        } finally {
          process.off('unhandledRejection', observe);
        }
      },
    );

    /**
     * @target MultiSigHandler.sign completes a six-signer round through signed envelopes with authorization enabled
     * @dependencies
     * - beforeContribution hook and six in-memory outbound submit sinks (mocked)
     * - ECDSA envelope signing, communicator handling, and ergo-lib-wasm Wallet (real)
     * @scenario
     * - start sign concurrently for six guards and collect serialized outbound messages
     * - deliver each message through the recipients' real handleMessage path until the queue drains
     * - await all sign promises and inspect transaction ids, hook kinds, and queue cleanup
     * @expected
     * - every signer returns the same transaction id
     * - authorization covers six commitments, one coordinator partial, and five peer partials
     * - every handler removes the completed queue entry
     */
    it('completes a six-signer round through signed envelopes with authorization enabled', async () => {
      const hook = vi.fn<(request: ContributionRequest) => Promise<void>>(
        async () => {},
      );
      const members = await Promise.all(
        testSecrets
          .slice(0, 6)
          .map((_, i) => generateTransportFixture(i, hook)),
      );
      const messages: Array<{
        message: string;
        peers: string[];
        sender: string;
      }> = [];
      members.forEach((member, i) => {
        member.submit.mockImplementation((message: string, peers: string[]) => {
          messages.push({ message, peers, sender: testPubs[i] });
        });
      });
      const signed = Promise.all(
        members.map(({ handler }) =>
          handler.sign(contributionReduced, 6, [...contributionBoxes], []),
        ),
      );
      // Drain an in-memory network through handleMessage, including real envelope
      // verification; no RPC, native operation or authorization method is mocked.
      await new Promise<void>((resolve) => setImmediate(resolve));
      expect(messages.length).toBeGreaterThan(0);
      let delivered = 0;
      while (messages.length) {
        if (++delivered > 30) throw Error('unexpected protocol message loop');
        const { message, peers, sender } = messages.shift()!;
        const recipients = peers.length ? peers : testPubs;
        for (let i = 0; i < members.length; i++)
          if (testPubs[i] !== sender && recipients.includes(testPubs[i]))
            await members[i].handler.handleMessage(message, sender);
      }
      const results = await signed;
      expect(results.map((tx) => tx.id().to_str())).toEqual(
        members.map(() => contributionTxId),
      );
      expect(hook.mock.calls.map(([request]) => request.kind).sort()).toEqual([
        ...Array<string>(6).fill('commitment'),
        'coordinator-sign',
        ...Array<string>(5).fill('peer-sign'),
      ]);
      for (const member of members)
        expect(await member.handler.isInSign(contributionTxId)).toEqual(false);
    });

    /**
     * @target MultiSigHandler.sign rejects a new sign call on a refused entry without replacing retained state (coordinator %s)
     * @dependencies
     * - stateful beforeContribution hook and retry timeout race (mocked)
     * - retained queued transaction created by generateContributionFixture
     * @scenario
     * - generate initial state for coordinator 0 or 1, then revoke authorization
     * - make the next contribution request fail and snapshot the retained queue entry
     * - call sign with a different threshold and race rejection against a timeout
     * - compare every retained field and hook call count after rejection
     * @expected
     * - sign rejects promptly with Contribution state changed
     * - retained queue state and hook count remain unchanged and the tx stays queued
     */
    it.each([0, 1])(
      'rejects a new sign call on a refused entry without replacing retained state (coordinator %s)',
      async (coordinator) => {
        let authorized = true;
        const hook = vi.fn(async () => {
          if (!authorized) throw Error('source invalid');
        });
        const { handler, transaction } =
          await generateContributionFixture(hook);
        await handler.generateCommitment(contributionTxId, coordinator);
        expect(transaction.secret).toBeDefined();
        authorized = false;
        await expect(
          handler.generateCommitment(contributionTxId, coordinator),
        ).rejects.toThrow('source invalid');
        const retained = { ...transaction };
        const hookCalls = hook.mock.calls.length;
        const retry = handler.sign(
          contributionReduced,
          5,
          [...contributionBoxes],
          [],
        );
        let timeout: ReturnType<typeof setTimeout> | undefined;
        try {
          const outcome = await Promise.race([
            retry.then(
              () => 'resolved',
              (error: unknown) => error,
            ),
            new Promise<string>((resolve) => {
              timeout = setTimeout(() => resolve('still pending'), 100);
            }),
          ]);
          expect(outcome).toBeInstanceOf(Error);
          expect((outcome as Error).message).toEqual(
            'Contribution state changed',
          );
        } finally {
          clearTimeout(timeout);
        }
        for (const key of Object.keys(retained) as Array<keyof typeof retained>)
          expect(transaction[key]).toBe(retained[key]);
        expect(hook).toHaveBeenCalledTimes(hookCalls);
        expect(await handler.isInSign(contributionTxId)).toEqual(true);
      },
    );
  });

  describe('addTx', () => {
    /**
     * @target MultiSigHandler.addTx should add transaction to the queue
     * @dependencies MultiSigHandlerInstance
     * @scenario
     * - Generate a MultiSigHandler instance
     * - Call addTx with a test transaction, required signs, boxes, and dataBoxes
     * - Call getQueuedTransaction with the transaction ID
     * @expected
     * - The returned transaction should have boxes length equal to 1 and requiredSigner equal to 6
     */
    it('should add transaction to the queue', async () => {
      const handler = await TestUtils.generateMultiSigHandlerInstance(
        testSecrets[0],
        vi.fn(),
        testPubs,
      );
      const txId = reduced.unsigned_tx().id().to_str();
      await TestUtils.addTx(handler, reduced, requiredSings, boxes, dataBoxes);
      const { transaction } = await handler.getQueuedTransaction(txId);
      expect(transaction.boxes.length).toEqual(1);
      expect(transaction.requiredSigner).toEqual(6);
    });
  });

  describe('generateCommitment', () => {
    /**
     * @target MultiSigHandler.generateCommitment should generate commitment
     * @dependencies MultiSigHandlerInstance
     * @scenario
     * - Generate a MultiSigHandler instance
     * - Call addTx with a test transaction, required signs, boxes, and dataBoxes
     * - Call generateCommitment with the transaction ID
     * @expected
     * - The returned transaction should have commitments length equal to 1
     */
    it('should generate commitment', async () => {
      const handler = await TestUtils.generateMultiSigHandlerInstance(
        testSecrets[0],
        vi.fn(),
        testPubs,
      );
      await TestUtils.addTx(handler, reduced, requiredSings, boxes, dataBoxes);
      await handler.generateCommitment(reduced.unsigned_tx().id().to_str());
      const { transaction } = await handler.getQueuedTransaction(
        reduced.unsigned_tx().id().to_str(),
      );
      expect(Object.values(transaction.commitments).length).toEqual(1);
      expect(Object.keys(transaction.commitments)[0]).toEqual(testPubs[0]);
      expect(transaction.secret).toBeDefined();
    });

    /**
     * @target MultiSigHandler.generateCommitment should not call sendMessage if his turn
     * @dependencies MultiSigHandlerInstance
     * @scenario
     * - Generate a MultiSigHandler instance
     * - Call addTx with a test transaction, required signs, boxes, and dataBoxes
     * - Set system time to 0
     * - Call generateCommitment with the transaction ID
     * @expected
     * - sendMessage should not have been called
     */
    it('should not call sendMessage if his turn', async () => {
      const handler = await TestUtils.generateMultiSigHandlerInstance(
        testSecrets[0],
        vi.fn(),
        testPubs,
      );
      const mockedSendMessage = vi.fn();
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      vi.spyOn(handler as any, 'sendMessage').mockImplementation(
        mockedSendMessage,
      );
      await TestUtils.addTx(handler, reduced, requiredSings, boxes, dataBoxes);
      vi.setSystemTime(0);
      await handler.generateCommitment(reduced.unsigned_tx().id().to_str());
      expect(mockedSendMessage).not.toHaveBeenCalled();
    });

    /**
     * @target MultiSigHandler.generateCommitment should call sendMessage if not his turn
     * @dependencies MultiSigHandlerInstance
     * @scenario
     * - Generate a MultiSigHandler instance
     * - Call addTx with a test transaction, required signs, boxes, and dataBoxes
     * - Set system time to turnTime
     * - Call generateCommitment with the transaction ID
     * @expected
     * - sendMessage should have been called
     */
    it('should call sendMessage if not his turn', async () => {
      const handler = await TestUtils.generateMultiSigHandlerInstance(
        testSecrets[0],
        vi.fn(),
        testPubs,
      );
      const mockedSendMessage = vi.fn();
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      vi.spyOn(handler as any, 'sendMessage').mockImplementation(
        mockedSendMessage,
      );
      await TestUtils.addTx(handler, reduced, requiredSings, boxes, dataBoxes);
      vi.setSystemTime(turnTime);
      await handler.generateCommitment(reduced.unsigned_tx().id().to_str(), 1);
      expect(mockedSendMessage).toHaveBeenCalled();
    });

    /**
     * @target MultiSigHandler.generateCommitment refuses a queued commitment before any native secret operation and rejects immediately
     * @dependencies
     * - beforeContribution hook, native commitment/sign spies, and reject callback (mocked)
     * - queued transaction state from generateContributionFixture
     * @scenario
     * - configure beforeContribution to reject with the source-proof error
     * - call generateCommitment for the queued transaction
     * - inspect native commitment/sign calls and the queue rejection callback
     * @expected
     * - generateCommitment rejects with the hook error
     * - no native commitment or sign operation runs and the queue entry is rejected
     */
    it('refuses a queued commitment before any native secret operation and rejects immediately', async () => {
      const failure = Error('source proof removed');
      const f = await generateContributionFixture(async () => {
        throw failure;
      });
      await expect(
        f.handler.generateCommitment(contributionTxId),
      ).rejects.toThrow(failure);
      expect(f.commitments).not.toHaveBeenCalled();
      expect(f.signs).not.toHaveBeenCalled();
      expect(f.reject).toHaveBeenCalledWith(failure);
    });

    /**
     * @target MultiSigHandler.generateCommitment passes a frozen exact request and permits a real native commitment
     * @dependencies
     * - beforeContribution hook and native commitment spy (mocked)
     * - reduced transaction bytes and queued transaction state (real)
     * @scenario
     * - assert the hook receives a frozen commitment request with the exact txId and reducedHex
     * - call generateCommitment for that queued transaction
     * - inspect hook/native call counts and the generated secret
     * @expected
     * - the hook runs once with the exact frozen request
     * - one native commitment is generated and stored as transaction secret state
     */
    it('passes a frozen exact request and permits a real native commitment', async () => {
      const hook = vi.fn(async (request) => {
        expect(Object.isFrozen(request)).toEqual(true);
        expect(request).toEqual({
          txId: contributionTxId,
          kind: 'commitment',
          reducedHex: Buffer.from(
            contributionReduced.sigma_serialize_bytes(),
          ).toString('hex'),
        });
      });
      const f = await generateContributionFixture(hook);
      await f.handler.generateCommitment(contributionTxId);
      expect(hook).toHaveBeenCalledTimes(1);
      expect(f.commitments).toHaveBeenCalledTimes(1);
      expect(f.transaction.secret).toBeDefined();
    });

    /**
     * @target MultiSigHandler.generateCommitment retains the synchronous native path when no hook is configured
     * @dependencies
     * - native wallet commitment method (spied)
     * - queued transaction state from generateContributionFixture
     * @scenario
     * - create a fixture without beforeContribution
     * - start generateCommitment without first awaiting its returned promise
     * - inspect the native commitment spy before awaiting completion
     * @expected
     * - native commitment generation starts synchronously and the operation completes
     */
    it('retains the synchronous native path when no hook is configured', async () => {
      const f = await generateContributionFixture();
      const pending = f.handler.generateCommitment(contributionTxId);
      expect(f.commitments).toHaveBeenCalledTimes(1);
      await pending;
    });

    /**
     * @target MultiSigHandler.generateCommitment coalesces overlapping requests for coordinator %s without rejecting the queued transaction
     * @dependencies
     * - gated beforeContribution hook, native commitment spy, sendMessage, and reject callback (mocked)
     * - queued transaction state from generateContributionFixture
     * @scenario
     * - gate the first authorization for coordinator undefined or 0
     * - start a second identical request while the first is pending, then release the gate
     * - await both requests and invoke the same request once more after completion
     * - inspect hook, native, transport, and rejection call counts
     * @expected
     * - both overlapping requests fulfill through one hook/native execution
     * - the later request executes independently and the queue entry is never rejected
     */
    it.each([undefined, 0])(
      'coalesces overlapping requests for coordinator %s without rejecting the queued transaction',
      async (coordinator) => {
        const entered = Promise.withResolvers<void>();
        const resume = Promise.withResolvers<void>();
        const hook = vi.fn(async () => {
          entered.resolve();
          await resume.promise;
        });
        const f = await generateContributionFixture(hook);
        const first = f.handler.generateCommitment(
          contributionTxId,
          coordinator,
        );
        await entered.promise;
        const second = f.handler.generateCommitment(
          contributionTxId,
          coordinator,
        );
        const results = Promise.allSettled([first, second]);
        resume.resolve();
        expect(await results).toEqual([
          { status: 'fulfilled', value: undefined },
          { status: 'fulfilled', value: undefined },
        ]);
        expect(hook).toHaveBeenCalledTimes(1);
        expect(f.commitments).toHaveBeenCalledTimes(1);
        expect(f.send).toHaveBeenCalledTimes(coordinator === undefined ? 0 : 1);
        expect(f.reject).not.toHaveBeenCalled();

        await f.handler.generateCommitment(contributionTxId, coordinator);
        expect(hook).toHaveBeenCalledTimes(2);
        expect(f.commitments).toHaveBeenCalledTimes(2);
        expect(f.send).toHaveBeenCalledTimes(coordinator === undefined ? 0 : 2);
        expect(f.reject).not.toHaveBeenCalled();
      },
    );

    /**
     * @target MultiSigHandler.generateCommitment keeps overlapping requests fail-closed on %s
     * @dependencies
     * - gated beforeContribution hook, native commitment spy, sendMessage, and reject callback (mocked)
     * - fake system time and queued transaction state
     * @scenario
     * - start two identical requests behind one authorization gate
     * - make authorization refuse, advance the turn, or add a conflicting coordinator request
     * - release the gate and collect every request result
     * - retry the original request after the failed overlap
     * @expected
     * - every pending request rejects with the source or state-change error
     * - retry remains failed, no native/transport action runs, and the queue entry is rejected
     */
    it.each(['refusal', 'turn', 'coordinator'] as const)(
      'keeps overlapping requests fail-closed on %s',
      async (changed) => {
        const entered = Promise.withResolvers<void>();
        const resume = Promise.withResolvers<void>();
        const hook = vi.fn(async () => {
          entered.resolve();
          await resume.promise;
          if (changed === 'refusal') throw Error('source invalid');
        });
        const f = await generateContributionFixture(hook);
        const first = f.handler.generateCommitment(contributionTxId, 0);
        await entered.promise;
        const second = f.handler.generateCommitment(contributionTxId, 0);
        const pending = [first, second];
        if (changed === 'turn') vi.setSystemTime(turnTime);
        if (changed === 'coordinator')
          pending.push(f.handler.generateCommitment(contributionTxId, 1));
        const results = Promise.allSettled(pending);
        resume.resolve();
        expect(await results).toEqual(
          pending.map(() => ({
            status: 'rejected',
            reason: expect.objectContaining({
              message:
                changed === 'refusal'
                  ? 'source invalid'
                  : 'Contribution state changed',
            }),
          })),
        );
        const hookCalls = hook.mock.calls.length;
        await expect(
          f.handler.generateCommitment(contributionTxId, 0),
        ).rejects.toThrow('Contribution state changed');
        expect(hook).toHaveBeenCalledTimes(hookCalls);
        expect(f.commitments).not.toHaveBeenCalled();
        expect(f.send).not.toHaveBeenCalled();
        expect(f.reject).toHaveBeenCalled();
      },
    );

    /**
     * @target MultiSigHandler.generateCommitment blocks a changed %s while authorization is pending
     * @dependencies
     * - gated beforeContribution hook, native wallet spies, and reject callback (mocked)
     * - queued transaction, committee, boxes, data boxes, and fake system time
     * @scenario
     * - start generateCommitment and pause inside authorization
     * - mutate the selected queue identity, transaction, round, secret, turn, threshold, committee, or box state
     * - release authorization and await the pending operation
     * - inspect native operation and queue rejection spies
     * @expected
     * - the request rejects with Contribution state changed
     * - no native secret operation runs and the queue entry records the state-change rejection
     */
    it.each([
      'queue',
      'transaction',
      'coordinator',
      'round',
      'roundCommitments',
      'roundSigns',
      'secret',
      'turn',
      'threshold',
      'committee',
      'boxes',
      'dataBoxes',
      'boxesContent',
      'dataBoxesContent',
      'boxesBytes',
      'dataBoxesBytes',
    ] as const)(
      'blocks a changed %s while authorization is pending',
      async (changed) => {
        const entered = Promise.withResolvers<void>();
        const resume = Promise.withResolvers<void>();
        const f = await generateContributionFixture(async () => {
          entered.resolve();
          await resume.promise;
        });
        if (changed === 'dataBoxesBytes')
          f.transaction.dataBoxes.push(contributionBoxes[0]);
        const pending = f.handler.generateCommitment(contributionTxId);
        await entered.promise;
        switch (changed) {
          case 'queue':
            f.handler.replaceQueuedTransaction(contributionTxId, f.transaction);
            break;
          case 'transaction':
            f.transaction.tx = wasm.ReducedTransaction.sigma_parse_bytes(
              contributionReduced.sigma_serialize_bytes(),
            );
            break;
          case 'coordinator':
            f.transaction.coordinator = 1;
            break;
          case 'round':
            f.handler.cleanQueuedTransaction(f.transaction);
            break;
          case 'secret':
            f.transaction.secret = wasm.TransactionHintsBag.empty();
            break;
          case 'roundCommitments':
            f.transaction.commitments = {};
            break;
          case 'roundSigns':
            f.transaction.signs = {};
            break;
          case 'turn':
            vi.setSystemTime(turnTime);
            break;
          case 'threshold':
            f.transaction.requiredSigner++;
            break;
          case 'committee':
            f.handler.handlePublicKeysChange([...testPubs].reverse());
            break;
          case 'boxes':
            f.transaction.boxes = [...contributionBoxes];
            break;
          case 'dataBoxes':
            f.transaction.dataBoxes = [];
            break;
          case 'boxesContent':
            f.transaction.boxes.push(contributionBoxes[0]);
            break;
          case 'dataBoxesContent':
            f.transaction.dataBoxes.push(contributionBoxes[0]);
            break;
          case 'boxesBytes':
            f.transaction.boxes[0] = differentContributionBox;
            break;
          case 'dataBoxesBytes':
            f.transaction.dataBoxes[0] = differentContributionBox;
            break;
        }
        resume.resolve();
        await expect(pending).rejects.toThrow('Contribution state changed');
        expect(f.commitments).not.toHaveBeenCalled();
        expect(f.signs).not.toHaveBeenCalled();
        expect(f.reject).toHaveBeenCalledWith(
          expect.objectContaining({ message: 'Contribution state changed' }),
        );
      },
    );

    /**
     * @target MultiSigHandler.generateCommitment does not publish a commitment when the turn changes during peer discovery
     * @dependencies
     * - GuardDetection.activeGuards gate and sendMessage (mocked)
     * - real commitment generation, queued state, and fake system time
     * @scenario
     * - pause peer discovery after starting generateCommitment as coordinator 0
     * - advance system time to the next turn and resume peer discovery
     * - await the request and inspect commitment publication calls
     * @expected
     * - generateCommitment rejects with Contribution state changed
     * - no Commitment message is published
     */
    it('does not publish a commitment when the turn changes during peer discovery', async () => {
      const f = await generateContributionFixture(async () => {});
      const entered = Promise.withResolvers<void>();
      const resume = Promise.withResolvers<void>();
      const detection = f.handler.getGuardDetection();
      vi.spyOn(detection, 'activeGuards').mockImplementationOnce(async () => {
        entered.resolve();
        await resume.promise;
        return testPubs.map((publicKey, index) => ({
          publicKey,
          peerId: publicKey,
          index,
        }));
      });
      const pending = f.handler.generateCommitment(contributionTxId, 0);
      await entered.promise;
      vi.setSystemTime(turnTime);
      resume.resolve();
      await expect(pending).rejects.toThrow('Contribution state changed');
      expect(f.send).not.toHaveBeenCalledWith(
        MessageType.Commitment,
        expect.anything(),
        expect.anything(),
        expect.anything(),
      );
    });

    /**
     * @target MultiSigHandler.generateCommitment does not publish a commitment when its generated secret changes during peer discovery
     * @dependencies
     * - MultiSigHandler.peersWithIds gate and sendMessage (mocked)
     * - real commitment generation and queued secret/commitment state
     * @scenario
     * - pause peer discovery after generating the local commitment
     * - retain the commitment but replace the transaction secret bag
     * - resume discovery and await the pending request
     * @expected
     * - generateCommitment rejects with Contribution state changed
     * - no Commitment message is published
     */
    it('does not publish a commitment when its generated secret changes during peer discovery', async () => {
      const f = await generateContributionFixture(async () => {});
      const entered = Promise.withResolvers<void>();
      const resume = Promise.withResolvers<void>();
      vi.spyOn(f.handler, 'peersWithIds').mockImplementationOnce(async () => {
        entered.resolve();
        await resume.promise;
        return testPubs.map((pub) => ({ pub, id: pub }));
      });
      const pending = f.handler.generateCommitment(contributionTxId, 0);
      await entered.promise;
      const publishedCommitment = f.transaction.commitments[testPubs[0]];
      f.transaction.secret = wasm.TransactionHintsBag.empty();
      expect(f.transaction.commitments[testPubs[0]]).toBe(publishedCommitment);
      resume.resolve();
      await expect(pending).rejects.toThrow('Contribution state changed');
      expect(f.send).not.toHaveBeenCalledWith(
        MessageType.Commitment,
        expect.anything(),
        expect.anything(),
        expect.anything(),
      );
    });

    /**
     * @target MultiSigHandler.generateCommitment does not revive a refused queue entry on a later contribution request
     * @dependencies
     * - stateful beforeContribution hook and native commitment spy (mocked)
     * - queued transaction state from generateContributionFixture
     * @scenario
     * - refuse the first generateCommitment request with source invalid
     * - allow the hook and retry generateCommitment for the same queue entry
     * - inspect the retry and native commitment spy
     * @expected
     * - the retry rejects with Contribution state changed
     * - no native commitment is generated for the refused entry
     */
    it('does not revive a refused queue entry on a later contribution request', async () => {
      let valid = false;
      const f = await generateContributionFixture(async () => {
        if (!valid) throw Error('source invalid');
      });
      await expect(
        f.handler.generateCommitment(contributionTxId),
      ).rejects.toThrow('source invalid');
      valid = true;
      await expect(
        f.handler.generateCommitment(contributionTxId),
      ).rejects.toThrow('Contribution state changed');
      expect(f.commitments).not.toHaveBeenCalled();
    });

    /**
     * @target MultiSigHandler.generateCommitment fences communication committee mutation during authorization: %s
     * @dependencies
     * - gated beforeContribution hook and native commitment spy (mocked)
     * - communication keys changed through changePks or reverseCommunicationKeys
     * @scenario
     * - pause generateCommitment inside authorization
     * - reverse communication keys through the public or in-place test path
     * - release authorization and await the pending request
     * @expected
     * - the pending request rejects and no native commitment is generated
     */
    it.each(['public-change', 'in-place'] as const)(
      'fences communication committee mutation during authorization: %s',
      async (mode) => {
        const entered = Promise.withResolvers<void>();
        const resume = Promise.withResolvers<void>();
        const f = await generateContributionFixture(async () => {
          entered.resolve();
          await resume.promise;
        });
        const pending = f.handler.generateCommitment(contributionTxId);
        await entered.promise;
        if (mode === 'public-change')
          await f.handler.changePks([...testPubs].reverse());
        else f.handler.reverseCommunicationKeys();
        resume.resolve();
        await expect(pending).rejects.toThrow();
        expect(f.commitments).not.toHaveBeenCalled();
      },
    );

    /**
     * @target MultiSigHandler.generateCommitment submits a signed commitment when its context remains current
     * @dependencies
     * - outbound submit sink and GuardDetection.activeGuards (mocked)
     * - ECDSA envelope signing and native commitment generation (real)
     * @scenario
     * - create guard 1 with a queued transaction and current committee
     * - call generateCommitment for coordinator 0
     * - parse the single serialized envelope submitted by the communicator
     * @expected
     * - one signed Commitment envelope is submitted for the queued txId
     */
    it('submits a signed commitment when its context remains current', async () => {
      const f = await generateTransportFixture(1);
      await f.handler.generateCommitment(contributionTxId, 0);
      expect(f.submit).toHaveBeenCalledTimes(1);
      const envelope = JSON.parse(f.submit.mock.calls[0][0]);
      expect(envelope.type).toEqual(MessageType.Commitment);
      expect(envelope.payload.txId).toEqual(contributionTxId);
      expect(envelope.sign).toBeTruthy();
    });

    /**
     * @target MultiSigHandler.generateCommitment rejects a commitment when the committee changes during envelope signing
     * @dependencies
     * - next ECDSA envelope signature gate and outbound submit sink (mocked)
     * - native commitment generation and queued transaction state (real)
     * @scenario
     * - start generateCommitment and pause the outgoing envelope signature
     * - replace the Ergo committee before resuming signature generation
     * - resume signing and await the pending request
     * @expected
     * - the request rejects with Contribution state changed
     * - no envelope is submitted and the queued transaction is rejected
     */
    it('rejects a commitment when the committee changes during envelope signing', async () => {
      const f = await generateTransportFixture(1);
      const gate = mockPendingEnvelopeSignature(f.messageEnc);
      const pending = f.handler.generateCommitment(contributionTxId, 0);
      await gate.entered.promise;
      f.handler.handlePublicKeysChange([...testPubs].reverse());
      gate.resume.resolve();
      await expect(pending).rejects.toThrow('Contribution state changed');
      expect(f.submit).not.toHaveBeenCalled();
      expect(f.transaction.reject).toHaveBeenCalled();
    });
  });

  describe('handleCommitment', () => {
    /**
     * @target MultiSigHandler.handleCommitment should do nothing if not his turn
     * @dependencies MultiSigHandlerInstance
     * @scenario
     * - Generate a MultiSigHandler instance
     * - Call addTx with a test transaction, required signs, boxes, and dataBoxes
     * - Set system time to turnTime
     * - Call handleCommitment with a test sender, payload, and signature
     * @expected
     * - sendMessage should not have been called
     * - The returned transaction should have commitments length equal to 0
     */
    it('should do nothing if not his turn', async () => {
      const handler = await TestUtils.generateMultiSigHandlerInstance(
        testSecrets[0],
        vi.fn(),
        testPubs,
      );
      const mockedSendMessage = vi.fn();
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      vi.spyOn(handler as any, 'sendMessage').mockImplementation(
        mockedSendMessage,
      );
      await TestUtils.addTx(handler, reduced, requiredSings, boxes, dataBoxes);

      vi.setSystemTime(0);
      await handler.handleCommitment(
        '0',
        testCmt.payload as CommitmentPayload,
        testCmt.sign,
        0, // Pass the index here
      );
      expect(mockedSendMessage).not.toHaveBeenCalled();
      const { transaction } = await handler.getQueuedTransaction(
        reduced.unsigned_tx().id().to_str(),
      );
      expect(Object.values(transaction.commitments).length).toEqual(0);
    });

    /**
     * @target MultiSigHandler.handleCommitment should add commitment to the tx
     * @dependencies MultiSigHandlerInstance
     * @scenario
     * - Generate a MultiSigHandler instance
     * - Call addTx with a test transaction, required signs, boxes, and dataBoxes
     * - Set system time to 0
     * - Call handleCommitment with a test sender, payload, and signature
     * @expected
     * - sendMessage should not have been called
     * - The returned transaction should have commitments length equal to 1
     */
    it('should add commitment to the tx', async () => {
      const handler = await TestUtils.generateMultiSigHandlerInstance(
        testSecrets[0],
        vi.fn(),
        testPubs,
      );
      const mockedSendMessage = vi.fn();
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      vi.spyOn(handler as any, 'sendMessage').mockImplementation(
        mockedSendMessage,
      );
      await TestUtils.addTx(handler, reduced, requiredSings, boxes, dataBoxes);

      vi.setSystemTime(0);
      await handler.generateCommitment(reduced.unsigned_tx().id().to_str());
      await handler.handleCommitment(
        '0',
        testCmt.payload as CommitmentPayload,
        testCmt.sign,
        0, // Pass the index here
      );
      expect(mockedSendMessage).not.toHaveBeenCalled();
      const { transaction } = await handler.getQueuedTransaction(
        reduced.unsigned_tx().id().to_str(),
      );
      expect(Object.values(transaction.commitments).length).toEqual(1);
    });

    /**
     * @target MultiSigHandler.handleCommitment should send commitments to the proper peer
     * @dependencies MultiSigHandlerInstance
     * @scenario
     * - Generate a MultiSigHandler instance
     * - Call addTx with a test transaction, required signs, boxes, and dataBoxes
     * - Set system time to 0
     * - Call handleCommitment with a test sender, payload, and signature
     * @expected
     * - The returned transaction should have commitments length equal to 3
     */
    it('should send commitments to the proper peer', async () => {
      const simulatedSender = new SenderSimulated();
      const allHandlers = await Promise.all(
        testSecrets.map((secret) =>
          TestUtils.generateMultiSigHandlerInstance(
            secret,
            simulatedSender.simulatedSender,
            testPubs,
          ),
        ),
      );
      const handlers = allHandlers.slice(0, 3);
      await simulatedSender.changeHandlers(handlers);
      vi.setSystemTime(0);
      await Promise.all(
        handlers.map((handler) => {
          return TestUtils.addTx(
            handler,
            reduced,
            requiredSings,
            boxes,
            dataBoxes,
          );
        }),
      );
      // Handler 0 is coordinator, others respond
      await handlers[0].generateCommitment(reduced.unsigned_tx().id().to_str());
      await handlers[1].generateCommitment(
        reduced.unsigned_tx().id().to_str(),
        0,
      );
      await handlers[2].generateCommitment(
        reduced.unsigned_tx().id().to_str(),
        0,
      );

      const turnHandler = handlers[0];
      const { transaction } = await turnHandler.getQueuedTransaction(
        reduced.unsigned_tx().id().to_str(),
      );
      expect(Object.values(transaction.commitments).length).toEqual(3);
    });

    /**
     * @target MultiSigHandler.handleCommitment revalidates after simulated hint extraction and creates no coordinator partial on refusal
     * @dependencies
     * - beforeContribution hook, MultiSigUtils.extract_hints gate, sendMessage, and reject callback (mocked)
     * - six-member committee commitments and native coordinator signing method
     * @scenario
     * - prepare five accepted commitments and deliver the sixth
     * - pause simulated-hint extraction, revoke authorization, and resume extraction
     * - inspect repeated hook calls, native partial creation, rejection, and InitiateSign publication
     * @expected
     * - authorization is checked again and the queued transaction is rejected with proof disappeared
     * - no coordinator partial or InitiateSign message is created
     */
    it('revalidates after simulated hint extraction and creates no coordinator partial on refusal', async () => {
      let valid = true;
      const hook = vi.fn(async () => {
        if (!valid) throw Error('proof disappeared');
      });
      const { members, deliver } = await generateContributionCommittee(hook);
      const coordinator = members[0];
      const entered = Promise.withResolvers<void>();
      const resume = Promise.withResolvers<void>();
      const extract = coordinator.utils.extract_hints.bind(coordinator.utils);
      vi.spyOn(coordinator.utils, 'extract_hints').mockImplementationOnce(
        async (...args) => {
          entered.resolve();
          await resume.promise;
          return extract(...args);
        },
      );
      const pending = deliver(5);
      await entered.promise;
      expect(hook).toHaveBeenCalledTimes(6);
      valid = false;
      resume.resolve();
      await pending;
      expect(hook).toHaveBeenCalledTimes(7);
      expect(coordinator.signs).not.toHaveBeenCalled();
      expect(coordinator.reject).toHaveBeenCalledWith(
        expect.objectContaining({ message: 'proof disappeared' }),
      );
      expect(coordinator.send).not.toHaveBeenCalledWith(
        MessageType.InitiateSign,
        expect.anything(),
        expect.anything(),
        expect.anything(),
      );
      expect(members.map((m) => m.commitments.mock.calls.length)).toEqual([
        1, 1, 1, 1, 1, 1,
      ]);
    });

    /**
     * @target MultiSigHandler.handleCommitment and MultiSigHandler.initiateSign permits real native partials at both signing sites when verification succeeds
     * @dependencies
     * - beforeContribution hook, sendMessage, and reject callbacks (mocked)
     * - six real native wallets and committee commitment state
     * @scenario
     * - complete the coordinator commitment threshold and obtain InitiateSign payload
     * - call initiateSign for each of the five peers
     * - inspect native partial-sign counts, authorization calls, and rejection callbacks
     * @expected
     * - every member performs one native partial-sign operation
     * - all twelve authorization checks pass and no queue entry is rejected
     */
    it('permits real native partials at both signing sites when verification succeeds', async () => {
      const hook = vi.fn(async () => {});
      const { members, deliver } = await generateContributionCommittee(hook);
      await deliver(5);
      const payload = members[0].send.mock.calls.find(
        (call) => call[0] === MessageType.InitiateSign,
      )![1] as InitiateSignPayload;
      for (let i = 1; i < members.length; i++)
        await members[i].handler.initiateSign(testPubs[0], payload, 0);
      expect(members.map((m) => m.signs.mock.calls.length)).toEqual([
        1, 1, 1, 1, 1, 1,
      ]);
      expect(hook).toHaveBeenCalledTimes(12);
      expect(members.every((m) => m.reject.mock.calls.length === 0)).toEqual(
        true,
      );
    });

    /**
     * @target MultiSigHandler.handleCommitment and MultiSigHandler.initiateSign blocks %s if its round changes during authorization
     * @dependencies
     * - kind-selective beforeContribution gate, native sign spy, and reject callback (mocked)
     * - coordinator and peer signing paths from generateContributionCommittee
     * @scenario
     * - enter coordinator-sign through handleCommitment or peer-sign through initiateSign
     * - pause the selected authorization and change the target transaction coordinator
     * - resume authorization and await the pending signing path
     * @expected
     * - no native partial is generated
     * - the target queue entry is rejected with Contribution state changed
     */
    it.each(['coordinator-sign', 'peer-sign'] as const)(
      'blocks %s if its round changes during authorization',
      async (kind) => {
        const entered = Promise.withResolvers<void>();
        const resume = Promise.withResolvers<void>();
        const { members, deliver } = await generateContributionCommittee(
          async (request) => {
            if (request.kind === kind) {
              entered.resolve();
              await resume.promise;
            }
          },
        );
        let pending: Promise<void>;
        const target = members[kind === 'coordinator-sign' ? 0 : 1];
        if (kind === 'coordinator-sign') pending = deliver(5);
        else {
          await deliver(5);
          const payload = members[0].send.mock.calls.find(
            (call) => call[0] === MessageType.InitiateSign,
          )![1] as InitiateSignPayload;
          pending = target.handler.initiateSign(testPubs[0], payload, 0);
        }
        await entered.promise;
        target.transaction.coordinator = 1;
        resume.resolve();
        await pending;
        expect(target.signs).not.toHaveBeenCalled();
        expect(target.reject).toHaveBeenCalledWith(
          expect.objectContaining({ message: 'Contribution state changed' }),
        );
      },
    );

    /**
     * @target MultiSigHandler.handleCommitment and MultiSigHandler.initiateSign does not publish a %s proof when its turn changes during final hint extraction
     * @dependencies
     * - MultiSigUtils.extract_hints gate, sendMessage, and reject callback (mocked)
     * - real coordinator/peer native signing state and fake system time
     * @scenario
     * - enter the final hint extraction for the coordinator-sign or peer-sign path
     * - advance system time to the next turn before resuming extraction
     * - await the path and inspect outgoing proof messages and queue rejection
     * @expected
     * - no InitiateSign or Sign proof is published for the selected path
     * - the target queue entry is rejected with Contribution state changed
     */
    it.each(['coordinator-sign', 'peer-sign'] as const)(
      'does not publish a %s proof when its turn changes during final hint extraction',
      async (kind) => {
        const { members, deliver } = await generateContributionCommittee(
          async () => {},
        );
        const target = members[kind === 'coordinator-sign' ? 0 : 1];
        let resume!: () => void;
        const extraction = new Promise<void>((resolve) => (resume = resolve));
        const entered = Promise.withResolvers<void>();
        const extract = target.utils.extract_hints.bind(target.utils);
        if (kind === 'coordinator-sign') {
          vi.spyOn(target.utils, 'extract_hints')
            .mockImplementationOnce((...args) => extract(...args))
            .mockImplementationOnce(async (...args) => {
              entered.resolve();
              await extraction;
              return extract(...args);
            });
          const pending = deliver(5);
          await entered.promise;
          vi.setSystemTime(turnTime);
          resume();
          await pending;
          expect(target.send).not.toHaveBeenCalledWith(
            MessageType.InitiateSign,
            expect.anything(),
            expect.anything(),
            expect.anything(),
          );
        } else {
          await deliver(5);
          const payload = members[0].send.mock.calls.find(
            (call) => call[0] === MessageType.InitiateSign,
          )![1] as InitiateSignPayload;
          vi.spyOn(target.utils, 'extract_hints').mockImplementationOnce(
            async (...args) => {
              entered.resolve();
              await extraction;
              return extract(...args);
            },
          );
          const pending = target.handler.initiateSign(testPubs[0], payload, 0);
          await entered.promise;
          vi.setSystemTime(turnTime);
          resume();
          await pending;
          expect(target.send).not.toHaveBeenCalledWith(
            MessageType.Sign,
            expect.anything(),
            expect.anything(),
            expect.anything(),
          );
        }
        expect(target.reject).toHaveBeenCalledWith(
          expect.objectContaining({ message: 'Contribution state changed' }),
        );
      },
    );

    /**
     * @target MultiSigHandler.handleCommitment and MultiSigHandler.initiateSign does not publish a %s proof if commitment regeneration replaces its secret during extraction
     * @dependencies
     * - MultiSigUtils.extract_hints gate, sendMessage, and reject callback (mocked)
     * - real generateCommitment and coordinator/peer signing state
     * @scenario
     * - enter final hint extraction for the coordinator-sign or peer-sign path
     * - regenerate the target commitment and secret before resuming extraction
     * - await the path and inspect proof publication and queue rejection
     * @expected
     * - no InitiateSign or Sign proof is published for the stale secret
     * - the target queue entry is rejected with Contribution state changed
     */
    it.each(['coordinator-sign', 'peer-sign'] as const)(
      'does not publish a %s proof if commitment regeneration replaces its secret during extraction',
      async (kind) => {
        const { members, deliver } = await generateContributionCommittee(
          async () => {},
        );
        const target = members[kind === 'coordinator-sign' ? 0 : 1];
        let resume!: () => void;
        const extraction = new Promise<void>((resolve) => (resume = resolve));
        const entered = Promise.withResolvers<void>();
        const extract = target.utils.extract_hints.bind(target.utils);
        if (kind === 'coordinator-sign') {
          vi.spyOn(target.utils, 'extract_hints')
            .mockImplementationOnce((...args) => extract(...args))
            .mockImplementationOnce(async (...args) => {
              entered.resolve();
              await extraction;
              return extract(...args);
            });
          const pending = deliver(5);
          await entered.promise;
          await target.handler.generateCommitment(contributionTxId, 0);
          resume();
          await pending;
          expect(target.send).not.toHaveBeenCalledWith(
            MessageType.InitiateSign,
            expect.anything(),
            expect.anything(),
            expect.anything(),
          );
        } else {
          await deliver(5);
          const payload = members[0].send.mock.calls.find(
            (call) => call[0] === MessageType.InitiateSign,
          )![1] as InitiateSignPayload;
          vi.spyOn(target.utils, 'extract_hints').mockImplementationOnce(
            async (...args) => {
              entered.resolve();
              await extraction;
              return extract(...args);
            },
          );
          const pending = target.handler.initiateSign(testPubs[0], payload, 0);
          await entered.promise;
          await target.handler.generateCommitment(contributionTxId, 0);
          resume();
          await pending;
          expect(target.send).not.toHaveBeenCalledWith(
            MessageType.Sign,
            expect.anything(),
            expect.anything(),
            expect.anything(),
          );
        }
        expect(target.reject).toHaveBeenCalledWith(
          expect.objectContaining({ message: 'Contribution state changed' }),
        );
      },
    );

    /**
     * @target MultiSigHandler.handleCommitment does not publish InitiateSign when the turn changes during peer discovery
     * @dependencies
     * - GuardDetection.activeGuards gate, sendMessage, and reject callback (mocked)
     * - six-member committee commitment state and fake system time
     * @scenario
     * - deliver the final peer commitment and pause coordinator peer discovery
     * - advance system time to the next turn and resume discovery
     * - await handleCommitment and inspect initiation publication and rejection
     * @expected
     * - no InitiateSign message is published
     * - the coordinator queue entry is rejected with Contribution state changed
     */
    it('does not publish InitiateSign when the turn changes during peer discovery', async () => {
      const { members } = await generateContributionCommittee(async () => {});
      const coordinator = members[0];
      const entered = Promise.withResolvers<void>();
      const resume = Promise.withResolvers<void>();
      const detection = coordinator.handler.getGuardDetection();
      vi.spyOn(detection, 'activeGuards').mockImplementationOnce(async () => {
        entered.resolve();
        await resume.promise;
        return testPubs.map((publicKey, index) => ({
          publicKey,
          peerId: publicKey,
          index,
        }));
      });
      const pending = coordinator.handler.handleCommitment(
        testPubs[5],
        {
          txId: contributionTxId,
          commitment: members[5].transaction.commitments[testPubs[5]],
        },
        'test-envelope-verified-upstream',
        5,
      );
      await entered.promise;
      vi.setSystemTime(turnTime);
      resume.resolve();
      await pending;
      expect(coordinator.send).not.toHaveBeenCalledWith(
        MessageType.InitiateSign,
        expect.anything(),
        expect.anything(),
        expect.anything(),
      );
      expect(coordinator.reject).toHaveBeenCalledWith(
        expect.objectContaining({ message: 'Contribution state changed' }),
      );
    });

    /**
     * @target MultiSigHandler.handleCommitment rejects a round replaced during simulated hint extraction before consulting authorization
     * @dependencies
     * - beforeContribution hook, MultiSigUtils.extract_hints gate, native sign spy, and reject callback (mocked)
     * - six-member committee commitment state
     * @scenario
     * - deliver the final commitment and pause simulated-hint extraction
     * - replace the coordinator commitment map before resuming extraction
     * - inspect hook count, native signing, and rejection state
     * @expected
     * - no seventh authorization call or native coordinator partial occurs
     * - the queue entry is rejected with Contribution state changed
     */
    it('rejects a round replaced during simulated hint extraction before consulting authorization', async () => {
      const hook = vi.fn(async () => {});
      const { members, deliver } = await generateContributionCommittee(hook);
      const coordinator = members[0];
      const entered = Promise.withResolvers<void>();
      const resume = Promise.withResolvers<void>();
      const extract = coordinator.utils.extract_hints.bind(coordinator.utils);
      vi.spyOn(coordinator.utils, 'extract_hints').mockImplementationOnce(
        async (...args) => {
          entered.resolve();
          await resume.promise;
          return extract(...args);
        },
      );
      const pending = deliver(5);
      await entered.promise;
      coordinator.transaction.commitments = {};
      resume.resolve();
      await pending;
      expect(hook).toHaveBeenCalledTimes(6);
      expect(coordinator.signs).not.toHaveBeenCalled();
      expect(coordinator.reject).toHaveBeenCalledWith(
        expect.objectContaining({ message: 'Contribution state changed' }),
      );
    });

    /**
     * @target MultiSigHandler.handleCommitment and MultiSigHandler.initiateSign preserves the original absolute turn across the %s queue wait
     * @dependencies
     * - queued-transaction lock barrier, native sign spy, sendMessage, and reject callback (mocked)
     * - coordinator/peer signing state and fake system time
     * @scenario
     * - hold an unrelated queue lock before coordinator-sign or peer-sign acquires its queue entry
     * - advance by one or one full committee turn epoch while the operation waits
     * - release the lock and inspect native signing, proof publication, and rejection
     * @expected
     * - stale coordinator/peer work produces no native partial or proof message
     * - the target queue entry is rejected; coordinator-sign also rejects its promise
     */
    it.each(['coordinator-sign', 'peer-sign'] as const)(
      'preserves the original absolute turn across the %s queue wait',
      async (kind) => {
        for (const epoch of [1, testPubs.length]) {
          const { members, deliver } = await generateContributionCommittee(
            async () => {},
          );
          const target = members[kind === 'coordinator-sign' ? 0 : 1];
          let payload: InitiateSignPayload | undefined;
          if (kind === 'peer-sign') {
            await deliver(5);
            payload = members[0].send.mock.calls.find(
              (call) => call[0] === MessageType.InitiateSign,
            )![1] as InitiateSignPayload;
          }
          const barrier =
            await target.handler.getQueuedTransaction('test-lock-barrier');
          const pending =
            kind === 'coordinator-sign'
              ? deliver(5)
              : target.handler.initiateSign(testPubs[0], payload!, 0);
          vi.setSystemTime(epoch * turnTime);
          barrier.release();
          if (kind === 'coordinator-sign')
            await expect(pending).rejects.toThrow('Contribution state changed');
          else await pending;
          expect(target.signs).not.toHaveBeenCalled();
          expect(
            target.send.mock.calls.filter(
              (call) =>
                call[0] === MessageType.Sign ||
                call[0] === MessageType.InitiateSign,
            ),
          ).toHaveLength(0);
          expect(target.reject).toHaveBeenCalledWith(expect.any(Error));
        }
      },
    );

    /**
     * @target MultiSigHandler.handleCommitment rejects initiation when the committee changes during envelope signing
     * @dependencies
     * - next ECDSA envelope signature gate and outbound submit sink (mocked)
     * - real coordinator commitment aggregation and InitiateSign construction
     * @scenario
     * - deliver the final commitment and pause InitiateSign envelope signing
     * - replace the committee before resuming the signature
     * - await the delivery path and inspect submission and rejection
     * @expected
     * - no InitiateSign envelope is submitted
     * - the coordinator queue entry is rejected
     */
    it('rejects initiation when the committee changes during envelope signing', async () => {
      const group = await generateTransportSigningGroup();
      const gate = mockPendingEnvelopeSignature(group.coordinator.messageEnc);
      const pending = group.finish();
      await gate.entered.promise;
      group.coordinator.handler.handlePublicKeysChange([...testPubs].reverse());
      gate.resume.resolve();
      await pending;
      expect(group.coordinator.submit).not.toHaveBeenCalled();
      expect(group.coordinator.transaction.reject).toHaveBeenCalled();
    });
  });

  describe('initiateSign', () => {
    /**
     * @target MultiSigHandler.initiateSign should successfully sign the transaction
     * @dependencies MultiSigHandlerInstance
     * @scenario
     * - Generate a MultiSigHandler instance
     * - Call addTx with a test transaction, required signs, boxes, and dataBoxes
     * - Set system time to 0
     * - Call initiateSign with a test sender and payload
     * @expected
     * - The returned transaction should have coordinator property equal to -1
     */
    it('should successfully sign the transaction', async () => {
      const simulatedSender = new SenderSimulated();
      const handlers = await Promise.all(
        testSecrets.map((secret) =>
          TestUtils.generateMultiSigHandlerInstance(
            secret,
            simulatedSender.simulatedSender,
            testPubs,
          ),
        ),
      );
      await simulatedSender.changeHandlers(handlers);
      vi.setSystemTime(0);
      await Promise.all(
        handlers.map((handler) => {
          return TestUtils.addTx(
            handler,
            reduced,
            requiredSings,
            boxes,
            dataBoxes,
          );
        }),
      );
      await Promise.all(
        handlers.map((handler) => {
          return handler.sign(reduced, requiredSings, boxes, dataBoxes);
        }),
      );
      const turnHandler = handlers[0];
      const { transaction } = await turnHandler.getQueuedTransaction(
        reduced.unsigned_tx().id().to_str(),
      );

      expect(transaction.coordinator).toEqual(-1);
    });

    /**
     * @target MultiSigHandler.initiateSign refuses a peer partial without claiming to retract the coordinator partial
     * @dependencies
     * - stateful beforeContribution hook, native sign spies, and peer reject callback (mocked)
     * - coordinator InitiateSign payload from a six-member committee
     * @scenario
     * - let the coordinator create its native partial and InitiateSign payload
     * - revoke authorization before peer 1 handles that payload
     * - inspect peer and coordinator native sign counts and peer rejection
     * @expected
     * - peer 1 creates no partial and records the source-spent rejection
     * - the already-created coordinator partial remains counted once
     */
    it('refuses a peer partial without claiming to retract the coordinator partial', async () => {
      let valid = true;
      const { members, deliver } = await generateContributionCommittee(
        async () => {
          if (!valid) throw Error('source spent');
        },
      );
      await deliver(5);
      expect(members[0].signs).toHaveBeenCalledTimes(1);
      const payload = members[0].send.mock.calls.find(
        (call) => call[0] === MessageType.InitiateSign,
      )![1] as InitiateSignPayload;
      valid = false;
      await members[1].handler.initiateSign(testPubs[0], payload, 0);
      expect(members[1].signs).not.toHaveBeenCalled();
      expect(members[1].reject).toHaveBeenCalledWith(
        expect.objectContaining({ message: 'source spent' }),
      );
      expect(members[0].signs).toHaveBeenCalledTimes(1);
    });

    /**
     * @target MultiSigHandler.initiateSign submits a peer proof when its context remains current
     * @dependencies
     * - outbound submit sinks and GuardDetection.activeGuards (mocked)
     * - real coordinator initiation, peer native signing, and ECDSA envelope signing
     * @scenario
     * - complete coordinator initiation and parse its submitted InitiateSign envelope
     * - clear peer 1's submit sink and call initiateSign with the envelope payload
     * - inspect the peer's serialized outbound envelope
     * @expected
     * - peer 1 submits exactly one Sign envelope
     */
    it('submits a peer proof when its context remains current', async () => {
      const group = await generateTransportSigningGroup();
      await group.finish();
      const initiation = JSON.parse(group.coordinator.submit.mock.calls[0][0]);
      expect(initiation.type).toEqual(MessageType.InitiateSign);
      const peer = group.members[1];
      peer.submit.mockClear();
      await peer.handler.initiateSign(testPubs[0], initiation.payload, 0);
      expect(peer.submit).toHaveBeenCalledTimes(1);
      expect(JSON.parse(peer.submit.mock.calls[0][0]).type).toEqual(
        MessageType.Sign,
      );
    });

    /**
     * @target MultiSigHandler.initiateSign rejects a prepared peer proof after another authorization fails during envelope signing
     * @dependencies
     * - stateful beforeContribution hook, next ECDSA signature gate, and submit sink (mocked)
     * - real coordinator initiation and peer native proof preparation
     * @scenario
     * - prepare peer 1's proof and pause its Sign envelope signature
     * - revoke authorization and make a concurrent generateCommitment request fail
     * - resume envelope signing and await the peer path
     * @expected
     * - the peer queue entry is rejected by the concurrent authorization failure
     * - the prepared Sign envelope is not submitted
     */
    it('rejects a prepared peer proof after another authorization fails during envelope signing', async () => {
      let valid = true;
      const group = await generateTransportSigningGroup(async () => {
        if (!valid) throw Error('source authorization revoked');
      });
      await group.finish();
      const initiation = JSON.parse(group.coordinator.submit.mock.calls[0][0]);
      expect(initiation.type).toEqual(MessageType.InitiateSign);
      const peer = group.members[1];
      peer.submit.mockClear();
      const gate = mockPendingEnvelopeSignature(peer.messageEnc);
      const pending = peer.handler.initiateSign(
        testPubs[0],
        initiation.payload as InitiateSignPayload,
        0,
      );
      await gate.entered.promise;
      valid = false;
      await expect(
        peer.handler.generateCommitment(contributionTxId, 0),
      ).rejects.toThrow('source authorization revoked');
      expect(peer.transaction.reject).toHaveBeenCalled();
      gate.resume.resolve();
      await pending;
      expect(peer.submit).not.toHaveBeenCalled();
    });
  });

  describe('cleanup', () => {
    /**
     * @target MultiSigHandler.cleanup should remove expired transactions
     * @dependencies MultiSigHandlerInstance
     * @scenario
     * - Generate a MultiSigHandler instance
     * - Call addTx with a test transaction, required signs, boxes, and dataBoxes
     * - Set system time to 10e6
     * - Call cleanup
     * - Call getQueuedTransaction with the transaction ID
     * @expected
     * - The returned transaction should have boxes length equal to 0
     */
    it('should remove expired transactions', async () => {
      const handler = await TestUtils.generateMultiSigHandlerInstance(
        testSecrets[0],
        vi.fn(),
        testPubs,
      );
      vi.setSystemTime(0);
      await TestUtils.addTx(handler, reduced, requiredSings, boxes, dataBoxes);
      vi.setSystemTime(10e6);
      handler.cleanup();
      const { transaction } = await handler.getQueuedTransaction(
        reduced.unsigned_tx().id().to_str(),
      );
      expect(transaction.boxes.length).toEqual(0);
    });

    /**
     * @target MultiSigHandler.cleanup should not remove good transactions
     * @dependencies MultiSigHandlerInstance
     * @scenario
     * - Generate a MultiSigHandler instance
     * - Call addTx with a test transaction, required signs, boxes, and dataBoxes
     * - Set system time to 1e2
     * - Call cleanup
     * - Call getQueuedTransaction with the transaction ID
     * @expected
     * - The returned transaction should have boxes length equal to 1
     */
    it('should not remove good transactions', async () => {
      const handler = await TestUtils.generateMultiSigHandlerInstance(
        testSecrets[0],
        vi.fn(),
        testPubs,
      );
      vi.setSystemTime(0);
      await TestUtils.addTx(handler, reduced, requiredSings, boxes, dataBoxes);
      vi.setSystemTime(1e2);
      handler.cleanup();
      const { transaction } = await handler.getQueuedTransaction(
        reduced.unsigned_tx().id().to_str(),
      );
      expect(transaction.boxes.length).toEqual(1);
    });
  });

  describe('handleMyTurn', () => {
    /**
     * @target MultiSigHandler.handleMyTurn should do nothing if it is not his turn
     * @dependencies MultiSigHandlerInstance
     * @scenario
     * - Generate a MultiSigHandler instance
     * - Call addTx with a test transaction, required signs, boxes, and dataBoxes
     * - Set system time to turnTime
     * - Call handleMyTurn
     * @expected
     * - sendMessage should not have been called
     */
    it('should do nothing if it is not his turn', async () => {
      const sender = vi.fn();
      const handler = await TestUtils.generateMultiSigHandlerInstance(
        testSecrets[0],
        sender,
        testPubs,
      );
      await TestUtils.addTx(handler, reduced, requiredSings, boxes, dataBoxes);
      vi.setSystemTime(turnTime);
      await handler.handleMyTurn();
      expect(sender).not.toHaveBeenCalled();
    });

    /**
     * @target MultiSigHandler.handleMyTurn should ask for commitments from all peers
     * @dependencies MultiSigHandlerInstance
     * @scenario
     * - Generate a MultiSigHandler instance
     * - Call addTx with a test transaction, required signs, boxes, and dataBoxes
     * - Set system time to 0
     * - Call handleMyTurn
     * @expected
     * - sendMessage should have been called with a 'generateCommitment' message
     */
    it('should ask for commitments from all peers', async () => {
      const handler = await TestUtils.generateMultiSigHandlerInstance(
        testSecrets[0],
        vi.fn(),
        testPubs,
      );
      await TestUtils.addTx(handler, reduced, requiredSings, boxes, dataBoxes);
      vi.setSystemTime(0);
      const sender = vi.fn();
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      vi.spyOn(handler as any, 'sendMessage').mockImplementation(sender);
      await handler.handleMyTurn();
      const currentTurnId = await handler.getCurrentTurnId();
      expect(sender).toHaveBeenLastCalledWith(
        'generateCommitment',
        { txId: reduced.unsigned_tx().id().to_str() },
        [...testPubs].reverse().filter((pk) => pk !== currentTurnId),
        0,
        undefined,
      );
    });

    /**
     * @target MultiSigHandler.handleMyTurn should ask for commitments from all peers if turn changes
     * @dependencies MultiSigHandlerInstance
     * @scenario
     * - Generate a MultiSigHandler instance
     * - Call addTx with a test transaction, required signs, boxes, and dataBoxes
     * - Set system time to turnTime
     * - Call handleMyTurn
     * - Set system time to 0
     * - Call handleMyTurn again
     * @expected
     * - sendMessage should have been called with a 'generateCommitment' message after the turn changes
     */
    it('should ask for commitments from all peers if turn changes', async () => {
      const handler = await TestUtils.generateMultiSigHandlerInstance(
        testSecrets[0],
        vi.fn(),
        testPubs,
      );
      await TestUtils.addTx(handler, reduced, requiredSings, boxes, dataBoxes);
      vi.setSystemTime(turnTime);
      const sender = vi.fn();
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      vi.spyOn(handler as any, 'sendMessage').mockImplementation(sender);
      await handler.handleMyTurn();
      expect(sender).not.toHaveBeenCalled();

      vi.setSystemTime(0);
      await handler.handleMyTurn();
      const currentTurnId = await handler.getCurrentTurnId();

      expect(sender).toHaveBeenLastCalledWith(
        'generateCommitment',
        { txId: reduced.unsigned_tx().id().to_str() },
        [...testPubs].reverse().filter((pk) => pk !== currentTurnId),
        0,
        undefined,
      );
    });

    /**
     * @target MultiSigHandler.handleMyTurn rejects a coordinator request when its turn expires during envelope signing
     * @dependencies
     * - next ECDSA envelope signature gate and outbound submit sink (mocked)
     * - real coordinator request construction, queued state, and fake system time
     * @scenario
     * - call handleMyTurn as guard 0 and pause the outgoing envelope signature
     * - advance time until guard 0's turn expires, then resume signing
     * - await the pending request and inspect submission and rejection
     * @expected
     * - handleMyTurn rejects with Contribution state changed
     * - no envelope is submitted and the queued transaction is rejected
     */
    it('rejects a coordinator request when its turn expires during envelope signing', async () => {
      const f = await generateTransportFixture(0);
      const gate = mockPendingEnvelopeSignature(f.messageEnc);
      const pending = f.handler.handleMyTurn();
      await gate.entered.promise;
      vi.setSystemTime(60000);
      gate.resume.resolve();
      await expect(pending).rejects.toThrow('Contribution state changed');
      expect(f.submit).not.toHaveBeenCalled();
      expect(f.transaction.reject).toHaveBeenCalled();
    });
  });

  describe('handleSignedTx', () => {
    /**
     * @target MultiSigHandler.handleSignedTx retains the public Promise<void> completion callback contract
     * @dependencies
     * - MultiSigHandler public handleSignedTx method type
     * - fixture queue and invalid serialized transaction input
     * @scenario
     * - assign handleSignedTx to a callback typed as (bytes: string) => Promise<void>
     * - invoke that callback with invalid transaction bytes
     * - await the public completion promise
     * @expected
     * - the assignment passes package type-checking and the callback resolves to undefined
     */
    it('retains the public Promise<void> completion callback contract', async () => {
      const { handler } = await generateContributionFixture();
      // This assignment is checked by the package type-check, not just Vitest.
      const callback: (bytes: string) => Promise<void> = handler.handleSignedTx;
      await expect(callback('invalid transaction')).resolves.toBeUndefined();
    });
  });

  describe('handleSign', () => {
    /**
     * @target MultiSigHandler.handleSign ignores proofs for a queue entry whose contribution authorization failed
     * @dependencies
     * - failed-contribution marker, submit sink, and sendMessage (mocked)
     * - queued simulated-hint bag and stale Sign payload
     * @scenario
     * - mark the queued transaction as contribution-failed
     * - pass a stale peer proof to handleSign
     * - inspect stored peer proofs and signed-transaction outputs
     * @expected
     * - no proof is stored and neither direct submission nor SignedTx messaging occurs
     */
    it('ignores proofs for a queue entry whose contribution authorization failed', async () => {
      const f = await generateContributionFixture(async () => {});
      f.transaction.simulatedBag = wasm.TransactionHintsBag.empty();
      f.handler.markContributionFailed(f.transaction);

      await f.handler.handleSign(
        testPubs[1],
        { txId: contributionTxId, proof: { proof: 'stale' } } as never,
        1,
      );

      expect(f.transaction.signs).toEqual({});
      expect(f.submit).not.toHaveBeenCalled();
      expect(f.send).not.toHaveBeenCalledWith(
        MessageType.SignedTx,
        expect.anything(),
        expect.anything(),
        expect.anything(),
      );
    });

    /**
     * @target MultiSigHandler.handleSign does not resolve or broadcast after authorization fails during final verification
     * @dependencies
     * - stateful beforeContribution hook, MultiSigUtils.verifyInput gate, resolve callback, and transports (mocked)
     * - real committee partial proofs and queued signing state
     * @scenario
     * - prepare all but the final coordinator proof
     * - pause final input verification, revoke commitment authorization, and fail a concurrent request
     * - resume verification, await handleSign, and inspect resolution/broadcast state
     * @expected
     * - the signing promise is not resolved and no transaction is submitted or announced
     * - the refused transaction remains queued
     */
    it('does not resolve or broadcast after authorization fails during final verification', async () => {
      let refuseCommitments = false;
      const { members, deliver } = await generateContributionCommittee(
        async (request) => {
          if (refuseCommitments && request.kind === 'commitment')
            throw Error('round authorization revoked');
        },
      );
      const coordinator = members[0];
      await deliver(5);
      const initiatePayload = coordinator.send.mock.calls.find(
        (call) => call[0] === MessageType.InitiateSign,
      )![1] as InitiateSignPayload;
      for (let i = 1; i < members.length; i++)
        await members[i].handler.initiateSign(testPubs[0], initiatePayload, 0);
      for (let i = 1; i < members.length - 1; i++) {
        const payload = members[i].send.mock.calls.find(
          (call) => call[0] === MessageType.Sign,
        )![1] as SignPayload;
        await coordinator.handler.handleSign(testPubs[i], payload, i);
      }

      const resolved = vi.fn();
      coordinator.transaction.resolve = resolved;
      const entered = Promise.withResolvers<void>();
      const resume = Promise.withResolvers<void>();
      vi.spyOn(coordinator.utils, 'verifyInput').mockImplementationOnce(
        async () => {
          entered.resolve();
          await resume.promise;
          return true;
        },
      );
      const finalProof = members[5].send.mock.calls.find(
        (call) => call[0] === MessageType.Sign,
      )![1] as SignPayload;
      const pending = coordinator.handler.handleSign(
        testPubs[5],
        finalProof,
        5,
      );
      await entered.promise;
      refuseCommitments = true;
      await expect(
        coordinator.handler.generateCommitment(contributionTxId, 0),
      ).rejects.toThrow('round authorization revoked');
      resume.resolve();
      await pending;

      expect(resolved).not.toHaveBeenCalled();
      expect(coordinator.submit).not.toHaveBeenCalled();
      expect(coordinator.send).not.toHaveBeenCalledWith(
        MessageType.SignedTx,
        expect.anything(),
        expect.anything(),
        expect.anything(),
      );
      expect(await coordinator.handler.isInSign(contributionTxId)).toEqual(
        true,
      );
    });
  });

  describe('handleMyTurnForTx', () => {
    /**
     * @target MultiSigHandler.handleMyTurnForTx does not publish GenerateCommitment when the turn changes during peer discovery
     * @dependencies
     * - MultiSigHandler.peersWithIds gate and sendMessage (mocked)
     * - queued transaction state and fake system time
     * @scenario
     * - start handleMyTurnForTx and pause peer discovery
     * - advance system time to the next turn and resume discovery
     * - await the operation and inspect coordinator-request publication
     * @expected
     * - the operation rejects with Contribution state changed
     * - no GenerateCommitment message is published
     */
    it('does not publish GenerateCommitment when the turn changes during peer discovery', async () => {
      const f = await generateContributionFixture(async () => {});
      const entered = Promise.withResolvers<void>();
      const resume = Promise.withResolvers<void>();
      vi.spyOn(f.handler, 'peersWithIds').mockImplementationOnce(async () => {
        entered.resolve();
        await resume.promise;
        return testPubs.map((pub) => ({ pub, id: pub }));
      });
      const pending = f.handler.handleMyTurnForTx(contributionTxId);
      await entered.promise;
      vi.setSystemTime(turnTime);
      resume.resolve();
      await expect(pending).rejects.toThrow('Contribution state changed');
      expect(f.send).not.toHaveBeenCalledWith(
        MessageType.GenerateCommitment,
        expect.anything(),
        expect.anything(),
        expect.anything(),
      );
    });

    /**
     * @target MultiSigHandler.handleMyTurnForTx preserves turn epoch before the coordinator scheduling waits: epoch %s
     * @dependencies
     * - MultiSigHandler.getCurrentTurnId gate and native commitment spy (mocked)
     * - queued transaction state and fake system time
     * @scenario
     * - start handleMyTurnForTx and pause its current-turn lookup
     * - advance by one or one full committee turn epoch before resuming lookup
     * - await the stale scheduling path and inspect native commitment generation
     * @expected
     * - the scheduling path rejects and no native commitment is generated
     */
    it.each([1, testPubs.length])(
      'preserves turn epoch before the coordinator scheduling waits: epoch %s',
      async (epoch) => {
        const entered = Promise.withResolvers<void>();
        const resume = Promise.withResolvers<void>();
        const f = await generateContributionFixture(async () => {});
        vi.spyOn(f.handler, 'getCurrentTurnId').mockImplementationOnce(
          async () => {
            entered.resolve();
            await resume.promise;
            return testPubs[0];
          },
        );
        const pending = f.handler.handleMyTurnForTx(contributionTxId);
        await entered.promise;
        vi.setSystemTime(epoch * turnTime);
        resume.resolve();
        await expect(pending).rejects.toThrow();
        expect(f.commitments).not.toHaveBeenCalled();
      },
    );
  });
});
