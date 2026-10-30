import {
  ErgoBox,
  Transaction,
  TransactionHintsBag,
  Wallet,
} from 'ergo-lib-wasm-nodejs';
import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  CommitmentPayload,
  GenerateCommitmentPayload,
  InitiateSignPayload,
  MessageType,
  MultiSigUtils,
  PublishedCommitment,
} from '../lib';
import { turnTime as defaultTurnTime } from '../lib/const';
import { boxJs, testCmt, testPubs, testSecrets } from './testData';
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
  describe('isMyTurn', () => {
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
     * @target MultiSigHandler.getQueuedTransaction should return queued transaction
     * @dependencies
     * @scenario
     * - mock `queuedTransaction`
     * - run test
     * @expected
     * - returned value should be same as `queuedTransaction`
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
     * @target MultiSigHandler.getQueuedTransaction should return an empty transaction for new txId
     * @dependencies MultiSigHandlerInstance
     * @scenario
     * - Generate a MultiSigHandler instance
     * - Call getQueuedTransaction with a test transaction ID
     * @expected
     * - The returned transaction should have a coordinator property equal to -1
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

  describe('signTransaction', () => {
    /**
     * @target MultiSigHandler.signTransaction should put transaction into queue
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
     * @target MultiSigHandler.signTransaction should call generateCommitment
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
     * - Set system time to 0
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
      vi.setSystemTime(0);
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
  });

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
  describe('handleCommitment', () => {
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
  });

  describe('commitment secret single use', () => {
    const txId = reduced.unsigned_tx().id().to_str();
    const otherCommitment = testCmt.payload.commitment as PublishedCommitment;

    afterEach(() => {
      vi.restoreAllMocks();
    });

    /**
     * @target MultiSigHandler.initiateSign should not sign two distinct
     * transcripts with one commitment secret, but sign again with a fresh one
     * @dependencies MultiSigHandlerInstance
     * @scenario
     * - Generate a MultiSigHandler instance and mock its native signer
     * - Call addTx with a test transaction, required signs, boxes, and dataBoxes
     * - Set system time to 0
     * - Call generateCommitment for coordinator 0
     * - Call initiateSign with two payloads with different committed sets
     * - Call generateCommitment for coordinator 0 again
     * - Call initiateSign with the fresh commitment
     * @expected
     * - The native signer should have been called once before the fresh
     *   commitment and once after it
     * - sendMessage should have been called once with Sign before the fresh
     *   commitment and once after it
     */
    it('should not sign two distinct transcripts with one commitment secret, but sign again with a fresh one', async () => {
      const handler = await TestUtils.generateMultiSigHandlerInstance(
        testSecrets[1],
        vi.fn(),
        testPubs,
      );
      const mockedSendMessage = vi.fn();
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      vi.spyOn(handler as any, 'sendMessage').mockImplementation(
        mockedSendMessage,
      );
      const nativeSign = vi
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        .spyOn((handler as any).getProver(), 'sign_reduced_transaction_multi')
        .mockReturnValue({} as Transaction);
      vi.spyOn(
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        (handler as any).multiSigUtilsInstance,
        'extract_hints',
      ).mockResolvedValue(TransactionHintsBag.empty());
      await TestUtils.addTx(handler, reduced, requiredSings, boxes, dataBoxes);

      vi.setSystemTime(0);
      await handler.generateCommitment(txId, 0);
      const { transaction, release } = await handler.getQueuedTransaction(txId);
      release();
      const myCommitment = transaction.commitments[testPubs[1]];
      await handler.initiateSign(
        '0',
        {
          txId,
          committedInds: [0, 1],
          cmts: [otherCommitment, myCommitment],
          simulated: [],
          simulatedProofs: [],
        },
        0,
      );
      await handler.initiateSign(
        '0',
        {
          txId,
          committedInds: [0, 1, 2],
          cmts: [otherCommitment, myCommitment, otherCommitment],
          simulated: [],
          simulatedProofs: [],
        },
        0,
      );

      const signMessagesCount = () =>
        mockedSendMessage.mock.calls.filter(
          (args) => args[0] === MessageType.Sign,
        ).length;
      expect(nativeSign).toHaveBeenCalledTimes(1);
      expect(signMessagesCount()).toEqual(1);

      await handler.generateCommitment(txId, 0);
      await handler.initiateSign(
        '0',
        {
          txId,
          committedInds: [0, 1],
          cmts: [otherCommitment, transaction.commitments[testPubs[1]]],
          simulated: [],
          simulatedProofs: [],
        },
        0,
      );

      expect(nativeSign).toHaveBeenCalledTimes(2);
      expect(signMessagesCount()).toEqual(2);
    });

    /**
     * @target MultiSigHandler.handleCommitment should keep the commitment
     * secret consumed when signing as coordinator fails after the native call
     * @dependencies MultiSigHandlerInstance
     * @scenario
     * - Generate a MultiSigHandler instance and mock its native signers
     * - Mock hint extraction to fail after the native call
     * - Call addTx with a test transaction, 2 required signs, boxes, and dataBoxes
     * - Set system time to 0
     * - Call generateCommitment as coordinator
     * - Call handleCommitment with the commitment of guard 1
     * @expected
     * - The native signer should have been called once
     * - The tx should have no commitment secret
     * - sendMessage should not have been called with InitiateSign
     */
    it('should keep the commitment secret consumed when signing as coordinator fails after the native call', async () => {
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
      const nativeSign = vi
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        .spyOn((handler as any).getProver(), 'sign_reduced_transaction_multi')
        .mockReturnValue({} as Transaction);
      vi.spyOn(MultiSigUtils, 'getEmptyProver').mockReturnValue({
        sign_reduced_transaction_multi: () => ({}) as Transaction,
      } as unknown as Wallet);
      vi.spyOn(
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        (handler as any).multiSigUtilsInstance,
        'extract_hints',
      )
        .mockResolvedValueOnce(TransactionHintsBag.empty())
        .mockRejectedValueOnce(new Error('extraction failed'));
      await TestUtils.addTx(handler, reduced, 2, boxes, dataBoxes);

      vi.setSystemTime(0);
      await handler.generateCommitment(txId);
      await handler.handleCommitment(
        '1',
        { txId, commitment: otherCommitment },
        testCmt.sign,
        1,
      );
      const { transaction, release } = await handler.getQueuedTransaction(txId);
      release();
      expect(nativeSign).toHaveBeenCalledTimes(1);
      expect(transaction.secret).toBeUndefined();
      expect(
        mockedSendMessage.mock.calls.filter(
          (args) => args[0] === MessageType.InitiateSign,
        ).length,
      ).toEqual(0);
    });

    /**
     * @target MultiSigHandler.initiateSign should keep the commitment secret
     * consumed when signing fails after the native call
     * @dependencies MultiSigHandlerInstance
     * @scenario
     * - Generate a MultiSigHandler instance and mock its native signer
     * - Mock hint extraction to fail once
     * - Call addTx with a test transaction, required signs, boxes, and dataBoxes
     * - Set system time to 0
     * - Call generateCommitment for coordinator 0
     * - Call initiateSign twice with the same payload
     * @expected
     * - The native signer should have been called once
     * - The tx should have no commitment secret
     * - sendMessage should not have been called with Sign
     */
    it('should keep the commitment secret consumed when signing fails after the native call', async () => {
      const handler = await TestUtils.generateMultiSigHandlerInstance(
        testSecrets[1],
        vi.fn(),
        testPubs,
      );
      const mockedSendMessage = vi.fn();
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      vi.spyOn(handler as any, 'sendMessage').mockImplementation(
        mockedSendMessage,
      );
      const nativeSign = vi
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        .spyOn((handler as any).getProver(), 'sign_reduced_transaction_multi')
        .mockReturnValue({} as Transaction);
      vi.spyOn(
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        (handler as any).multiSigUtilsInstance,
        'extract_hints',
      )
        .mockRejectedValueOnce(new Error('extraction failed'))
        .mockResolvedValue(TransactionHintsBag.empty());
      await TestUtils.addTx(handler, reduced, requiredSings, boxes, dataBoxes);

      vi.setSystemTime(0);
      await handler.generateCommitment(txId, 0);
      const { transaction, release } = await handler.getQueuedTransaction(txId);
      release();
      const payload: InitiateSignPayload = {
        txId,
        committedInds: [0, 1],
        cmts: [otherCommitment, transaction.commitments[testPubs[1]]],
        simulated: [],
        simulatedProofs: [],
      };
      await handler.initiateSign('0', payload, 0);
      await handler.initiateSign('0', payload, 0);

      expect(nativeSign).toHaveBeenCalledTimes(1);
      expect(transaction.secret).toBeUndefined();
      expect(
        mockedSendMessage.mock.calls.filter(
          (args) => args[0] === MessageType.Sign,
        ).length,
      ).toEqual(0);
    });

    /**
     * @target MultiSigHandler.initiateSign should reject a sender other than
     * the tx coordinator without consuming the commitment secret
     * @dependencies MultiSigHandlerInstance
     * @scenario
     * - Generate a MultiSigHandler instance and mock its native signer
     * - Call addTx with a test transaction, required signs, boxes, and dataBoxes
     * - Set system time to 0
     * - Call generateCommitment for coordinator 0
     * - Set system time to the turn of guard 2
     * - Call initiateSign from guard 2
     * @expected
     * - The native signer should not have been called
     * - The tx should still have its commitment secret
     */
    it('should reject a sender other than the tx coordinator without consuming the commitment secret', async () => {
      const handler = await TestUtils.generateMultiSigHandlerInstance(
        testSecrets[1],
        vi.fn(),
        testPubs,
      );
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      vi.spyOn(handler as any, 'sendMessage').mockImplementation(vi.fn());
      const nativeSign = vi
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        .spyOn((handler as any).getProver(), 'sign_reduced_transaction_multi')
        .mockReturnValue({} as Transaction);
      await TestUtils.addTx(handler, reduced, requiredSings, boxes, dataBoxes);

      vi.setSystemTime(0);
      await handler.generateCommitment(txId, 0);
      const { transaction, release } = await handler.getQueuedTransaction(txId);
      release();
      vi.setSystemTime(2 * turnTime);
      await handler.initiateSign(
        '2',
        {
          txId,
          committedInds: [2, 1],
          cmts: [otherCommitment, transaction.commitments[testPubs[1]]],
          simulated: [],
          simulatedProofs: [],
        },
        2,
      );

      expect(nativeSign).not.toHaveBeenCalled();
      expect(transaction.secret).toBeDefined();
    });

    /**
     * @target MultiSigHandler.initiateSign should reject transcripts without
     * its current commitment without consuming the commitment secret
     * @dependencies MultiSigHandlerInstance
     * @scenario
     * - Generate a MultiSigHandler instance and mock its native signer
     * - Call addTx with a test transaction, required signs, boxes, and dataBoxes
     * - Set system time to 0
     * - Call generateCommitment for coordinator 0
     * - Call initiateSign with payloads which replace its commitment, omit
     *   it, duplicate an index and mismatch the commitments count
     * @expected
     * - The native signer should not have been called
     * - The tx should still have its commitment secret
     */
    it('should reject transcripts without its current commitment without consuming the commitment secret', async () => {
      const handler = await TestUtils.generateMultiSigHandlerInstance(
        testSecrets[1],
        vi.fn(),
        testPubs,
      );
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      vi.spyOn(handler as any, 'sendMessage').mockImplementation(vi.fn());
      const nativeSign = vi
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        .spyOn((handler as any).getProver(), 'sign_reduced_transaction_multi')
        .mockReturnValue({} as Transaction);
      await TestUtils.addTx(handler, reduced, requiredSings, boxes, dataBoxes);

      vi.setSystemTime(0);
      await handler.generateCommitment(txId, 0);
      const { transaction, release } = await handler.getQueuedTransaction(txId);
      release();
      const myCommitment = transaction.commitments[testPubs[1]];
      const invalidPayloads: Array<
        Pick<InitiateSignPayload, 'committedInds' | 'cmts'>
      > = [
        { committedInds: [0, 1], cmts: [otherCommitment, otherCommitment] },
        { committedInds: [0], cmts: [otherCommitment] },
        { committedInds: [1, 1], cmts: [myCommitment, myCommitment] },
        { committedInds: [1, 0], cmts: [myCommitment] },
      ];
      for (const invalidPayload of invalidPayloads) {
        await handler.initiateSign(
          '0',
          { txId, ...invalidPayload, simulated: [], simulatedProofs: [] },
          0,
        );
      }

      expect(nativeSign).not.toHaveBeenCalled();
      expect(transaction.secret).toBeDefined();
    });

    /**
     * @target MultiSigHandler.generateCommitment should not keep the previous
     * round commitment secret when generating a new one fails
     * @dependencies MultiSigHandlerInstance
     * @scenario
     * - Generate a MultiSigHandler instance
     * - Call addTx with a test transaction, required signs, boxes, and dataBoxes
     * - Set system time to 0
     * - Call generateCommitment for coordinator 0
     * - Mock commitment generation to fail once
     * - Set system time to the turn of guard 2
     * - Call generateCommitment for coordinator 2
     * @expected
     * - generateCommitment should throw
     * - The tx should have no commitment secret
     */
    it('should not keep the previous round commitment secret when generating a new one fails', async () => {
      const handler = await TestUtils.generateMultiSigHandlerInstance(
        testSecrets[1],
        vi.fn(),
        testPubs,
      );
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      vi.spyOn(handler as any, 'sendMessage').mockImplementation(vi.fn());
      await TestUtils.addTx(handler, reduced, requiredSings, boxes, dataBoxes);

      vi.setSystemTime(0);
      await handler.generateCommitment(txId, 0);
      vi.spyOn(
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        (handler as any).getProver(),
        'generate_commitments_for_reduced_transaction',
      ).mockImplementationOnce(() => {
        throw new Error('generation failed');
      });
      vi.setSystemTime(2 * turnTime);
      await expect(handler.generateCommitment(txId, 2)).rejects.toThrow(
        'generation failed',
      );

      const { transaction, release } = await handler.getQueuedTransaction(txId);
      release();
      expect(transaction.secret).toBeUndefined();
    });
  });

  describe('generateCommitment admission', () => {
    const txId = reduced.unsigned_tx().id().to_str();

    afterEach(() => {
      vi.restoreAllMocks();
    });

    /**
     * @target MultiSigHandler.generateCommitment should ignore a request from
     * a guard which does not have the turn
     * @dependencies MultiSigHandlerInstance
     * @scenario
     * - Generate a MultiSigHandler instance with the tx in its queue
     * - Set system time to the turn of guard 0
     * - Call generateCommitment for coordinator 2
     * @expected
     * - generateCommitment should return false
     * - sendMessage should not have been called
     * - The tx should have no coordinator, commitment secret or commitments
     */
    it('should ignore a request from a guard which does not have the turn', async () => {
      const handler = await TestUtils.generateMultiSigHandlerInstance(
        testSecrets[1],
        vi.fn(),
        testPubs,
      );
      const sendMessage = vi
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        .spyOn(handler as any, 'sendMessage')
        .mockResolvedValue(undefined);
      await TestUtils.addTx(handler, reduced, requiredSings, boxes, dataBoxes);

      vi.setSystemTime(0);
      expect(await handler.generateCommitment(txId, 2)).toEqual(false);

      expect(sendMessage).not.toHaveBeenCalled();
      const { transaction, release } = await handler.getQueuedTransaction(txId);
      release();
      expect(transaction.coordinator).toEqual(-1);
      expect(transaction.secret).toBeUndefined();
      expect(transaction.commitments).toEqual({});
    });

    /**
     * @target MultiSigHandler.generateCommitment should not change the tx
     * while another handler holds the semaphore
     * @dependencies MultiSigHandlerInstance
     * @scenario
     * - Generate a MultiSigHandler instance with the tx in its queue
     * - Hold the semaphore by getting the queued tx
     * - Call generateCommitment for the coordinator with the current turn
     * - Release the semaphore
     * @expected
     * - The tx should not change while the semaphore is held
     * - The tx should have a commitment secret and coordinator after release
     */
    it('should not change the tx while another handler holds the semaphore', async () => {
      const handler = await TestUtils.generateMultiSigHandlerInstance(
        testSecrets[1],
        vi.fn(),
        testPubs,
      );
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      vi.spyOn(handler as any, 'sendMessage').mockResolvedValue(undefined);
      await TestUtils.addTx(handler, reduced, requiredSings, boxes, dataBoxes);

      vi.setSystemTime(0);
      const { transaction, release } = await handler.getQueuedTransaction(txId);
      const generating = handler.generateCommitment(txId, 0);
      await new Promise((resolve) => setTimeout(resolve, 10));
      expect(transaction.coordinator).toEqual(-1);
      expect(transaction.secret).toBeUndefined();

      release();
      expect(await generating).toEqual(true);
      expect(transaction.coordinator).toEqual(0);
      expect(transaction.secret).toBeDefined();
    });

    /**
     * @target MultiSigHandler.handleMyTurnForTx should start one round when
     * called concurrently for the same tx
     * @dependencies MultiSigHandlerInstance
     * @scenario
     * - Generate a MultiSigHandler instance with the tx in its queue
     * - Set system time to its turn
     * - Call handleMyTurnForTx twice concurrently
     * @expected
     * - A commitment should be generated once
     * - GenerateCommitment should be sent once
     */
    it('should start one round when called concurrently for the same tx', async () => {
      const handler = await TestUtils.generateMultiSigHandlerInstance(
        testSecrets[0],
        vi.fn(),
        testPubs,
      );
      const sendMessage = vi
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        .spyOn(handler as any, 'sendMessage')
        .mockResolvedValue(undefined);
      await TestUtils.addTx(handler, reduced, requiredSings, boxes, dataBoxes);
      const generate = vi.spyOn(
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        (handler as any).getProver(),
        'generate_commitments_for_reduced_transaction',
      );

      vi.setSystemTime(0);
      await Promise.all([
        handler.handleMyTurnForTx(txId),
        handler.handleMyTurnForTx(txId),
      ]);

      expect(generate).toHaveBeenCalledTimes(1);
      expect(
        sendMessage.mock.calls.filter(
          (args) => args[0] === MessageType.GenerateCommitment,
        ).length,
      ).toEqual(1);
    });

    /**
     * @target MultiSigHandler.generateCommitment should ignore a request when
     * the turn changes while waiting for the semaphore
     * @dependencies MultiSigHandlerInstance
     * @scenario
     * - Generate a MultiSigHandler instance with the tx in its queue
     * - Set system time to 0
     * - Hold the semaphore by getting the queued tx
     * - Call generateCommitment for coordinator 0 and as coordinator itself
     * - Set system time to turnTime and release the semaphore
     * @expected
     * - Both generateCommitment calls should return false
     * - The tx should have no coordinator, commitment secret or commitments
     * - sendMessage should not have been called
     */
    it('should ignore a request when the turn changes while waiting for the semaphore', async () => {
      const handler = await TestUtils.generateMultiSigHandlerInstance(
        testSecrets[0],
        vi.fn(),
        testPubs,
      );
      const sendMessage = vi
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        .spyOn(handler as any, 'sendMessage')
        .mockResolvedValue(undefined);
      await TestUtils.addTx(handler, reduced, requiredSings, boxes, dataBoxes);

      vi.setSystemTime(0);
      const { transaction, release } = await handler.getQueuedTransaction(txId);
      const fromCoordinator = handler.generateCommitment(txId, 0);
      const fromSelf = handler.generateCommitment(txId);
      await new Promise((resolve) => setTimeout(resolve, 10));
      vi.setSystemTime(turnTime);
      release();

      expect(await fromCoordinator).toEqual(false);
      expect(await fromSelf).toEqual(false);
      expect(transaction.coordinator).toEqual(-1);
      expect(transaction.secret).toBeUndefined();
      expect(transaction.commitments).toEqual({});
      expect(sendMessage).not.toHaveBeenCalled();
    });

    /**
     * @target MultiSigHandler.handleMyTurn should retry a tx and continue with
     * other txs when generating its commitment fails
     * @dependencies MultiSigHandlerInstance
     * @scenario
     * - Generate a MultiSigHandler instance with two txs in its queue
     * - Mock commitment generation to fail once
     * - Set system time to 0
     * - Call handleMyTurn
     * - Call handleMyTurnForTx for the failed tx
     * @expected
     * - GenerateCommitment should be sent for the second tx by handleMyTurn
     * - GenerateCommitment should be sent for the failed tx on retry
     * - Both txs should have this guard as coordinator and a commitment secret
     */
    it('should retry a tx and continue with other txs when generating its commitment fails', async () => {
      const handler = await TestUtils.generateMultiSigHandlerInstance(
        testSecrets[0],
        vi.fn(),
        testPubs,
      );
      const sendMessage = vi
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        .spyOn(handler as any, 'sendMessage')
        .mockResolvedValue(undefined);
      await TestUtils.addTx(handler, reduced, requiredSings, boxes, dataBoxes);
      const otherTxId = 'otherTx';
      const other = await handler.getQueuedTransaction(otherTxId);
      other.transaction.tx = reduced;
      other.transaction.boxes = boxes;
      other.transaction.requiredSigner = requiredSings;
      other.release();
      vi.spyOn(
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        (handler as any).getProver(),
        'generate_commitments_for_reduced_transaction',
      ).mockImplementationOnce(() => {
        throw new Error('generation failed');
      });

      vi.setSystemTime(0);
      await handler.handleMyTurn();
      const sentTxIds = () =>
        sendMessage.mock.calls
          .filter((args) => args[0] === MessageType.GenerateCommitment)
          .map((args) => (args[1] as GenerateCommitmentPayload).txId);
      expect(sentTxIds()).toEqual([otherTxId]);

      await handler.handleMyTurnForTx(txId);
      expect(sentTxIds()).toEqual([otherTxId, txId]);
      for (const id of [txId, otherTxId]) {
        const { transaction, release } = await handler.getQueuedTransaction(id);
        release();
        expect(transaction.coordinator).toEqual(0);
        expect(transaction.secret).toBeDefined();
      }
    });
  });

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
  describe('cleanup', () => {
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

  describe('turn no-work time', () => {
    const txId = reduced.unsigned_tx().id().to_str();
    const otherCommitment = testCmt.payload.commitment as PublishedCommitment;

    afterEach(() => {
      vi.restoreAllMocks();
    });

    /**
     * @target MultiSigHandler should not be created with a turn no-work time
     * which is not shorter than the turn time
     * @dependencies MultiSigHandlerInstance
     * @scenario
     * - Generate a MultiSigHandler instance with turnNoWork equal to turnTime
     * @expected
     * - Generating the instance should throw
     */
    it('should not be created with a turn no-work time which is not shorter than the turn time', async () => {
      await expect(
        TestUtils.generateMultiSigHandlerInstance(
          testSecrets[0],
          vi.fn(),
          testPubs,
          { turnTime: 60, turnNoWork: 60 },
        ),
      ).rejects.toThrow();
    });

    /**
     * @target MultiSigHandler.handleMyTurnForTx should not start a round when
     * the no-work time starts while waiting for the semaphore
     * @dependencies MultiSigHandlerInstance
     * @scenario
     * - Generate a MultiSigHandler instance
     * - Call addTx with a test transaction, required signs, boxes, and dataBoxes
     * - Set system time to 0
     * - Hold the semaphore by getting the queued tx
     * - Call handleMyTurnForTx
     * - Set system time to the no-work time of turn 0 and release the semaphore
     * @expected
     * - sendMessage should not have been called
     * - The tx should have no coordinator or commitment secret
     */
    it('should not start a round when the no-work time starts while waiting for the semaphore', async () => {
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
      const { transaction, release } = await handler.getQueuedTransaction(txId);
      const starting = handler.handleMyTurnForTx(txId);
      await new Promise((resolve) => setTimeout(resolve, 10));
      vi.setSystemTime(turnTime - 1);
      release();
      await starting;

      expect(mockedSendMessage).not.toHaveBeenCalled();
      expect(transaction.coordinator).toEqual(-1);
      expect(transaction.secret).toBeUndefined();
    });

    /**
     * @target MultiSigHandler.handleMyTurnForTx should not start a round in
     * the no-work time of the turn
     * @dependencies MultiSigHandlerInstance
     * @scenario
     * - Generate a MultiSigHandler instance
     * - Call addTx with a test transaction, required signs, boxes, and dataBoxes
     * - Set system time to the no-work time of turn 0
     * - Call handleMyTurnForTx
     * @expected
     * - sendMessage should not have been called
     * - The tx should have no coordinator or commitment secret
     */
    it('should not start a round in the no-work time of the turn', async () => {
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

      vi.setSystemTime(turnTime - 1);
      await handler.handleMyTurnForTx(txId);

      expect(mockedSendMessage).not.toHaveBeenCalled();
      const { transaction, release } = await handler.getQueuedTransaction(txId);
      release();
      expect(transaction.coordinator).toEqual(-1);
      expect(transaction.secret).toBeUndefined();
    });

    /**
     * @target MultiSigHandler.handleCommitment should not initiate sign in the
     * no-work time of the turn
     * @dependencies MultiSigHandlerInstance
     * @scenario
     * - Generate a MultiSigHandler instance and mock its native signers
     * - Call addTx with a test transaction, 2 required signs, boxes, and dataBoxes
     * - Set system time to 0
     * - Call generateCommitment as coordinator
     * - Set system time to the no-work time of turn 0
     * - Call handleCommitment with the commitment of guard 1
     * @expected
     * - The native signer should not have been called
     * - The tx should still have its commitment secret
     * - sendMessage should not have been called
     */
    it('should not initiate sign in the no-work time of the turn', async () => {
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
      const nativeSign = vi
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        .spyOn((handler as any).getProver(), 'sign_reduced_transaction_multi')
        .mockReturnValue({} as Transaction);
      vi.spyOn(MultiSigUtils, 'getEmptyProver').mockReturnValue({
        sign_reduced_transaction_multi: () => ({}) as Transaction,
      } as unknown as Wallet);
      vi.spyOn(
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        (handler as any).multiSigUtilsInstance,
        'extract_hints',
      ).mockResolvedValue(TransactionHintsBag.empty());
      await TestUtils.addTx(handler, reduced, 2, boxes, dataBoxes);

      vi.setSystemTime(0);
      await handler.generateCommitment(txId);
      vi.setSystemTime(turnTime - 1);
      await handler.handleCommitment(
        '1',
        { txId, commitment: otherCommitment },
        testCmt.sign,
        1,
      );

      expect(nativeSign).not.toHaveBeenCalled();
      const { transaction, release } = await handler.getQueuedTransaction(txId);
      release();
      expect(transaction.secret).toBeDefined();
      expect(mockedSendMessage).not.toHaveBeenCalled();
    });

    /**
     * @target MultiSigHandler.handleCommitment should not initiate sign after
     * the turn of this guard is over
     * @dependencies MultiSigHandlerInstance
     * @scenario
     * - Generate a MultiSigHandler instance and mock its native signers
     * - Call addTx with a test transaction, 2 required signs, boxes, and dataBoxes
     * - Set system time to 0
     * - Call generateCommitment as coordinator
     * - Set system time to turnTime
     * - Call handleCommitment with the commitment of guard 1
     * @expected
     * - The native signer should not have been called
     * - The tx should still have its commitment secret
     * - sendMessage should not have been called
     */
    it('should not initiate sign after the turn of this guard is over', async () => {
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
      const nativeSign = vi
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        .spyOn((handler as any).getProver(), 'sign_reduced_transaction_multi')
        .mockReturnValue({} as Transaction);
      vi.spyOn(MultiSigUtils, 'getEmptyProver').mockReturnValue({
        sign_reduced_transaction_multi: () => ({}) as Transaction,
      } as unknown as Wallet);
      vi.spyOn(
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        (handler as any).multiSigUtilsInstance,
        'extract_hints',
      ).mockResolvedValue(TransactionHintsBag.empty());
      await TestUtils.addTx(handler, reduced, 2, boxes, dataBoxes);

      vi.setSystemTime(0);
      await handler.generateCommitment(txId);
      vi.setSystemTime(turnTime);
      await handler.handleCommitment(
        '1',
        { txId, commitment: otherCommitment },
        testCmt.sign,
        1,
      );

      expect(nativeSign).not.toHaveBeenCalled();
      const { transaction, release } = await handler.getQueuedTransaction(txId);
      release();
      expect(transaction.secret).toBeDefined();
      expect(mockedSendMessage).not.toHaveBeenCalled();
    });
  });

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
  describe('handleMyTurn', () => {
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
      );
    });
  });
});
