import { CommitmentPayload } from '../lib';
import { describe, expect, it, vi } from 'vitest';
import TestUtils from './testUtils/TestUtils';
import { boxJs, testCmt, testPubs, testSecrets } from './testData';
import { turnTime } from '../lib/const';
import {
  getChangeBoxJs,
  getOutBoxJs,
  jsToReducedTx,
} from './testUtils/txUtils';
import { ErgoBox } from 'ergo-lib-wasm-nodejs';
import { SenderSimulated } from './testUtils/SenderSimulated';

const fee = 1000000;
const tree =
  '0008cd03e5bedab3f782ef17a73e9bdc41ee0e18c3ab477400f35bcf7caa54171db7ff36';
const out = getOutBoxJs(tree, ['ERG', 10000000]);
const ins = [boxJs];
const dataBoxes: any = [];
const change = getChangeBoxJs(ins, [out], tree, fee);
const reduced = jsToReducedTx(ins, [out, change], dataBoxes, 1311604, fee);
const requiredSings = 6;
const boxes = ins.map((i: any) => ErgoBox.from_json(JSON.stringify(i)));

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
      const id = await handler.getCurrentTurnId();
      expect(id).toEqual(testPubs[turnInd]);
      vi.setSystemTime(turnTime);
      const turnInd2 = handler.getCurrentTurnInd();
      const id2 = await handler.getCurrentTurnId();
      expect(id2).toEqual(testPubs[turnInd2]);
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
      expect(await handler.isMyTurn()).to.be.true;
      vi.setSystemTime(turnTime);
      expect(await handler.isMyTurn()).to.be.false;
      expect(await handler2.isMyTurn()).to.be.true;
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
      const { transaction, release } = await handler.getQueuedTransaction(txId);
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
      const { transaction: transaction2, release: release2 } =
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
      const { transaction, release } = await handler.getQueuedTransaction(
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
      const { transaction, release } = await handler.getQueuedTransaction(txId);
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
      handler.generateCommitment(reduced.unsigned_tx().id().to_str());
      const { transaction, release } = await handler.getQueuedTransaction(
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
      vi.spyOn(handler as any, 'sendMessage').mockImplementation(
        mockedSendMessage,
      );
      await TestUtils.addTx(handler, reduced, requiredSings, boxes, dataBoxes);
      vi.setSystemTime(turnTime);
      await handler.generateCommitment(reduced.unsigned_tx().id().to_str());
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
      vi.spyOn(handler as any, 'sendMessage').mockImplementation(
        mockedSendMessage,
      );
      await TestUtils.addTx(handler, reduced, requiredSings, boxes, dataBoxes);

      vi.setSystemTime(turnTime);
      await handler.handleCommitment(
        '0',
        testCmt.payload as CommitmentPayload,
        testCmt.sign,
        0, // Pass the index here
      );
      expect(mockedSendMessage).not.toHaveBeenCalled();
      const { transaction, release } = await handler.getQueuedTransaction(
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
      const { transaction, release } = await handler.getQueuedTransaction(
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
        testSecrets.map((secret, index) =>
          TestUtils.generateMultiSigHandlerInstance(
            secret,
            simulatedSender.simulatedSender,
            testPubs,
          ),
        ),
      );
      const handlers = allHandlers.slice(0, 3);
      await simulatedSender.changeHandlers(handlers, testPubs);
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
          return handler.generateCommitment(
            reduced.unsigned_tx().id().to_str(),
          );
        }),
      );
      const turnHandler = handlers[0];
      const { transaction, release } = await turnHandler.getQueuedTransaction(
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
        testSecrets.map((secret, index) =>
          TestUtils.generateMultiSigHandlerInstance(
            secret,
            simulatedSender.simulatedSender,
            testPubs,
          ),
        ),
      );
      simulatedSender.changeHandlers(handlers, testPubs);
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
      const { transaction, release } = await turnHandler.getQueuedTransaction(
        reduced.unsigned_tx().id().to_str(),
      );

      expect(transaction.coordinator).toEqual(-1);
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
      const { transaction, release } = await handler.getQueuedTransaction(
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
      const { transaction, release } = await handler.getQueuedTransaction(
        reduced.unsigned_tx().id().to_str(),
      );
      expect(transaction.boxes.length).toEqual(1);
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
      vi.spyOn(handler as any, 'sendMessage').mockImplementation(sender);
      await handler.handleMyTurn();
      // expect(sender).toHaveBeenLastCalledWith({
      //   type: 'generateCommitment',
      //   payload: {
      //     txId: reduced.unsigned_tx().id().to_str(),
      //   },
      // });
      expect(sender).toHaveBeenLastCalledWith(
        'generateCommitment',
        { txId: reduced.unsigned_tx().id().to_str() },
        testPubs,
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
      vi.spyOn(handler as any, 'sendMessage').mockImplementation(sender);
      await handler.handleMyTurn();
      expect(sender).not.toHaveBeenCalled();

      vi.setSystemTime(0);
      await handler.handleMyTurn();

      expect(sender).toHaveBeenLastCalledWith(
        'generateCommitment',
        { txId: reduced.unsigned_tx().id().to_str() },
        testPubs,
        0,
      );
    });
  });
});
