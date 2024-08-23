import { MultiSigUtils } from '../lib';
import { describe, it, vi, expect } from 'vitest';
import TestUtils from './testUtils/TestUtils';
import { boxJs, testPubs, testSecrets } from './testData';
import TestConfigs from './testUtils/TestConfigs';
import { turnTime } from '../lib/const';
import { getChangeBoxJs, getOutBoxJs, jsToReducedTx } from './testUtils/txUtils';
import { ErgoBox } from 'ergo-lib-wasm-nodejs';


const fee = 1000000
const tree = "0008cd03e5bedab3f782ef17a73e9bdc41ee0e18c3ab477400f35bcf7caa54171db7ff36"
const out = getOutBoxJs(tree, ['ERG', 10000000])
const ins = [boxJs]
const dataBoxes: any = []
const change = getChangeBoxJs(ins, [out], tree, fee)
const reduced = jsToReducedTx(ins, [out, change], dataBoxes, 1311604, fee)
const requiredSings = 6
const boxes = ins.map((i: any) => ErgoBox.from_json(JSON.stringify(i)))


const senderMock = (expectedType: string, expectedPayload: any) => {
  return async (msg: string, peers: string[]) => {
    const msgJson = JSON.parse(msg);
    expect(msgJson.type).toEqual(expectedType);
    expect(msgJson.payload).toEqual(expectedPayload);
  };
}

describe('MultiSigUtils', () => {
  describe('publicKeyToProposition', () => {
    /**
     * @target MultiSigUtils.publicKeyToProposition should run without any error
     * @dependencies
     * @scenario
     * - run test with mocked public keys
     * @expected
     * - no error has been thrown
     */
    it('should run without any error', () => {
      MultiSigUtils.publicKeyToProposition([
        '028d938d67befbb8ab3513c44886c16c2bcd62ed4595b9b216b20ef03eb8fb8fb8',
        '03074e09c476bb215dc3aeff908d0b7691895a99dfc3bd950fa629defe541e0364',
        '0300e8750a242ee7d78f5b458e1f7474bd884d2b7894676412ba6b5f319d2ee410',
        '023a5b48c87cd9fece23f5acd08cb464ceb9d76e3c1ddac08206980a295546bb2e'
      ]);
    });
  });

  describe('comparePublishedCommitmentsToBeDiffer', () => {
    /**
     * @target MultiSigUtils.comparePublishedCommitmentsToBeDiffer should return
     * false when two published commitments are same
     * @dependencies
     * @scenario
     * - mock two similar commitments
     * - run test
     * - check retuned value
     * @expected
     * - returned value should be false
     */
    it('should return false when two published commitments are same', () => {
      const firstPublishedCommitment = {
        '0': [
          { a: '20', position: '0-0' },
          { a: '10', position: '0-3' },
          { a: '30', position: '0-11' }
        ],
        '1': [
          { a: '31', position: '0-1' },
          { a: '21', position: '0-4' },
          { a: '11', position: '0-12' }
        ],
        '2': [
          { a: '52', position: '0-5' },
          { a: '51', position: '0-9' },
          { a: '55', position: '0-13' }
        ]
      };
      const secondPublishedCommitment = {
        '1': [
          { a: '21', position: '0-4' },
          { a: '11', position: '0-12' },
          { a: '31', position: '0-1' }
        ],
        '2': [
          { a: '51', position: '0-9' },
          { a: '55', position: '0-13' },
          { a: '52', position: '0-5' }
        ],
        '0': [
          { a: '10', position: '0-3' },
          { a: '20', position: '0-0' },
          { a: '30', position: '0-11' }
        ]
      };
      const res = MultiSigUtils.comparePublishedCommitmentsToBeDiffer(
        firstPublishedCommitment,
        secondPublishedCommitment,
        3
      );
      expect(res).to.be.false;
    });

    /**
     * @target MultiSigUtils.comparePublishedCommitmentsToBeDiffer should return
     * true when two published commitments have different length
     * @dependencies
     * @scenario
     * - mock two commitments with different length
     * - run test
     * - check retuned value
     * @expected
     * - returned value should be true
     */
    it('should return true when two published commitments have different length', () => {
      const firstPublishedCommitment = {
        '0': [
          { a: '20', position: '0-0' },
          { a: '10', position: '0-3' },
          { a: '30', position: '0-11' }
        ],
        '1': [
          { a: '31', position: '0-1' },
          { a: '21', position: '0-4' },
          { a: '11', position: '0-12' }
        ],
        '2': [
          { a: '52', position: '0-5' },
          { a: '51', position: '0-9' },
          { a: '55', position: '0-13' }
        ]
      };
      const secondPublishedCommitment = {
        '1': [
          { a: '11', position: '0-12' },
          { a: '31', position: '0-1' }
        ],
        '2': [
          { a: '51', position: '0-9' },
          { a: '55', position: '0-13' },
          { a: '52', position: '0-5' }
        ],
        '0': [
          { a: '10', position: '0-3' },
          { a: '20', position: '0-0' },
          { a: '30', position: '0-11' }
        ]
      };
      const res = MultiSigUtils.comparePublishedCommitmentsToBeDiffer(
        firstPublishedCommitment,
        secondPublishedCommitment,
        3
      );
      expect(res).to.be.true;
    });

    /**
     * @target MultiSigUtils.comparePublishedCommitmentsToBeDiffer should return
     * true when two published commitments have different value
     * @dependencies
     * @scenario
     * - mock two commitments with different value
     * - run test
     * - check retuned value
     * @expected
     * - returned value should be true
     */
    it('should return true when two published commitments have different value', () => {
      const firstPublishedCommitment = {
        '0': [
          { a: '20', position: '0-0' },
          { a: '12', position: '0-3' },
          { a: '30', position: '0-11' }
        ],
        '1': [
          { a: '31', position: '0-1' },
          { a: '21', position: '0-4' },
          { a: '11', position: '0-12' }
        ],
        '2': [
          { a: '52', position: '0-5' },
          { a: '51', position: '0-9' },
          { a: '55', position: '0-13' }
        ]
      };
      const secondPublishedCommitment = {
        '1': [
          { a: '21', position: '0-4' },
          { a: '11', position: '0-12' },
          { a: '31', position: '0-1' }
        ],
        '2': [
          { a: '51', position: '0-9' },
          { a: '55', position: '0-13' },
          { a: '52', position: '0-5' }
        ],
        '0': [
          { a: '10', position: '0-3' },
          { a: '20', position: '0-0' },
          { a: '30', position: '0-11' }
        ]
      };
      const res = MultiSigUtils.comparePublishedCommitmentsToBeDiffer(
        firstPublishedCommitment,
        secondPublishedCommitment,
        3
      );
      expect(res).to.be.true;
    });
  });

  describe('compareSingleInputCommitmentsAreEquals', () => {
    /**
     * @target MultiSigUtils.compareSingleInputCommitmentsAreEquals should return
     * true when two commitments are same
     * @dependencies
     * @scenario
     * - mock two similar commitments
     * - run test
     * - check retuned value
     * @expected
     * - returned value should be true
     */
    it('should return true when two commitments are same', () => {
      const firstCommitments = [
        { a: '2', position: '0-2' },
        { a: '1', position: '0-1' },
        { a: '3', position: '0-3' }
      ];
      const secondCommitments = [
        { a: '3', position: '0-3' },
        { a: '2', position: '0-2' },
        { a: '1', position: '0-1' }
      ];
      const res = MultiSigUtils.compareSingleInputCommitmentsAreEquals(
        firstCommitments,
        secondCommitments
      );
      expect(res).to.be.true;
    });

    /**
     * @target MultiSigUtils.compareSingleInputCommitmentsAreEquals should return
     * false when two commitments are different
     * @dependencies
     * @scenario
     * - mock two different commitments
     * - run test
     * - check retuned value
     * @expected
     * - returned value should be false
     */
    it('should return false when two commitments are different', () => {
      const firstCommitments = [
        { a: '1', position: '0-2' },
        { a: '1', position: '0-1' },
        { a: '3', position: '0-3' }
      ];
      const secondCommitments = [
        { a: '3', position: '0-3' },
        { a: '2', position: '0-2' },
        { a: '1', position: '0-1' }
      ];
      const res = MultiSigUtils.compareSingleInputCommitmentsAreEquals(
        firstCommitments,
        secondCommitments
      );
      expect(res).to.be.false;
    });
  });

  describe('getCurrentTurnInd', () => {
    it('should return current turn index', async () => {
      const sender = vi.fn();
      const handler = await TestUtils.generateMultiSigHandlerInstance(testSecrets[0], sender, testPubs);
      vi.setSystemTime(0);
      expect(handler.getCurrentTurnInd()).to.equal(0);
      vi.setSystemTime(turnTime);
      expect(handler.getCurrentTurnInd()).to.equal(1);
      vi.setSystemTime(turnTime * testPubs.length + 1);
      expect(handler.getCurrentTurnInd()).to.equal(0);
    });
  });

  describe('isMyTurn', () => {
    it('should return true if it is my turn', async () => {
      const sender = vi.fn();
      const handler = await TestUtils.generateMultiSigHandlerInstance(testSecrets[0], sender, testPubs);
      const handler2 = await TestUtils.generateMultiSigHandlerInstance(testSecrets[1], sender, testPubs);
      vi.setSystemTime(0);
      expect(handler.isMyTurn()).to.be.true;
      vi.setSystemTime(turnTime);
      expect(handler.isMyTurn()).to.be.false;
      expect(handler2.isMyTurn()).to.be.true;
    });
  });

  describe('getIndex', () => {
    it('should return index of the handler', async () => {
      for (let i = 0; i < testPubs.length; i++) {
        const sender = vi.fn();
        const handler = await TestUtils.generateMultiSigHandlerInstance(testSecrets[i], sender, testPubs);
        expect(handler.getIndex()).to.equal(i);
      }
    });
  })

  describe('handleRegister', () => {
    /**
     * @target MultiSigHandler.handleRegister should handle and send response successfully
     * @dependencies
     * @scenario
     * - mock MultiSigHandler.sendMessage
     * - run test
     * - check if function got called
     * @expected
     * - `sendMessage` should got called
     */
    it('should handle and send response successfully', async () => {
      // mock MultiSigHandler.sendMessage
      const handler = await TestUtils.generateMultiSigHandlerInstance(testSecrets[0], vi.fn(), testPubs);
      const mockedSendMessage = vi.fn();
      vi.spyOn(handler, 'sendMessage').mockImplementation(mockedSendMessage);

      // run test
      await handler.handleRegister('sender', {
        index: 1,
        nonce: 'nonce',
        myId: 'myId',
      });

      // check if function got called
      expect(mockedSendMessage).toHaveBeenCalledOnce();
    });
  });

  describe('handlePublicKeysChange', () => {
    const updatedPublicKeys = [
      '028d938d67befbb8ab3513c44886c16c2bcd62ed4595b9b216b20ef03eb8fb8fb1',
      '028d938d67befbb8ab3513c44886c16c2bcd62ed4595b9b216b20ef03eb8fb8fb2',
      '028d938d67befbb8ab3513c44886c16c2bcd62ed4595b9b216b20ef03eb8fb8fb3',
      '028d938d67befbb8ab3513c44886c16c2bcd62ed4595b9b216b20ef03eb8fb8fb4',
      '028d938d67befbb8ab3513c44886c16c2bcd62ed4595b9b216b20ef03eb8fb8fb5',
      '028d938d67befbb8ab3513c44886c16c2bcd62ed4595b9b216b20ef03eb8fb8fb6',
      '028d938d67befbb8ab3513c44886c16c2bcd62ed4595b9b216b20ef03eb8fb8fb7',
    ];

    /**
     * @target MultiSigHandler.handlePublicKeysChange should update peers
     * and send register message
     * @dependencies
     * @scenario
     * - mock `sendRegister`
     * - run test
     * - check if new index is verified
     * - check if function got called
     * @expected
     * - index 6 should get verified
     * - `sendRegister` should got called
     */
    it('should update peers and send register message', async () => {
      // mock `sendRegister`
      const handler = await TestUtils.generateMultiSigHandlerInstance(testSecrets[0], vi.fn(), testPubs);
      const mockedSendRegister = vi.fn();
      vi.spyOn(handler, 'sendRegister').mockImplementation(mockedSendRegister);

      handler.handlePublicKeysChange(updatedPublicKeys);

      // check if new index is verified
      expect(handler.verifyIndex(6)).toEqual(true);

      // check if function got called
      expect(mockedSendRegister).toHaveBeenCalledOnce();
    });
  });

  describe('handleApprove', () => {
    /**
     * @target MultiSigHandler.handleApprove should send message with
     * expected keys
     * @dependencies
     * - Dialer
     * @scenario
     * - mock Dialer.sendMessage to throw error if expectation does not meet
     * - run test
     * @expected
     * - sent message should contain 'type', 'sign' and 'payload' key
     * - sent message payload should contain 'nonceToSign'
     */
    it('should send message with expected keys', async () => {
      // mock Dialer.sendMessage

      // run test
      const sender = senderMock('approve', {
        index: 0,
        nonce: '1',
        myId: testPubs[0],
        nonceToSign: '',
        id: testPubs[0],
      });
      const handler = await TestUtils.generateMultiSigHandlerInstance(testSecrets[0], sender, testPubs);
      handler.handleApprove('sender', {
        index: 1,
        nonce: 'nonce',
        myId: testPubs[1],
        nonceToSign: '1',
      });
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
      const handler = await TestUtils.generateMultiSigHandlerInstance(testSecrets[0], vi.fn(), testPubs);
      const txId = 'test'
      const { transaction, release } = await handler.getQueuedTransaction(txId)
      expect(transaction.coordinator).toEqual(-1);
    });

    it('should return the queued transaction', async () => {
      // mock `queuedTransaction`
      const handler = await TestUtils.generateMultiSigHandlerInstance(testSecrets[0], vi.fn(), testPubs);
      const txId = 'test'
      const { transaction, release } = await handler.getQueuedTransaction(txId)
      transaction.coordinator = 1;
      release();
      const { transaction: transaction2, release: release2 } = await handler.getQueuedTransaction(txId)
      expect(transaction2.coordinator).toEqual(1);
    });
  })

  describe('signTransaction', () => {
    it('should put transaction into queue', async () => {
      // mock `sign`
      const handler = await TestUtils.generateMultiSigHandlerInstance(testSecrets[0], vi.fn(), testPubs);
      const mockedGenerateCmt = vi.fn();
      vi.spyOn(handler, 'generateCommitment').mockImplementation(mockedGenerateCmt);

      // run test
      handler.sign(reduced, requiredSings, boxes, dataBoxes).then(() => {})
      const { transaction, release } = await handler.getQueuedTransaction(reduced.unsigned_tx().id().to_str())
      expect(transaction.boxes.length).toEqual(1);
      expect(transaction.requiredSigner).toEqual(6);
    });

    it('should call generateCommitment', async () => {
      // mock `sign`
      const handler = await TestUtils.generateMultiSigHandlerInstance(testSecrets[0], vi.fn(), testPubs);
      const mockedGenerateCmt = vi.fn();
      vi.spyOn(handler, 'generateCommitment').mockImplementation(mockedGenerateCmt);
      expect(mockedGenerateCmt).not.toHaveBeenCalled();
    });
  })

  describe('getProver', () => {
    /**
     * @target MultiSigHandler.getProver should run successfully
     * @dependencies
     * @scenario
     * - run test
     * @expected
     * - only no error throws
     */
    it('should run successfully', async () => {
      const handler = await TestUtils.generateMultiSigHandlerInstance(testSecrets[0], vi.fn(), testPubs);
      handler.getProver();
    });
  });

  describe('addTx', () => {
    it('should add transaction to the queue', async () => {
      const handler = await TestUtils.generateMultiSigHandlerInstance(testSecrets[0], vi.fn(), testPubs);
      const txId = reduced.unsigned_tx().id().to_str();
      await handler.addTx(reduced, requiredSings, boxes, dataBoxes)
      const { transaction, release } = await handler.getQueuedTransaction(txId)
      expect(transaction.boxes.length).toEqual(1);
      expect(transaction.requiredSigner).toEqual(6);
    })
  })

  describe('generateCommitment', () => {
    it('should generate commitment', async () => {
      const handler = await TestUtils.generateMultiSigHandlerInstance(testSecrets[0], vi.fn(), testPubs);
      await handler.addTx(reduced, requiredSings, boxes, dataBoxes)
      handler.generateCommitment(reduced.unsigned_tx().id().to_str())
      const { transaction, release } = await handler.getQueuedTransaction(reduced.unsigned_tx().id().to_str())
      expect(Object.values(transaction.commitments).length).toEqual(1);
      expect(Object.keys(transaction.commitments)[0]).toEqual(testPubs[0]);
      expect(transaction.secret).toBeDefined();
    })

    it('should not call sendMessage if his turn', async () => {
      const handler = await TestUtils.generateMultiSigHandlerInstance(testSecrets[0], vi.fn(), testPubs);
      const mockedSendMessage = vi.fn();
      vi.spyOn(handler, 'sendMessage').mockImplementation(mockedSendMessage);
      await handler.addTx(reduced, requiredSings, boxes, dataBoxes)
      vi.setSystemTime(0);
      handler.generateCommitment(reduced.unsigned_tx().id().to_str())
      expect(mockedSendMessage).not.toHaveBeenCalled();
    })

    it('should call sendMessage if not his turn', async () => {
      const handler = await TestUtils.generateMultiSigHandlerInstance(testSecrets[0], vi.fn(), testPubs);
      const mockedSendMessage = vi.fn();
      vi.spyOn(handler, 'sendMessage').mockImplementation(mockedSendMessage);
      await handler.addTx(reduced, requiredSings, boxes, dataBoxes)
      vi.setSystemTime(turnTime);
      handler.generateCommitment(reduced.unsigned_tx().id().to_str())
      expect(mockedSendMessage).toHaveBeenCalled();
    })
  })

});
