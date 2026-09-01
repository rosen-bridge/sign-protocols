import { describe, expect, it, vi, beforeEach } from 'vitest';

import { EdDSA } from '@rosen-bridge/encryption';

import { TestCommunicator } from './testCommunicator';

describe('Communicator', () => {
  // must match TestCommunicator's protocolVersion
  const protocolVersion = '1.0.0';
  let guardMessageEncs: Array<EdDSA>;
  let guardPks: Array<string>;
  const payload = { foo: 'bar' };

  beforeEach(async () => {
    guardMessageEncs = [];
    guardPks = [];
    for (let index = 0; index < 10; index++) {
      const sk = new EdDSA(await EdDSA.randomKey());
      guardMessageEncs.push(sk);
      guardPks.push(await sk.getPk());
    }
  });

  describe('getIndex', () => {
    const mockSubmit = vi.fn();

    /**
     * @target Communicator.getIndex should return exception when pk of guard doesn't exist between guardPks
     * @dependencies
     * @scenario
     * - override current guard message encryption with wrong
     * - create communicator
     * - call getIndex
     * @expected
     * - must throw Error
     */
    it("should return exception when pk of guard doesn't exist between guardPks", async () => {
      guardMessageEncs[1] = new EdDSA(await EdDSA.randomKey());
      const communicator = new TestCommunicator(
        guardMessageEncs[1],
        mockSubmit,
        guardPks,
      );
      await expect(communicator.mockedGetIndex()).rejects.toThrow(Error);
    });

    /**
     * @target Communicator.getIndex should return correct index 1
     * @dependencies
     * @scenario
     * - create communicator and assign guardMessageEnc with index 1 as current guard
     * - call getIndex
     * @expected
     * - should return correct index 1
     */
    it('should return correct index', async () => {
      const communicator = new TestCommunicator(
        guardMessageEncs[1],
        mockSubmit,
        guardPks,
      );
      await expect(communicator.mockedGetIndex()).resolves.toEqual(1);
    });
  });

  describe('getDate', () => {
    let communicator: TestCommunicator;

    beforeEach(async () => {
      const mockSubmit = vi.fn();
      communicator = new TestCommunicator(
        guardMessageEncs[1],
        mockSubmit,
        guardPks,
      );
    });

    /**
     * @target Communicator.sendMessage should return current timestamp rounded to seconds
     * @dependencies
     * @scenario
     * - mock Date.now to return 1685683305125
     * - call getDate
     * @expected
     * - must return 1685683305
     */
    it('should return current timestamp rounded to seconds', () => {
      const currentTime = 1685683305;
      vi.spyOn(Date, 'now').mockReturnValue(currentTime * 1000 + 125);
      const res = communicator.mockedGetDate();
      expect(res).toEqual(currentTime);
    });
  });

  describe('sendMessage', () => {
    let communicator: TestCommunicator;
    let mockSubmit = vi.fn();

    beforeEach(async () => {
      mockSubmit = vi.fn();
      communicator = new TestCommunicator(
        guardMessageEncs[1],
        mockSubmit,
        guardPks,
      );
    });

    /**
     * @target Communicator.sendMessage should call submit message
     * @dependencies
     * @scenario
     * - mock submitMessage function
     * - call with specified argument
     * @expected
     * - mocked function must call once
     * - first argument must be as a json contain expected values
     */
    it('should call submit message', async () => {
      const currentTime = 1685683141;
      const publicKey = await guardMessageEncs[1].getPk();
      const sign = await guardMessageEncs[1].sign(
        `${JSON.stringify(payload)}${currentTime}${publicKey}${protocolVersion}`,
      );
      vi.spyOn(Date, 'now').mockReturnValue(currentTime * 1000);
      await communicator.testSendMessage('msg', payload, []);
      const expected = {
        type: 'msg',
        payload: payload,
        sign: sign,
        publicKey: publicKey,
        timestamp: currentTime,
        index: 1,
        version: protocolVersion,
      };
      expect(mockSubmit).toHaveBeenCalledTimes(1);
      const callArgs = JSON.parse(mockSubmit.mock.calls[0][0]);
      expect(callArgs).toEqual(expected);
    });
  });

  describe('handleMessage', () => {
    let communicator: TestCommunicator;

    beforeEach(async () => {
      const mockSubmit = vi.fn();
      communicator = new TestCommunicator(
        guardMessageEncs[1],
        mockSubmit,
        guardPks,
      );
    });

    /**
     * @target Communicator.handleMessage should pass arguments to process message function when sign is valid
     * @dependencies
     * @scenario
     * - generate a message signed with second guard sk
     * - pass to handleMessage
     * @expect
     * - processMessage function called once
     * - message type and payload pass to processMessage
     */
    it('should pass arguments to process message function when sign is valid', async () => {
      const currentTime = 1685683142;
      const publicKey = await guardMessageEncs[2].getPk();
      const sign = await guardMessageEncs[2].sign(
        `${JSON.stringify(payload)}${currentTime}${publicKey}${protocolVersion}`,
      );
      vi.spyOn(Date, 'now').mockReturnValue(currentTime * 1000);
      const message = {
        type: 'message',
        payload: payload,
        sign: sign,
        timestamp: currentTime,
        publicKey,
        index: 2,
        version: protocolVersion,
      };
      await communicator.handleMessage(JSON.stringify(message), 'guardIndex2');
      expect(communicator.processMessage).toHaveBeenCalledTimes(1);
      expect(communicator.processMessage).toHaveBeenCalledWith(
        'message',
        payload,
        sign,
        2,
        'guardIndex2',
        currentTime,
      );
    });

    /**
     * @target Communicator.handleMessage should not call processMessage when signature is not valid
     * @dependencies
     * @scenario
     * - generate a message signed with second guard sk with index 3 (invalid sign)
     * - pass to handleMessage
     * @expect
     * - processMessage must not call
     */
    it('should not call processMessage when signature is not valid', async () => {
      const currentTime = 1685683143;
      const publicKey = await guardMessageEncs[2].getPk();
      const sign = await guardMessageEncs[2].sign(
        `${JSON.stringify(payload)}${currentTime}${publicKey}${protocolVersion}`,
      );
      vi.spyOn(Date, 'now').mockReturnValue(currentTime * 1000);
      const message = {
        type: 'message',
        payload: payload,
        publicKey: await guardMessageEncs[3].getPk(),
        timestamp: currentTime,
        sign: sign,
        index: 3,
        version: protocolVersion,
      };
      await communicator.handleMessage(JSON.stringify(message), 'guardIndex2');
      expect(communicator.processMessage).toHaveBeenCalledTimes(0);
    });

    /**
     * @target Communicator.handleMessage should not call processMessage when signer public key differ from index
     * @dependencies
     * @scenario
     * - generate a message signed with second guard sk with index 3 and public key of second guard
     * - pass to handleMessage
     * @expect
     * - processMessage must not call
     */
    it('should not call processMessage when signer public key differ from index', async () => {
      const currentTime = 1685683144;
      const publicKey = await guardMessageEncs[2].getPk();
      const sign = await guardMessageEncs[2].sign(
        `${JSON.stringify(payload)}${currentTime}${publicKey}${protocolVersion}`,
      );
      vi.spyOn(Date, 'now').mockReturnValue(currentTime * 1000);
      const message = {
        type: 'message',
        payload: payload,
        publicKey,
        timestamp: currentTime,
        sign: sign,
        index: 3,
        version: protocolVersion,
      };
      await communicator.handleMessage(JSON.stringify(message), 'guardIndex2');
      expect(communicator.processMessage).toHaveBeenCalledTimes(0);
    });

    /**
     * @target Communicator.handleMessage should not call processMessage when message timed out
     * @dependencies
     * @scenario
     * - mock Date.now() to return 1685683141101
     * - generate a valid message with timestamp equals to 60001 milliseconds before
     * - pass to handleMessage
     * @expect
     * - processMessage must not call
     */
    it('should not call processMessage when message timed out', async () => {
      const currentTime = 1685683145;
      const publicKey = await guardMessageEncs[2].getPk();
      const sign = await guardMessageEncs[2].sign(
        `${JSON.stringify(payload)}${currentTime - 60001}${publicKey}${protocolVersion}`,
      );
      vi.spyOn(Date, 'now').mockReturnValue(currentTime * 1000);
      const message = {
        type: 'message',
        payload: payload,
        publicKey,
        timestamp: currentTime - 61,
        sign: sign,
        index: 2,
        version: protocolVersion,
      };
      await communicator.handleMessage(JSON.stringify(message), 'guardIndex2');
      expect(communicator.processMessage).toHaveBeenCalledTimes(0);
    });

    /**
     * @target Communicator.handleMessage should not call processMessage when protocol major version differs
     * @dependencies
     * @scenario
     * - generate a validly signed message with a different major protocol version
     * - pass to handleMessage
     * @expect
     * - processMessage must not call
     */
    it('should not call processMessage when protocol major version differs', async () => {
      const currentTime = 1685683146;
      const publicKey = await guardMessageEncs[2].getPk();
      const otherVersion = '2.0.0'; // different major than protocolVersion
      const sign = await guardMessageEncs[2].sign(
        `${JSON.stringify(payload)}${currentTime}${publicKey}${otherVersion}`,
      );
      vi.spyOn(Date, 'now').mockReturnValue(currentTime * 1000);
      const message = {
        type: 'message',
        payload: payload,
        publicKey,
        timestamp: currentTime,
        sign: sign,
        index: 2,
        version: otherVersion,
      };
      await communicator.handleMessage(JSON.stringify(message), 'guardIndex2');
      expect(communicator.processMessage).toHaveBeenCalledTimes(0);
    });

    /**
     * @target Communicator.handleMessage should call processMessage when only the minor/patch protocol version differs
     * @dependencies
     * @scenario
     * - generate a validly signed message whose version shares protocolVersion's major but differs in minor/patch
     * - pass to handleMessage
     * @expect
     * - processMessage must be called
     */
    it('should call processMessage when only the minor/patch protocol version differs', async () => {
      const currentTime = 1685683148;
      const publicKey = await guardMessageEncs[2].getPk();
      const otherVersion = `${protocolVersion.split('.')[0]}.9.9`; // same major, different minor/patch
      const sign = await guardMessageEncs[2].sign(
        `${JSON.stringify(payload)}${currentTime}${publicKey}${otherVersion}`,
      );
      vi.spyOn(Date, 'now').mockReturnValue(currentTime * 1000);
      const message = {
        type: 'message',
        payload: payload,
        publicKey,
        timestamp: currentTime,
        sign: sign,
        index: 2,
        version: otherVersion,
      };
      await communicator.handleMessage(JSON.stringify(message), 'guardIndex2');
      expect(communicator.processMessage).toHaveBeenCalledOnce();
    });

    /**
     * @target Communicator.handleMessage should not call processMessage when the version field is tampered after signing
     * @dependencies
     * @scenario
     * - generate a message signed with the current protocol version
     * - rewrite its version field to a different value before passing to handleMessage
     * @expect
     * - processMessage must not call, since the signature no longer matches the (signed) version
     */
    it('should not call processMessage when the version field is tampered with after signing', async () => {
      const currentTime = 1685683147;
      const publicKey = await guardMessageEncs[2].getPk();
      const sign = await guardMessageEncs[2].sign(
        `${JSON.stringify(payload)}${currentTime}${publicKey}${protocolVersion}`,
      );
      vi.spyOn(Date, 'now').mockReturnValue(currentTime * 1000);
      const message = {
        type: 'message',
        payload: payload,
        publicKey,
        timestamp: currentTime,
        sign: sign,
        index: 2,
        version: `${protocolVersion}-tampered`,
      };
      await communicator.handleMessage(JSON.stringify(message), 'guardIndex2');
      expect(communicator.processMessage).toHaveBeenCalledTimes(0);
    });
  });
});
