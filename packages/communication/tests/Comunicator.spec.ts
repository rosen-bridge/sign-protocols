import { TestCommunicator } from './TestCommunicator';
import { EdDSA } from '@rosen-bridge/encryption';
import { describe, expect, it, vi, beforeEach } from 'vitest';

describe('Communicator', () => {
  let communicator: TestCommunicator;
  let mockSubmit = vi.fn();
  let guardMessageEncs: Array<EdDSA>;
  const payload = { foo: 'bar' };

  beforeEach(async () => {
    guardMessageEncs = [];
    const guardPks: Array<string> = [];
    for (let index = 0; index < 10; index++) {
      const sk = new EdDSA(await EdDSA.randomKey());
      guardMessageEncs.push(sk);
      guardPks.push(await sk.getPk());
    }
    mockSubmit = vi.fn();
    communicator = new TestCommunicator(
      guardMessageEncs[1],
      mockSubmit,
      guardPks,
    );
  });

  describe('getDate', () => {
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
        `${JSON.stringify(payload)}${currentTime}${publicKey}`,
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
      };
      expect(mockSubmit).toHaveBeenCalledTimes(1);
      const callArgs = JSON.parse(mockSubmit.mock.calls[0][0]);
      expect(callArgs).toEqual(expected);
    });
  });

  describe('handleMessage', () => {
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
        `${JSON.stringify(payload)}${currentTime}${publicKey}`,
      );
      vi.spyOn(Date, 'now').mockReturnValue(currentTime * 1000);
      const message = {
        type: 'message',
        payload: payload,
        sign: sign,
        timestamp: currentTime,
        publicKey,
        index: 2,
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
        `${JSON.stringify(payload)}${currentTime}${publicKey}`,
      );
      vi.spyOn(Date, 'now').mockReturnValue(currentTime * 1000);
      const message = {
        type: 'message',
        payload: payload,
        publicKey: await guardMessageEncs[3].getPk(),
        timestamp: currentTime,
        sign: sign,
        index: 3,
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
        `${JSON.stringify(payload)}${currentTime}${publicKey}`,
      );
      vi.spyOn(Date, 'now').mockReturnValue(currentTime * 1000);
      const message = {
        type: 'message',
        payload: payload,
        publicKey,
        timestamp: currentTime,
        sign: sign,
        index: 3,
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
        `${JSON.stringify(payload)}${currentTime - 60001}${publicKey}`,
      );
      vi.spyOn(Date, 'now').mockReturnValue(currentTime * 1000);
      const message = {
        type: 'message',
        payload: payload,
        publicKey,
        timestamp: currentTime - 61,
        sign: sign,
        index: 2,
      };
      await communicator.handleMessage(JSON.stringify(message), 'guardIndex2');
      expect(communicator.processMessage).toHaveBeenCalledTimes(0);
    });
  });
});
