import { SignRequestPayload, StatusEnum } from '../../lib';
import { GuardDetection, ActiveGuard } from '@rosen-bridge/detection';
import { EdDSA } from '@rosen-bridge/encryption';
import { TestTssSigner } from './TestTssSigner';
import { generateSigners } from '../testUtils';
import {
  approveMessage,
  cachedMessage,
  requestMessage,
  startMessage,
} from '../../lib/const/signer';
import { beforeEach, describe, expect, it, MockInstance, vi } from 'vitest';

describe('TssSigner', () => {
  let signer: TestTssSigner;
  let mockSubmit = vi.fn();
  let guardMessageEncs: Array<EdDSA>;
  let detection: GuardDetection;
  const currentTime = 1686286005068;
  const timestamp = Math.floor(currentTime / 1000);

  beforeEach(async () => {
    const signers = await generateSigners();
    guardMessageEncs = signers.guardSigners;
    vi.restoreAllMocks();
    vi.setSystemTime(new Date(currentTime));
    mockSubmit = vi.fn();
    detection = new GuardDetection({
      messageEnc: guardMessageEncs[0],
      guardsPublicKey: signers.guardPks,
      submit: mockSubmit,
      getPeerId: () => Promise.resolve('myPeerId'),
    });
    signer = new TestTssSigner({
      submitMsg: mockSubmit,
      callbackUrl: '',
      signingCrypto: 'eddsa',
      messageEnc: guardMessageEncs[0],
      detection: detection,
      guardsPk: signers.guardPks,
      tssApiUrl: '',
      getPeerId: () => Promise.resolve('myPeerId'),
      shares: signers.guardPks,
      signCacheTTLSeconds: 0.05,
    });
  });

  describe('cleanup', () => {
    /**
     * @target TssSigner.cleanup should remove timed out signs
     * @dependencies
     * @scenario
     * - mock `Date.now` to return 1686286005068 ( a random timestamp )
     * - add one sign for 5 minute + 1 second before
     * - call cleanup
     * @expected
     * - signs must be empty array
     */
    it('should remove timed out signs', async () => {
      const signs = signer.getSigns();
      signs.push({
        msg: 'random msg',
        signs: [],
        addedTime: Math.floor(currentTime / 1000) - 5 * 60 - 1,
        callback: () => null,
        posted: false,
        chainCode: 'chainCode',
      });
      await (signer as any).cleanup();
      expect(signer.getSigns().length).toEqual(0);
    });

    /**
     * @target TssSigner.cleanup should not remove non-timed out signs
     * @dependencies
     * @scenario
     * - mock `Date.now` to return 1686286005068 ( a random timestamp )
     * - add one sign for 5 minute - 1 second before
     * - call cleanup
     * @expected
     * - signs must contain one element
     */
    it('should not remove non-timed out signs', async () => {
      const signs = signer.getSigns();
      signs.push({
        msg: 'random msg',
        signs: [],
        posted: false,
        addedTime: Math.floor(currentTime / 1000) - 5 * 60 + 1,
        callback: () => null,
        chainCode: 'chainCode',
      });
      await (signer as any).cleanup();
      expect(signer.getSigns().length).toEqual(1);
    });

    /**
     * @target TssSigner.cleanup should remove pending item which not in guards turn
     * @dependencies
     * @scenario
     * - mock `Date.now` to return 1686286005068 ( a random timestamp )
     * - add one pending sign for guard index 4 (current guard turn is 5)
     * - call cleanup
     * @expected
     * - pendingSign array must be empty
     */
    it('should remove pending item which not in guards turn', async () => {
      const pending = signer.getPendingSigns();
      pending.push({
        msg: 'random msg',
        index: 4,
        guards: [],
        timestamp: currentTime,
        sender: '',
      });
      await (signer as any).cleanup();
      expect(signer.getPendingSigns().length).toEqual(0);
    });

    /**
     * @target TssSigner.cleanup should not remove pending item which in guards turn
     * @dependencies
     * @scenario
     * - mock `Date.now` to return 1686286005068 ( a random timestamp )
     * - add one pending sign for guard index 5 (current guard turn)
     * - call cleanup
     * @expected
     * - pendingSign must contain one element
     */
    it('should not remove pending item which in guards turn', async () => {
      const pending = signer.getPendingSigns();
      pending.push({
        msg: 'random msg',
        index: 6,
        guards: [],
        timestamp: currentTime,
        sender: '',
      });
      await (signer as any).cleanup();
      expect(signer.getPendingSigns().length).toEqual(1);
    });
  });

  describe('addSignToCache', () => {
    /**
     * @target TssSigner.addSignToCache should add SignResult to signCache
     * @dependencies
     * @scenario
     * - call addSignToCache with signature record
     * - wait 25ms
     * - check signCache
     * - wait 25ms
     * - check signCache
     * @expected
     * - before ttl signCache should have contained the SignResult
     * - after ttl signCache should have contained the SignResult
     */
    it('should add SignResult to signCache', async () => {
      const msg = 'test message';
      const signResult = {
        signature: 'signature',
        signatureRecovery: 'signatureRecovery',
      };
      signer.callAddSignToCache(msg, signResult);
      await new Promise((resolve) => setTimeout(resolve, 25));
      expect(signer.getSignCache()).toHaveProperty(msg);
      expect(signer.getSignCache()[msg]).toMatchObject(signResult);
      await new Promise((resolve) => setTimeout(resolve, 25));
      expect(Object.keys(signer.getSignCache())).toHaveLength(0);
    });

    /**
     * @target TssSigner.addSignToCache should return if message already is in cache
     * @dependencies
     * @scenario
     * - call addSignToCache with signature record
     * - wait 25ms
     * - call addSignToCache again with the same message and different signature
     * - check signCache
     * - wait 25ms
     * - check signCache
     * @expected
     * - signCache should have contained 1 record with 'msg' as key and 'signature' as value
     * - after cache ttl signCache should have been empty
     */
    it('should return if message already is in cache', async () => {
      const msg = 'mgs';
      signer.callAddSignToCache(msg, {
        signature: 'signature',
        signatureRecovery: '',
      });

      await new Promise((resolve) => setTimeout(resolve, 25));

      signer.callAddSignToCache(msg, {
        signature: 'signature2',
        signatureRecovery: '',
      });

      expect(Object.keys(signer.getSignCache())).toHaveLength(1);
      expect(signer.getSignCache()).toHaveProperty(msg);
      expect(signer.getSignCache()[msg].signature).toEqual('signature');

      await new Promise((resolve) => setTimeout(resolve, 25));

      expect(Object.keys(signer.getSignCache())).toHaveLength(0);
    });
  });

  describe('update', () => {
    beforeEach(() => {
      signer.getSigns().push({
        posted: false,
        msg: 'random message',
        callback: vi.fn(),
        signs: [],
        addedTime: currentTime,
        chainCode: 'chainCode',
      });
    });
    /**
     * @target TssSigner.update should call cleanup
     * @dependencies
     * @scenario
     * - mock cleanup
     * - mock `Date.now` to return 1686286005068 ( a random timestamp )
     * @expected
     * - mocked cleanup must call once
     */
    it('should call cleanup', async () => {
      const mockedCleanup = vi
        .spyOn(signer as any, 'cleanup')
        .mockReturnValue(null);
      await signer.update();
      expect(mockedCleanup).toHaveBeenCalledTimes(1);
    });

    /**
     * @target TssSigner.update should not call sendMessage when it's not guard turn
     * @dependencies
     * @scenario
     * - mock activeGuards to return a list of 7 active guard
     * - mock `Date.now` to return 1686286005068 ( a random timestamp )
     * - call update
     * @expected
     * - mocked submitMsg must not call
     */
    it("should not call sendMessage when it's not guard turn", async () => {
      const activeGuards = Array(7)
        .fill('')
        .map((item, index) => ({
          peerId: `peerId-${index}`,
          publicKey: `publicKey-${index}`,
        }));
      vi.spyOn(detection, 'activeGuards').mockResolvedValue(activeGuards);
      await signer.update();
      expect(mockSubmit).not.toBeCalled();
    });

    /**
     * @target TssSigner.update should not call sendMessage when active guards list length lower than threshold
     * @dependencies
     * @scenario
     * - mock activeGuards to return a list of 6 active guard
     * - mock `Date.now` to return 1686285600 ( a random timestamp when its this guard turn)
     * - mock updateThreshold
     * - call update
     * @expected
     * - mocked submitMsg must not call
     */
    it('should not call sendMessage when active guards list length lower than threshold', async () => {
      vi.setSystemTime(new Date(1686285600608));
      vi.spyOn(signer as any, 'updateThreshold').mockResolvedValue(undefined);
      (signer as any).threshold = { expiry: 0, value: 7 };
      const activeGuards = Array(6)
        .fill('')
        .map((item, index) => ({
          peerId: `peerId-${index}`,
          publicKey: `publicKey-${index}`,
        }));
      vi.spyOn(detection, 'activeGuards').mockResolvedValue(activeGuards);
      await signer.update();
      expect(mockSubmit).not.toBeCalled();
    });

    /**
     * @target TssSigner.update should call once sendMessage when more than one time called
     * @dependencies
     * @scenario
     * - mock activeGuards to return a list of 7 active guard
     * - mock `Date.now` to return 1686285600 ( a random timestamp when its this guard turn)
     * - call update twice
     * @expected
     * - mocked submitMsg must call once
     */
    it('should call once sendMessage when more than one time called', async () => {
      vi.setSystemTime(new Date(1686285600608));
      const activeGuards = Array(7)
        .fill('')
        .map((item, index) => ({
          peerId: `peerId-${index}`,
          publicKey: `publicKey-${index}`,
        }));
      vi.spyOn(detection, 'activeGuards').mockResolvedValue(activeGuards);
      await signer.update();
      await signer.update();
      expect(mockSubmit).toHaveBeenCalledTimes(1);
    });

    /**
     * @target TssSigner.update should send at most two messages
     * @dependencies
     * @scenario
     * - mock activeGuards to return a list of 7 active guard
     * - mock `Date.now` to return 1686285600 ( a random timestamp when its this guard turn)
     * - insert three more messages to signs
     * - call update twice
     * @expected
     * - mocked submitMsg must call twice
     */
    it('should send at most two messages', async () => {
      vi.setSystemTime(new Date(1686285600608));
      const activeGuards = Array(7)
        .fill('')
        .map((item, index) => ({
          peerId: `peerId-${index}`,
          publicKey: `publicKey-${index}`,
        }));
      vi.spyOn(detection, 'activeGuards').mockResolvedValue(activeGuards);
      for (let i = 0; i < 3; i++) {
        signer.getSigns().push({
          posted: false,
          msg: `random message ${i}`,
          callback: vi.fn(),
          signs: [],
          addedTime: currentTime + i * 10,
          chainCode: 'chainCode',
        });
      }
      await signer.update();
      expect(mockSubmit).toHaveBeenCalledTimes(2);
    });

    /**
     * @target TssSigner.update should update signs array
     * @dependencies
     * @scenario
     * - mock activeGuards to return a list of 7 active guard
     * - mock `Date.now` to return 1686285600 ( a random timestamp when its this guard turn)
     * - call update twice
     * @expected
     * - signs array must be a list of 10 element
     * - only first element must have value
     */
    it('should update signs array', async () => {
      vi.setSystemTime(new Date(1686285600608));
      const activeGuards = Array(7)
        .fill('')
        .map((item, index) => ({
          peerId: `peerId-${index}`,
          publicKey: `publicKey-${index}`,
        }));
      vi.spyOn(detection, 'activeGuards').mockResolvedValue(activeGuards);
      await signer.update();
      const signs = signer.getSigns()[0].signs;
      expect(signs.length).toEqual(10);
      expect(signs.filter((item) => item !== '').length).toEqual(1);
      expect(signs[0]).not.toEqual('');
    });
  });

  describe('getGuardTurn', () => {
    /**
     * @target TssSigner.getGuardTurn should return guard index turn
     * @dependencies
     * @scenario
     * - mock `Date.now` to return 1686286005068 ( a random timestamp )
     * @expected
     * - must return 6
     */
    it('should return guard index turn', () => {
      expect(signer.getGuardTurn()).toEqual(6);
    });
  });

  describe('isNoWorkTime', () => {
    /**
     * @target TssSigner.isNoWorkTime should return false when remain more than NoWork seconds
     * @dependencies
     * @scenario
     * - mock `Date.now` to return 1686285606068 (beginning of turn)
     * - call isNoWorkTime
     * @expected
     * - must return false
     */
    it('should return false when remain more than NoWork seconds', () => {
      const currentTime = 1686285606068;
      vi.setSystemTime(new Date(currentTime));
      expect(signer.mockedIsNoWorkTime()).toBeFalsy();
    });

    /**
     * @target TssSigner.isNoWorkTime should return false when remain more than NoWork seconds
     * @dependencies
     * @scenario
     * - mock `Date.now` to return 1686285651068 (9 seconds to end of turn noWorkTurn is 10)
     * - call isNoWorkTime
     * @expected
     * - must return true
     */
    it('should return true when remain less than NoWork seconds', () => {
      const currentTime = 1686285651068;
      vi.setSystemTime(new Date(currentTime));
      expect(signer.mockedIsNoWorkTime()).toBeTruthy();
    });
  });

  describe('sign', () => {
    /**
     * @target TssSigner.sign should add new sign to list
     * @dependencies
     * @scenario
     * - call sign
     * @expected
     * - an element with entered msg must add to sign list
     */
    it('should add new sign to list', async () => {
      await signer.callSign('msg', vi.fn(), 'chainCode');
      expect(
        signer.getSigns().filter((item) => item.msg === 'msg').length,
      ).toEqual(1);
    });

    /**
     * @target TssSigner.sign should call back with cached signature if cache record is available
     * @dependencies
     * @scenario
     * - mock getPkAndVerifySignature
     * - mock signCache to contain cache record for message 'msg'
     * - mock callback
     * - call sign
     * @expected
     * - callback should have been called with expected arguments
     * - sign should not have been added to signs array
     * - valid cached signature should not have been removed
     */
    it('should call back with cached signature if cache record is available', async () => {
      vi.spyOn(signer as any, 'getPkAndVerifySignature').mockResolvedValue(
        true,
      );
      signer.getSignCache()['msg'] = {
        signature: 'signature',
        signatureRecovery: 'signatureRecovery',
      };
      const cb = vi.fn();
      await signer.callSign('msg', cb, 'chainCode');
      expect(cb).toHaveBeenCalledTimes(1);
      expect(cb).toHaveBeenCalledWith(
        true,
        undefined,
        'signature',
        'signatureRecovery',
      );
      expect(signer.getSigns()).toHaveLength(0);
      expect(signer.getSignCache()).toHaveProperty('msg');
    });

    /**
     * @target TssSigner.sign should return when cached signature verification fails
     * @dependencies
     * @scenario
     * - mock getPkAndVerifySignature to return false
     * - mock signCache to contain cache record for message 'msg'
     * - mock callback
     * - call sign
     * @expected
     * - callback should not have been called
     * - sign should not have been added to signs array
     * - invalid cached signature should have been removed
     */
    it('should return when cached signature verification fails', async () => {
      vi.spyOn(signer as any, 'getPkAndVerifySignature').mockResolvedValue(
        false,
      );
      signer.getSignCache()['msg'] = {
        signature: 'signature',
        signatureRecovery: 'signatureRecovery',
      };
      const cb = vi.fn();
      await signer.callSign('msg', cb, 'chainCode');
      expect(cb).toHaveBeenCalledTimes(0);
      expect(signer.getSigns()).toHaveLength(0);
      expect(signer.getSignCache()).not.toHaveProperty('msg');
    });

    /**
     * @target TssSigner.sign should call handleRequestMessage if msg in pending state
     * @dependencies
     * @scenario
     * - call sign
     * @expected
     * - an element with entered msg must add to sign list
     */
    it('should call handleRequestMessage if msg in pending state', async () => {
      const pending = signer.getPendingSigns();
      pending.push({
        msg: 'signing message',
        guards: [],
        index: 6,
        sender: 'sender',
        timestamp: currentTime,
      });
      const mockedHandleRequest = vi
        .spyOn(signer as any, 'handleRequestMessage')
        .mockReturnValue(null);
      await signer.callSign('signing message', vi.fn(), 'chainCode');
      expect(mockedHandleRequest).toHaveBeenCalledTimes(1);
      expect(mockedHandleRequest).toHaveBeenCalledWith(
        {
          msg: 'signing message',
          guards: [],
        },
        'sender',
        6,
        currentTime,
      );
    });
  });

  describe('processMessage', () => {
    /**
     * @target TssSigner.processMessage should call handleRequestMessage
     * when message type is requestMessage
     * @dependencies
     * @scenario
     * - mock handleRequestMessage
     * - call processMessage
     * @expected
     * - mocked function must call with expected arguments
     */
    it('should call handleRequestMessage when message type is requestMessage', async () => {
      const mockedFn = ((signer as any).handleRequestMessage = vi.fn());
      await signer.processMessage(requestMessage, {}, '', 1, 'peerId', 1234);
      expect(mockedFn).toHaveBeenCalledTimes(1);
      expect(mockedFn).toHaveBeenCalledWith({}, 'peerId', 1, 1234);
    });

    /**
     * @target TssSigner.processMessage should call handleApproveMessage
     * when message type is approveMessage
     * @dependencies
     * @scenario
     * - mock handleApproveMessage
     * - call processMessage
     * @expected
     * - mocked function must call with expected arguments
     */
    it('should call handleApproveMessage when message type is approveMessage', async () => {
      const mockedFn = ((signer as any).handleApproveMessage = vi.fn());
      await signer.processMessage(
        approveMessage,
        {},
        'sign',
        1,
        'peerId',
        1234,
      );
      expect(mockedFn).toHaveBeenCalledTimes(1);
      expect(mockedFn).toHaveBeenCalledWith({}, 'peerId', 1, 'sign');
    });

    /**
     * @target TssSigner.processMessage should call handleSignCachedMessage
     * when message type is cacheMessage
     * @dependencies
     * @scenario
     * - mock handleSignCachedMessage
     * - call processMessage
     * @expected
     * - handleSignCachedMessage should have been called with expected arguments
     */
    it('should call handleSignCachedMessage when message type is cacheMessage', async () => {
      const mockedHandleSignCachedMessage = vi
        .spyOn(signer as any, 'handleSignCachedMessage')
        .mockResolvedValue(undefined);

      await signer.processMessage(cachedMessage, {}, 'sign', 1, 'peerId', 1234);
      expect(mockedHandleSignCachedMessage).toHaveBeenCalledTimes(1);
      expect(mockedHandleSignCachedMessage).toHaveBeenCalledWith({}, 'peerId');
    });

    /**
     * @target GuardDetection.processMessage should call handleStartMessage
     * when message type is startMessage
     * @dependencies
     * @scenario
     * - mock handleApproveMessage
     * - call processMessage
     * @expected
     * - mocked function must call with expected arguments
     */
    it('should call handleStartMessage when message type is startMessage', async () => {
      const mockedFn = ((signer as any).handleStartMessage = vi.fn());
      await signer.processMessage(startMessage, {}, '', 1, 'peerId', 1234);
      expect(mockedFn).toHaveBeenCalledTimes(1);
      expect(mockedFn).toHaveBeenCalledWith({}, 1234, 1, 'peerId');
    });
  });

  describe('getUnknownGuards', () => {
    /**
     * @target GuardDetection.getUnknownGuards should return list of unknown guards
     * @dependencies
     * @scenario
     * - mock detection to return known list of guards
     * - call getUnknownGuards with one unknown guard
     * @expected
     * - must return unknown guard
     */
    it('should return list of unknown guards', async () => {
      const myActiveGuards = [
        { peerId: 'peerId-1', publicKey: await guardMessageEncs[1].getPk() },
        { peerId: 'peerId-2', publicKey: await guardMessageEncs[2].getPk() },
        { peerId: 'peerId-3', publicKey: await guardMessageEncs[3].getPk() },
      ];
      const unknownGuard = {
        peerId: 'peerId-4',
        publicKey: await guardMessageEncs[4].getPk(),
      };
      const requestedGuard = [...myActiveGuards, unknownGuard];
      vi.spyOn(detection, 'activeGuards').mockResolvedValue(myActiveGuards);
      const unknownGuards = await signer.mockedGetUnknownGuards(requestedGuard);
      expect(unknownGuards).toEqual([unknownGuard]);
    });
  });

  describe('getInvalidGuards', () => {
    /**
     * @target GuardDetection.getInvalidGuards should return list of invalid guards
     * @dependencies
     * @scenario
     * - mock detection to return known list of guards
     * - call getInvalidGuards with one guard with different peerId
     * @expected
     * - must return selected guard
     */
    it('should return list of unknown guards', async () => {
      const myActiveGuards = [
        { peerId: 'peerId-1', publicKey: await guardMessageEncs[1].getPk() },
        { peerId: 'peerId-2', publicKey: await guardMessageEncs[2].getPk() },
        { peerId: 'peerId-3', publicKey: await guardMessageEncs[3].getPk() },
      ];
      const invalidGuard = {
        peerId: 'peerId-3-new',
        publicKey: await guardMessageEncs[3].getPk(),
      };
      const requestedGuard = [...myActiveGuards.slice(0, 2), invalidGuard];
      vi.spyOn(detection, 'activeGuards').mockResolvedValue(myActiveGuards);
      const unknownGuards = await signer.mockedGetInvalidGuards(requestedGuard);
      expect(unknownGuards).toEqual([invalidGuard]);
    });
  });

  describe('handleRequestMessage', () => {
    let activeGuards: Array<ActiveGuard>;
    beforeEach(async () => {
      activeGuards = [
        { peerId: 'peerId-1', publicKey: await guardMessageEncs[1].getPk() },
        { peerId: 'peerId-2', publicKey: await guardMessageEncs[2].getPk() },
        { peerId: 'peerId-3', publicKey: await guardMessageEncs[3].getPk() },
      ];
      vi.spyOn(detection, 'activeGuards').mockResolvedValue(activeGuards);
      signer.getSigns().push({
        msg: 'test message',
        signs: [],
        addedTime: currentTime,
        callback: vi.fn(),
        posted: false,
        chainCode: 'chainCode',
      });
    });
    /**
     * @target GuardDetection.handleRequestMessage should send approve message when all conditions are OK
     * @dependencies
     * @scenario
     * - mock a list of active guards
     * - add a sign to signs list of signer
     * - call handleRequestMessage
     * @expected
     * - send message called once with
     *   - second argument with ['sender']
     *   - first argument is a json
     *     - type is approveMessage
     *     - payload as expected
     *     - timestamp same as called timestamp
     */
    it('should send approve message when all conditions are OK', async () => {
      await signer.mockedHandleRequestMessage(
        {
          msg: 'test message',
          guards: activeGuards,
        },
        'sender',
        6,
        timestamp,
        true,
      );
      expect(mockSubmit).toHaveBeenCalledTimes(1);
      expect(mockSubmit).toHaveBeenCalledWith(expect.any(String), ['sender']);
      const msg = JSON.parse(mockSubmit.mock.calls[0][0]);
      expect(msg.type).toEqual(approveMessage);
      expect(msg.payload).toEqual({
        msg: 'test message',
        guards: activeGuards,
        initGuardIndex: 6,
      });
      expect(msg.timestamp).toEqual(timestamp);
    });

    /**
     * @target TssSigner.handleRequestMessage should send cached message when all conditions are OK and signature exist in cache
     * @dependencies
     * @scenario
     * - mock a list of active guards
     * - mock signCache to contain record with key 'msg'
     * - call mockedHandleRequestMessage with 'msg'
     * @expected
     * - send message called once with
     *   - second argument with ['sender']
     *   - first argument is a json
     *     - type is cachedMessage
     *     - payload is SignCachedPayload
     *     - timestamp same as called timestamp
     */
    it('should send cached message when all conditions are OK and signature exist in cache', async () => {
      signer.getSignCache()['msg'] = {
        signature: 'signature',
        signatureRecovery: undefined,
      };
      await signer.mockedHandleRequestMessage(
        {
          msg: 'msg',
          guards: activeGuards,
        },
        'sender',
        6,
        timestamp,
        true,
      );
      expect(mockSubmit).toHaveBeenCalledTimes(1);
      expect(mockSubmit).toHaveBeenCalledWith(expect.any(String), ['sender']);
      const msg = JSON.parse(mockSubmit.mock.calls[0][0]);
      expect(msg.type).toEqual(cachedMessage);
      expect(msg.payload).toEqual({
        msg: 'msg',
        signature: 'signature',
        signatureRecovery: undefined,
      });
      expect(msg.timestamp).toEqual(timestamp);
    });

    /**
     * @target GuardDetection.handleRequestMessage should not send any message when it's not guard turn
     * @dependencies
     * @scenario
     * - mock a list of active guards
     * - add a sign to signs list of signer
     * - call handleRequestMessage with invalid guard index turn
     * @expected
     * - mockSubmit must not call
     */
    it("should not send any message when it's not guard turn", async () => {
      await signer.mockedHandleRequestMessage(
        {
          msg: 'test message',
          guards: activeGuards,
        },
        'sender',
        5,
        timestamp,
        true,
      );
      expect(mockSubmit).toHaveBeenCalledTimes(0);
    });

    /**
     * @target GuardDetection.handleRequestMessage should not send any message when at least one of guards are invalid
     * @dependencies
     * @scenario
     * - mock a list of active guards
     * - add a sign to signs list of signer
     * - create guards list with invalid peedId for index 2
     * - call handleRequestMessage
     * @expected
     * - mockSubmit must not call
     */
    it("should not send any message when it's not guard turn", async () => {
      const invalidGuards = [...activeGuards];
      invalidGuards[2] = { ...invalidGuards[2], peerId: 'invalid peer id' };
      await signer.mockedHandleRequestMessage(
        {
          msg: 'test message',
          guards: invalidGuards,
        },
        'sender',
        6,
        timestamp,
        true,
      );
      expect(mockSubmit).toHaveBeenCalledTimes(0);
    });

    /**
     * @target GuardDetection.handleRequestMessage should store request and send register to unknown guard
     * @dependencies
     * @scenario
     * - mock a list of active guards
     * - mock register of detection
     * - add a sign to signs list of signer
     * - call handleRequestMessage with new guard added to list
     * - after it mock handleRequestMessage
     * - then call callBack passed to register function
     * @expected
     * - mockSubmit must not call
     * - mockedRegister must call once with 'peerId-4' and its publicKey
     * - after calling callBack it must call handleRequestMessage once with same argument passed to it first
     */
    it('should store request and send register to unknown guard', async () => {
      const mockedRegister = vi
        .spyOn(detection, 'register')
        .mockResolvedValue();
      const guards = [
        ...activeGuards,
        { peerId: 'peerId-4', publicKey: await guardMessageEncs[4].getPk() },
      ];
      const payload: SignRequestPayload = {
        msg: 'test message',
        guards: guards,
      };
      await signer.mockedHandleRequestMessage(
        payload,
        'sender',
        6,
        timestamp,
        true,
      );
      expect(mockedRegister).toHaveBeenCalledTimes(1);
      expect(mockSubmit).toHaveBeenCalledTimes(0);
      expect(mockedRegister).toHaveBeenCalledWith(
        'peerId-4',
        await guardMessageEncs[4].getPk(),
        expect.anything(),
      );
      const callback = mockedRegister.mock.calls[0][2];
      const mocked = vi
        .spyOn(signer as any, 'handleRequestMessage')
        .mockResolvedValue(null);
      await callback(true);
      expect(mocked).toHaveBeenCalledTimes(1);
      expect(mocked).toHaveBeenCalledWith(
        payload,
        'sender',
        6,
        timestamp,
        false,
      );
    });

    /**
     * @target GuardDetection.handleRequestMessage should do nothing when unknown guard exists and sendRegister is false
     * @dependencies
     * @scenario
     * - mock a list of active guards
     * - mock register of detection
     * - add a sign to signs list of signer
     * - call handleRequestMessage with new guard added to list and sendRegister=false
     * @expected
     * - mockSubmit must not call
     * - mockedRegister must not call
     */
    it('should do nothing when unknown guard exists and sendRegister is false', async () => {
      const mockedRegister = vi
        .spyOn(detection, 'register')
        .mockResolvedValue();
      const payload: SignRequestPayload = {
        msg: 'test message',
        guards: [
          ...activeGuards,
          { peerId: 'peerId-4', publicKey: await guardMessageEncs[4].getPk() },
        ],
      };
      await signer.mockedHandleRequestMessage(
        payload,
        'sender',
        6,
        timestamp,
        false,
      );
      expect(mockedRegister).toHaveBeenCalledTimes(0);
      expect(mockSubmit).toHaveBeenCalledTimes(0);
    });

    /**
     * @target GuardDetection.handleRequestMessage should add pendingSign when sign does not exist and do nothing
     * @dependencies
     * @scenario
     * - mock a list of active guards
     * - mock register of detection
     * - add a sign to signs list of signer
     * - call handleRequestMessage with new msg
     * @expected
     * - mockSubmit must not call
     * - mockedRegister must not call
     * - pendingSign must contain one element with passed arguments
     */
    it('should add pendingSign when sign does not exist and do nothing', async () => {
      const mockedRegister = vi
        .spyOn(detection, 'register')
        .mockResolvedValue();
      const payload: SignRequestPayload = {
        msg: 'test message new',
        guards: activeGuards,
      };
      await signer.mockedHandleRequestMessage(
        payload,
        'sender',
        6,
        timestamp,
        false,
      );
      expect(mockedRegister).toHaveBeenCalledTimes(0);
      expect(mockSubmit).toHaveBeenCalledTimes(0);
      const pending = signer.getPendingSigns();
      expect(pending).toEqual([
        {
          guards: activeGuards,
          index: 6,
          msg: 'test message new',
          sender: 'sender',
          timestamp,
        },
      ]);
    });

    /**
     * @target GuardDetection.handleRequestMessage should update pending sign request and do nothing
     * @dependencies
     * @scenario
     * - mock a list of active guards
     * - mock register of detection
     * - add selected message to pending list
     * - add a sign to signs list of signer
     * - call handleRequestMessage with new msg
     * @expected
     * - mockSubmit must not call
     * - mockedRegister must not call
     * - pendingSign must be updated with new data
     */
    it('should update pending sign request and do nothing', async () => {
      const mockedRegister = vi
        .spyOn(detection, 'register')
        .mockResolvedValue();
      const payload: SignRequestPayload = {
        msg: 'test message new',
        guards: activeGuards,
      };
      const pendings = signer.getPendingSigns();
      pendings.push({
        msg: 'test message new',
        guards: [],
        index: 0,
        timestamp: 0,
        sender: 'sender old',
      });
      await signer.mockedHandleRequestMessage(
        payload,
        'sender',
        6,
        timestamp,
        false,
      );
      expect(mockedRegister).toHaveBeenCalledTimes(0);
      expect(mockSubmit).toHaveBeenCalledTimes(0);
      const pending = signer.getPendingSigns();
      expect(pending).toEqual([
        {
          guards: activeGuards,
          index: 6,
          msg: 'test message new',
          sender: 'sender',
          timestamp,
        },
      ]);
    });
  });

  describe('getSign', () => {
    /**
     * @target GuardDetection.getSign should return sign instance from list
     * @dependencies
     * @scenario
     * - mock signs array to contain one element with `msg1` as msg
     * - call getSign
     * @expected
     * - must sign instance with `msg1` as its msg
     */
    it('should return sign instance from list', () => {
      const signs = signer.getSigns();
      signs.push({
        msg: 'msg1',
        signs: [],
        addedTime: currentTime,
        callback: vi.fn,
        posted: false,
        chainCode: 'chainCode',
      });
      const sign = signer.mockedGetSign('msg1');
      expect(sign).toBeDefined();
      expect(sign?.msg).toEqual('msg1');
    });

    /**
     * @target GuardDetection.getSign should return undefined when sign not exists
     * @dependencies
     * @scenario
     * - mock signs array to contain one element with `msg1` as msg
     * - call getSign with `msg2`
     * @expected
     * - must return undefined
     */
    it('should return undefined when sign not exists', () => {
      const signs = signer.getSigns();
      signs.push({
        msg: 'msg1',
        signs: [],
        addedTime: currentTime,
        callback: vi.fn,
        posted: false,
        chainCode: 'chainCode',
      });
      const sign = signer.mockedGetSign('msg2');
      expect(sign).toBeUndefined();
    });
  });

  describe('removeSign', () => {
    let activeGuards: Array<ActiveGuard>;
    beforeEach(async () => {
      activeGuards = [
        { peerId: 'peerId-1', publicKey: await guardMessageEncs[1].getPk() },
        { peerId: 'peerId-2', publicKey: await guardMessageEncs[2].getPk() },
        { peerId: 'peerId-3', publicKey: await guardMessageEncs[3].getPk() },
      ];
    });

    const addSign = (msg: string) => {
      signer.getSigns().push({
        msg,
        signs: Array(10).fill(''),
        addedTime: timestamp,
        callback: vi.fn(),
        request: {
          index: 0,
          guards: activeGuards,
          timestamp,
        },
        posted: false,
        chainCode: 'chainCode',
      });
    };

    /**
     * @target TssSigner.removeSign should do nothing when called with non-existing sign message
     * @dependencies
     * @scenario
     * - mock signs
     * - call removeSign
     * @expected
     * - signs should have been the same as before removeSign call
     */
    it('should do nothing when called with non-existing sign message', async () => {
      // mock signs
      addSign('test message');
      addSign('test message2');

      // call removeSign
      await signer.callRemoveSign('');

      expect(signer.getSigns().length).toBe(2);
      expect(signer.getSigns()[0].msg).toBe('test message');
      expect(signer.getSigns()[1].msg).toBe('test message2');
    });

    /**
     * @target TssSigner.removeSign should remove sign when input message matches a sign message
     * @dependencies
     * @scenario
     * - mock signs
     * - call removeSign
     * @expected
     * - sign that its message matched requested message should have been removed from signs
     */
    it('should remove sign when input message matches a sign message', async () => {
      // mock signs
      addSign('test message');
      addSign('test message2');

      // call removeSign
      await signer.callRemoveSign('test message2');

      expect(signer.getSigns().length).toBe(1);
      expect(signer.getSigns()[0].msg).toBe('test message');
    });
  });

  describe('getPendingSign', () => {
    /**
     * @target GuardDetection.getPendingSign should return pendingSign instance from list
     * @dependencies
     * @scenario
     * - mock pendingSigns array to contain one element with `msg1` as msg
     * - call getPendingSign
     * @expected
     * - must pendingSign instance with `msg1` as its msg
     */
    it('should return pendingSign instance from list', () => {
      const pending = signer.getPendingSigns();
      pending.push({
        msg: 'msg1',
        index: 2,
        guards: [],
        timestamp: currentTime,
        sender: 'sender',
      });
      const sign = signer.mockedGetPendingSign('msg1');
      expect(sign).toBeDefined();
      expect(sign?.msg).toEqual('msg1');
    });

    /**
     * @target GuardDetection.getPendingSign should return undefined when pendingSign not exists
     * @dependencies
     * @scenario
     * - mock pendingSign array to contain one element with `msg1` as msg
     * - call getPendingSign with `msg2`
     * @expected
     * - must return undefined
     */
    it('should return undefined when pendingSign not exists', () => {
      const pending = signer.getPendingSigns();
      pending.push({
        msg: 'msg1',
        index: 2,
        guards: [],
        timestamp: currentTime,
        sender: 'sender',
      });
      const sign = signer.mockedGetSign('msg2');
      expect(sign).toBeUndefined();
    });
  });

  describe('handleApproveMessage', () => {
    let activeGuards: Array<ActiveGuard>;
    beforeEach(async () => {
      activeGuards = [
        { peerId: 'peerId-1', publicKey: await guardMessageEncs[1].getPk() },
        { peerId: 'peerId-2', publicKey: await guardMessageEncs[2].getPk() },
        { peerId: 'peerId-3', publicKey: await guardMessageEncs[3].getPk() },
      ];
      signer.getSigns().push({
        msg: 'test message',
        signs: Array(10).fill(''),
        addedTime: timestamp,
        callback: vi.fn(),
        request: {
          index: 0,
          guards: activeGuards,
          timestamp,
        },
        posted: false,
        chainCode: 'chainCode',
      });
    });

    /**
     * @target GuardDetection.handleApproveMessage should add guard sign to sign object
     * when all conditions are met and signs are not enough
     * @dependencies
     * @scenario
     * - mock updateThreshold
     * - mock EdDSA signer to approve signatures
     * - add sign instance to list with valid request and empty list of signs
     * - call handleApproveMessage
     * @expected
     * - mockSubmit must not call
     * - inserted sign must contain new signature only
     */
    it('should add guard sign to sign object when all conditions are met and signs are not enough', async () => {
      vi.spyOn(guardMessageEncs[0], 'verify').mockResolvedValue(true);
      vi.spyOn(signer as any, 'updateThreshold').mockResolvedValue(undefined);
      (signer as any).threshold = { expiry: 0, value: 7 };
      await signer.mockedHandleApproveMessage(
        {
          msg: 'test message',
          guards: activeGuards,
          initGuardIndex: 0,
        },
        'peerId-2',
        2,
        'random signature',
      );
      const sign = signer.getSigns()[0];
      expect(sign.signs).toEqual(
        Array(10)
          .fill('')
          .map((item, index) => (index === 2 ? 'random signature' : '')),
      );
      expect(mockSubmit).not.toHaveBeenCalled();
    });

    /**
     * @target GuardDetection.handleApproveMessage should call start sign
     * and send sign message when signature are enough
     * @dependencies
     * @scenario
     * - add sign instance to list with valid request and empty list of 6 signatures
     * - mock EdDsa verify to return true
     * - mock startSign method
     * - call handleApproveMessage
     * @expected
     * - mockedStartSign must call
     * - mockSubmit must call with start sign message
     */
    it('should call start sign and send sign message when signature are enough', async () => {
      activeGuards = await Promise.all(
        Array(7)
          .fill('')
          .map(async (item, index) => ({
            peerId: `peerId-${index}`,
            publicKey: await guardMessageEncs[index].getPk(),
          })),
      );
      vi.spyOn(signer as any, 'getApprovedGuards').mockResolvedValue(
        activeGuards,
      );
      const sign = signer.getSigns()[0];
      sign.request = {
        guards: activeGuards,
        timestamp: timestamp,
        index: 0,
      };
      sign.signs = sign.signs.map((item, index) =>
        index < 6 ? `random signature ${index}` : '',
      );
      const mockedStartSign = vi.spyOn(signer, 'startSign').mockResolvedValue();
      await signer.mockedHandleApproveMessage(
        {
          msg: 'test message',
          guards: activeGuards,
          initGuardIndex: 0,
        },
        'peerId-2',
        6,
        'random signature',
      );
      expect(mockedStartSign).toHaveBeenCalledTimes(1);
      expect(mockedStartSign).toHaveBeenCalledWith(
        'test message',
        activeGuards,
      );
      expect(mockSubmit).toHaveBeenCalledTimes(1);
      expect(mockSubmit).toHaveBeenCalledWith(
        expect.any(String),
        activeGuards.slice(1).map((item) => item.peerId),
      );
      const msg = JSON.parse(mockSubmit.mock.calls[0][0]);
      expect(msg.type).toEqual(startMessage);
      expect(msg.index).toEqual(0);
      expect(msg.timestamp).toEqual(timestamp);
      expect(msg.payload).toEqual({
        msg: 'test message',
        guards: activeGuards,
        signs: [
          ...Array(6)
            .fill('')
            .map((item, index) => `random signature ${index}`),
          'random signature',
          '',
          '',
          '',
        ],
      });
    });

    /**
     * @target GuardDetection.handleApproveMessage should do nothing when sign is invalid
     * @dependencies
     * @scenario
     * - add sign instance to list with valid request
     * - call handleApproveMessage with invalid message
     * @expected
     * - mockedStartSign must not call
     * - mockSubmit must not call
     */
    it('should do nothing when sign is invalid', async () => {
      const mockedStartSign = vi.spyOn(signer, 'startSign').mockResolvedValue();
      await signer.mockedHandleApproveMessage(
        {
          msg: 'test message invalid',
          guards: activeGuards,
          initGuardIndex: 0,
        },
        'peerId-2',
        2,
        'random signature',
      );
      expect(mockedStartSign).toHaveBeenCalledTimes(0);
      expect(mockSubmit).toHaveBeenCalledTimes(0);
    });

    /**
     * @target GuardDetection.handleApproveMessage should do nothing when sign have no request
     * @dependencies
     * @scenario
     * - add sign instance to list without request
     * - call handleApproveMessage
     * @expected
     * - mockedStartSign must not call
     * - mockSubmit must not call
     */
    it('should do nothing when sign have no request', async () => {
      const mockedStartSign = vi.spyOn(signer, 'startSign').mockResolvedValue();
      const sign = signer.getSigns()[0];
      sign.request = undefined;
      await signer.mockedHandleApproveMessage(
        {
          msg: 'test message',
          guards: activeGuards,
          initGuardIndex: 0,
        },
        'peerId-2',
        2,
        'random signature',
      );
      expect(mockedStartSign).toHaveBeenCalledTimes(0);
      expect(mockSubmit).toHaveBeenCalledTimes(0);
    });

    /**
     * @target GuardDetection.handleApproveMessage should do nothing in noWork time
     * @dependencies
     * @scenario
     * - add sign instance to list
     * - mock isNoWorkTime to return true
     * - call handleApproveMessage
     * @expected
     * - mockedStartSign must not call
     * - mockSubmit must not call
     */
    it('should do nothing in noWork time', async () => {
      const mockedStartSign = vi.spyOn(signer, 'startSign').mockResolvedValue();
      vi.spyOn(signer as any, 'isNoWorkTime').mockReturnValue(true);
      await signer.mockedHandleApproveMessage(
        {
          msg: 'test message',
          guards: activeGuards,
          initGuardIndex: 0,
        },
        'peerId-2',
        2,
        'random signature',
      );
      expect(mockedStartSign).toHaveBeenCalledTimes(0);
      expect(mockSubmit).toHaveBeenCalledTimes(0);
    });
  });

  describe('handleSignCachedMessage', () => {
    const addSign = async (msg: string) => {
      const sign = {
        msg,
        signs: Array(10).fill(''),
        addedTime: timestamp,
        callback: vi.fn(),
        request: {
          index: 0,
          guards: [
            {
              peerId: 'peerId-1',
              publicKey: await guardMessageEncs[1].getPk(),
            },
            {
              peerId: 'peerId-2',
              publicKey: await guardMessageEncs[2].getPk(),
            },
            {
              peerId: 'peerId-3',
              publicKey: await guardMessageEncs[3].getPk(),
            },
          ],
          timestamp,
        },
        posted: false,
        chainCode: 'chainCode',
      };
      signer.getSigns().push(sign);
      return sign;
    };

    /**
     * @target TssSigner.handleSignCachedMessage should return if sign record doesn't exist
     * @dependencies
     * @scenario
     * - mock getPkAndVerifySignature
     * - mock handleSuccessfulSign
     * - call handleSignCachedMessage
     * @expected
     * - getPkAndVerifySignature should not have been called
     * - handleSuccessfulSign should not have been called
     * - signature should not have been added to signCache
     */
    it("should return if sign record doesn't exist", async () => {
      // mock getPkAndVerifySignature
      const mockedGetPkAndVerifySignature = vi
        .spyOn(signer as any, 'getPkAndVerifySignature')
        .mockResolvedValue(true);

      // mock handleSuccessfulSign
      const mockedHandleSuccessfulSign = vi
        .spyOn(signer, 'handleSuccessfulSign')
        .mockResolvedValue();

      // call handleSignCachedMessage with cached message
      await signer.callHandleSignCachedMessage(
        {
          msg: 'test message',
          signature: 'signature',
          signatureRecovery: undefined,
        },
        'sender',
      );

      // getPkAndVerifySignature should not have been called
      expect(mockedGetPkAndVerifySignature).toHaveBeenCalledTimes(0);

      // handleSuccessfulSign should not have been called
      expect(mockedHandleSuccessfulSign).toHaveBeenCalledTimes(0);

      // signature should not have been added to signCache
      expect(signer.getSignCache()).not.toHaveProperty('test message');
    });

    /**
     * @target TssSigner.handleSignCachedMessage should call handleSuccessfulSign even when approving guards are less than threshold
     * @dependencies
     * @scenario
     * - mock sign
     * - mock getPkAndVerifySignature
     * - mock handleSuccessfulSign
     * - call handleSignCachedMessage
     * @expected
     * - getPkAndVerifySignature should have been called
     * - handleSuccessfulSign should have been called
     * - sign record should have been removed from sign array
     */
    it('should call handleSuccessfulSign even when approving guards are less than threshold', async () => {
      // mock sign
      const sign = await addSign('test message');

      // mock getPkAndVerifySignature
      const mockedGetPkAndVerifySignature = vi
        .spyOn(signer as any, 'getPkAndVerifySignature')
        .mockResolvedValue(true);

      // mock handleSuccessfulSign
      const mockedHandleSuccessfulSign = vi
        .spyOn(signer, 'handleSuccessfulSign')
        .mockResolvedValue();

      // call handleSignCachedMessage
      await signer.callHandleSignCachedMessage(
        {
          msg: 'test message',
          signature: 'signature',
          signatureRecovery: undefined,
        },
        'sender',
      );

      // getPkAndVerifySignature should have been called
      expect(mockedGetPkAndVerifySignature).toHaveBeenCalledTimes(1);
      expect(mockedGetPkAndVerifySignature).toHaveBeenCalledWith(
        'test message',
        'signature',
        'chainCode',
        undefined,
      );

      // handleSuccessfulSign should have been called
      expect(mockedHandleSuccessfulSign).toHaveBeenCalledTimes(1);
      expect(mockedHandleSuccessfulSign).toHaveBeenCalledWith(
        sign,
        'signature',
        undefined,
      );

      // sign record should have been removed from sign array
      expect(signer.mockedGetSign('test message')).toBeUndefined();
    });

    /**
     * @target TssSigner.handleSignCachedMessage should return if signature is not valid
     * @dependencies
     * @scenario
     * - mock sign
     * - mock getPkAndVerifySignature
     * - mock handleSuccessfulSign
     * - call handleSignCachedMessage
     * @expected
     * - getPkAndVerifySignature should have been called
     * - handleSuccessfulSign should not have been called
     * - signs array should have contained the signature
     */
    it('should return if signature is not valid', async () => {
      // mock sign
      await addSign('test message');

      // mock getPkAndVerifySignature
      const mockedGetPkAndVerifySignature = vi
        .spyOn(signer as any, 'getPkAndVerifySignature')
        .mockResolvedValue(false);

      // mock handleSuccessfulSign
      const mockedHandleSuccessfulSign = vi
        .spyOn(signer, 'handleSuccessfulSign')
        .mockResolvedValue();

      // call handleSignCachedMessage
      await signer.callHandleSignCachedMessage(
        {
          msg: 'test message',
          signature: 'signature',
          signatureRecovery: undefined,
        },
        'sender',
      );

      // getPkAndVerifySignature should have been called
      expect(mockedGetPkAndVerifySignature).toHaveBeenCalledTimes(1);
      expect(mockedGetPkAndVerifySignature).toHaveBeenCalledWith(
        'test message',
        'signature',
        'chainCode',
        undefined,
      );

      // handleSuccessfulSign should not have been called
      expect(mockedHandleSuccessfulSign).toHaveBeenCalledTimes(0);

      // signs array should have contained the signature
      expect(signer.mockedGetSign('test message')).toBeDefined();
    });
  });

  describe('handleStartMessage', () => {
    let activeGuards: Array<ActiveGuard>;
    let mockedStartSign: MockInstance;
    beforeEach(async () => {
      signer.getSigns().push({
        msg: 'signing message',
        signs: [],
        addedTime: timestamp,
        callback: vi.fn(),
        posted: false,
        chainCode: 'chainCode',
      });
      activeGuards = await Promise.all(
        guardMessageEncs.map(async (item, index) => ({
          peerId: `peerId-${index}`,
          publicKey: await item.getPk(),
        })),
      );
      mockedStartSign = vi.spyOn(signer, 'startSign').mockResolvedValue();
    });

    /**
     * @target GuardDetection.handleStartMessage should call start sign when all conditions are met
     * @dependencies
     * @scenario
     * - add sign instance to list
     * - mock startSign
     * - call handleStartMessage
     * @expected
     * - mockedStartSign must call once with `signing message` and activeGuards
     */
    it('should call start sign when all conditions are met', async () => {
      vi.spyOn(signer as any, 'getApprovedGuards').mockResolvedValue(
        activeGuards,
      );
      await signer.mockedHandleStartMessage(
        {
          msg: 'signing message',
          guards: activeGuards,
          signs: Array(10)
            .fill('')
            .map((item, index) => (index < 7 ? `signature ${index}` : '')),
        },
        timestamp,
        6,
        'peerId-6',
      );
      expect(mockedStartSign).toHaveBeenCalledTimes(1);
      expect(mockedStartSign).toHaveBeenCalledWith(
        'signing message',
        activeGuards,
      );
    });

    /**
     * @target GuardDetection.handleStartMessage should not call start sign when not required guard available
     * @dependencies
     * @scenario
     * - add sign instance to list
     * - mock startSign
     * - mock getApprovedGuards to return list of 6 guards
     * - mock updateThreshold
     * - call handleStartMessage
     * @expected
     * - mockedStartSign must not call
     */
    it('should not call start sign when not required guard available', async () => {
      vi.spyOn(signer as any, 'getApprovedGuards').mockResolvedValue(
        activeGuards.slice(0, 6),
      );
      vi.spyOn(signer as any, 'updateThreshold').mockResolvedValue(undefined);
      (signer as any).threshold = { expiry: 0, value: 7 };
      await signer.mockedHandleStartMessage(
        {
          msg: 'signing message',
          guards: activeGuards,
          signs: Array(10)
            .fill('')
            .map((item, index) => (index < 7 ? `signature ${index}` : '')),
        },
        timestamp,
        6,
        'peerId-6',
      );
      expect(mockedStartSign).toHaveBeenCalledTimes(0);
    });

    /**
     * @target GuardDetection.handleStartMessage should not call start sign when not guard turn
     * @dependencies
     * @scenario
     * - add sign instance to list
     * - mock startSign
     * - mock verify method of EdDSA signer to return false once
     * - call handleStartMessage with guard index 5
     * @expected
     * - mockedStartSign must not call
     */
    it('should not call start sign when not guard turn', async () => {
      await signer.mockedHandleStartMessage(
        {
          msg: 'signing message',
          guards: activeGuards,
          signs: Array(10)
            .fill('')
            .map((item, index) => (index < 7 ? `signature ${index}` : '')),
        },
        timestamp,
        5,
        'peerId-5',
      );
      expect(mockedStartSign).toHaveBeenCalledTimes(0);
    });

    /**
     * @target GuardDetection.handleStartMessage should not call start sign when selected guard not involved
     * @dependencies
     * @scenario
     * - add sign instance to list
     * - mock startSign
     * - remove guard index 0 from active guards
     * - call handleStartMessage
     * @expected
     * - mockedStartSign must not call
     */
    it('should not call start sign when selected guard not involved', async () => {
      await signer.mockedHandleStartMessage(
        {
          msg: 'signing message',
          guards: [...activeGuards.slice(1)],
          signs: Array(10)
            .fill('')
            .map((item, index) => (index < 7 ? `signature ${index}` : '')),
        },
        timestamp,
        6,
        'peerId-6',
      );
      expect(mockedStartSign).toHaveBeenCalledTimes(0);
    });

    /**
     * @target GuardDetection.handleStartMessage should not call start sign when message is invalid
     * @dependencies
     * @scenario
     * - add sign instance to list
     * - mock startSign
     * - call handleStartMessage with invalid message to sign
     * @expected
     * - mockedStartSign must not call
     */
    it('should not call start sign when message is invalid', async () => {
      await signer.mockedHandleStartMessage(
        {
          msg: 'signing message invalid',
          guards: activeGuards,
          signs: Array(10)
            .fill('')
            .map((item, index) => (index < 7 ? `signature ${index}` : '')),
        },
        timestamp,
        6,
        'peerId-5',
      );
      expect(mockedStartSign).toHaveBeenCalledTimes(0);
    });
  });

  describe('handleSignData', () => {
    const callback = vi.fn();
    beforeEach(() => {
      const signs = signer.getSigns();
      vi.resetAllMocks();
      signs.push({
        msg: 'valid signing data',
        callback: callback,
        signs: [],
        addedTime: 0,
        posted: true,
        chainCode: 'chainCode',
      });
    });

    /**
     * @target GuardDetection.handleSignData should throw error when sign does not exist
     * @dependencies
     * @scenario
     * - add sign instance to list
     * - call handleSignData with invalid message to sign
     * @expected
     * - throw exception
     */
    it('should throw error when sign does not exist', async () => {
      await expect(async () =>
        signer.handleSignData(
          StatusEnum.Success,
          'invalid signing data',
          'signature',
        ),
      ).rejects.toThrow();
    });

    /**
     * @target GuardDetection.handleSignData should throw error when status is success and no signature passed
     * @dependencies
     * @scenario
     * - add sign instance to list
     * - call handleSignData with valid message without signature
     * @expected
     * - throw exception
     */
    it('should throw error when status is success and no signature passed', async () => {
      await expect(async () =>
        signer.handleSignData(StatusEnum.Success, 'valid signing data'),
      ).rejects.toThrow();
    });

    /**
     * @target GuardDetection.handleSignData should call callback function with success status and signature
     * @dependencies
     * @scenario
     * - add sign instance to list
     * - call handleSignData
     * @expected
     * - callback function called once
     * - callback function called with true and undefined as message and signature
     */
    it('should call callback function with success status and signature', async () => {
      await signer.handleSignData(
        StatusEnum.Success,
        'valid signing data',
        'signature',
        'signature recovery',
      );
      expect(callback).toHaveBeenCalledTimes(1);
      expect(callback).toHaveBeenCalledWith(
        true,
        undefined,
        'signature',
        'signature recovery',
      );
    });

    /**
     * @target GuardDetection.handleSignData should call callback function with fail status and message
     * @dependencies
     * @scenario
     * - add sign instance to list
     * - call handleSignData with Failed status and error message
     * @expected
     * - callback function called once
     * - callback function called with false and error message
     */
    it('should call callback function with fail status and message', async () => {
      await signer.handleSignData(
        StatusEnum.Failed,
        'valid signing data',
        '',
        '',
        'error message',
      );
      expect(callback).toHaveBeenCalledTimes(1);
      expect(callback).toHaveBeenCalledWith(false, 'error message');
    });

    /**
     * @target GuardDetection.handleSignData should remove sign element from signing queue
     * @dependencies
     * @scenario
     * - add sign instance to list
     * - call handleSignData
     * @expected
     * - signing list must be empty
     */
    it('should remove sign element from signing queue', async () => {
      await signer.handleSignData(
        StatusEnum.Success,
        'valid signing data',
        'signature',
      );
      const signs = signer.getSigns();
      expect(signs.length).toEqual(0);
    });
  });

  describe('getApprovedGuards', () => {
    /**
     * @target TssSigner.getApprovedGuards should not return selected guard when signature is empty string
     * @dependencies
     * @scenario
     * - call function with one guard and list of empty string as signatures
     * @expected
     * - returned list must be empty
     */
    it('should not return selected guard when signature is empty string', async () => {
      const res = await signer.mockedGetApprovedGuards(
        timestamp,
        {
          guards: [
            {
              publicKey: await guardMessageEncs[1].getPk(),
              peerId: 'peer-Id1',
            },
          ],
          msg: 'testing message',
          initGuardIndex: 1,
        },
        Array(10).fill(''),
      );
      expect(res.length).toEqual(0);
    });

    /**
     * @target TssSigner.getApprovedGuards should not return selected guard when pk not in guardsPk
     * @dependencies
     * @scenario
     * - call function with one new guard and list of random strings as signatures
     * @expected
     * - returned list must be empty
     */
    it('should not return selected guard when pk not in guardsPk', async () => {
      const res = await signer.mockedGetApprovedGuards(
        timestamp,
        {
          guards: [
            {
              publicKey: await new EdDSA(await EdDSA.randomKey()).getPk(),
              peerId: 'peer-Id1',
            },
          ],
          msg: 'testing message',
          initGuardIndex: 1,
        },
        Array(10).fill('random-signature'),
      );
      expect(res.length).toEqual(0);
    });

    /**
     * @target TssSigner.getApprovedGuards should not return selected guard when signature is invalid
     * @dependencies
     * @scenario
     * - mock verify sign to return false
     * - call function with one guard and list of random strings as signatures
     * @expected
     * - returned list must be empty
     */
    it('should not return selected guard when signature is invalid', async () => {
      vi.spyOn(guardMessageEncs[0], 'verify').mockResolvedValue(false);
      const res = await signer.mockedGetApprovedGuards(
        timestamp,
        {
          guards: [
            {
              publicKey: await guardMessageEncs[0].getPk(),
              peerId: 'peer-Id1',
            },
          ],
          msg: 'testing message',
          initGuardIndex: 1,
        },
        Array(10).fill('random-signature'),
      );
      expect(res.length).toEqual(0);
    });

    /**
     * @target TssSigner.getApprovedGuards should return selected guard when signature is valid
     * @dependencies
     * @scenario
     * - mock verify sign to return true
     * - call function with one guard and list of random strings as signatures
     * @expected
     * - returned list must contain entered guard
     */
    it('should return selected guard when signature is valid', async () => {
      vi.spyOn(guardMessageEncs[0], 'verify').mockResolvedValue(true);
      const guards = [
        {
          publicKey: await guardMessageEncs[0].getPk(),
          peerId: 'peer-Id1',
        },
      ];
      const res = await signer.mockedGetApprovedGuards(
        timestamp,
        {
          guards,
          msg: 'testing message',
          initGuardIndex: 1,
        },
        Array(10).fill('random-signature'),
      );
      expect(res.length).toEqual(1);
      expect(res).toEqual(guards);
    });
  });

  describe('updateThreshold', () => {
    /**
     * @target TssSigner.updateThreshold should update threshold in the first time and using that instead of axios call
     * @dependencies
     * - Date
     * @scenario
     * - mock axios to return { data: { threshold: 6 } }
     * - call updateThreshold (should call axios and update expiry)
     * - call updateThreshold (should not call axios)
     * @expected
     * - must call axios once and cache threshold
     */
    it('should update threshold in the first time and using that instead of axios call', async () => {
      const mockedAxios = vi
        .spyOn((signer as any).axios, 'get')
        .mockReturnValue({ data: { threshold: 6 } });
      (signer as any).threshold = { expiry: 0 };
      await signer.mockedUpdateThreshold();
      await signer.mockedUpdateThreshold();
      expect(mockedAxios).toHaveBeenCalledTimes(1);
    });

    /**
     * @target TssSigner.updateThreshold should update threshold after expiredTime
     * @dependencies
     * - Date
     * @scenario
     * - mock `Date.now` to return 1686286005068 (currentTime)
     * - mock `signer.threshold` to return { expiry: currentTime, threshold: 7}
     * - mock axios to return { data: { threshold: 7 } }
     * - mock `Date.now` to return currentTime + 1ms
     * - call updateThreshold (should call axios)
     * @expected
     * - must call axios once after expiredTime
     */
    it('should update threshold after expiredTime', async () => {
      const mockedAxios = vi
        .spyOn((signer as any).axios, 'get')
        .mockReturnValue({ data: { threshold: 7 } });
      (signer as any).threshold = { expiry: currentTime, threshold: 7 };
      vi.setSystemTime(new Date(currentTime + 1));
      await signer.mockedUpdateThreshold();
      expect(mockedAxios).toHaveBeenCalledTimes(1);
    });
  });

  describe('getPkAndVerifySignature', () => {
    /**
     * @target TssSigner.getPkAndVerifySignature should return false when response from getPk is undefined
     * @dependencies
     * @scenario
     * - mock getPk
     * - call getPkAndVerifySignature
     * @expected
     * - getPk should have been called with correct PublicKeyID
     * - getPkAndVerifySignature should have returned false
     */
    it('should return false when response from getPk is undefined', async () => {
      // mock getPk
      const mockedGetPk = vi
        .spyOn(signer as any, 'getPk')
        .mockResolvedValue(undefined);

      // call getPkAndVerifySignature
      const verified = await signer.callGetPkAndVerifySignature(
        'test message',
        'signature',
        'chainCode',
        [0, 0, 0, 0],
      );

      expect(mockedGetPk).toHaveBeenCalledTimes(1);
      expect(mockedGetPk).toHaveBeenCalledWith({
        chainCode: 'chainCode',
        derivationPath: [0, 0, 0, 0],
      });
      expect(verified).toBe(false);
    });

    /**
     * @target TssSigner.getPkAndVerifySignature should return true when verify succeeds
     * @dependencies
     * @scenario
     * - mock getPk
     * - mock verify to return true
     * - call getPkAndVerifySignature with valid args
     * @expected
     * - getPk should have been called with correct PublicKeyID
     * - verify should have been called with message, signature and public key
     * - getPkAndVerifySignature should have returned true
     */
    it('should return true when verify succeeds', async () => {
      // mock getPk
      const mockedGetPk = vi
        .spyOn(signer as any, 'getPk')
        .mockResolvedValue('pk');

      // mock verify to return true
      const mockedVerify = vi.spyOn(signer, 'verify').mockResolvedValue(true);

      // call getPkAndVerifySignature with valid args
      const verified = await signer.callGetPkAndVerifySignature(
        'msg',
        'signature',
        'chainCode',
        undefined,
      );

      expect(mockedGetPk).toHaveBeenCalledTimes(1);
      expect(mockedGetPk).toHaveBeenCalledWith({
        chainCode: 'chainCode',
        derivationPath: [],
      });
      expect(mockedVerify).toHaveBeenCalledTimes(1);
      expect(mockedVerify).toHaveBeenCalledWith('msg', 'signature', 'pk');
      expect(verified).toBe(true);
    });

    /**
     * @target TssSigner.getPkAndVerifySignature should return false when verify fails
     * @dependencies
     * @scenario
     * - mock getPk
     * - mock verify to return false
     * - call getPkAndVerifySignature using invalid signature
     * @expected
     * - getPk should have been called with correct PublicKeyID
     * - verify should have been called with message, signature and public key
     * - getPkAndVerifySignature should have returned false
     */
    it('should return false when verify fails', async () => {
      // mock getPk
      const mockedGetPk = vi
        .spyOn(signer as any, 'getPk')
        .mockResolvedValue('pk');

      // mock verify to return false
      const mockedVerify = vi.spyOn(signer, 'verify').mockResolvedValue(false);

      // call getPkAndVerifySignature using invalid signature
      const verified = await signer.callGetPkAndVerifySignature(
        'msg',
        'signature',
        'chainCode',
        undefined,
      );

      expect(mockedGetPk).toHaveBeenCalledTimes(1);
      expect(mockedGetPk).toHaveBeenCalledWith({
        chainCode: 'chainCode',
        derivationPath: [],
      });
      expect(mockedVerify).toHaveBeenCalledTimes(1);
      expect(mockedVerify).toHaveBeenCalledWith('msg', 'signature', 'pk');
      expect(verified).toBe(false);
    });
  });
});
