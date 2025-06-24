import { TestGuardDetection } from './TestGuardDetection';
import { EdDSA } from '@rosen-bridge/encryption';
import {
  approveMessage,
  heartbeatMessage,
  registerMessage,
} from '../lib/const/detection';
import { Nonce } from '../lib';
import { generateSigners } from './testUtils';
import { describe, expect, it, vi, beforeEach } from 'vitest';

describe('GuardDetection', () => {
  let detection: TestGuardDetection;
  let mockSubmit = vi.fn();
  let guardMessageEncs: Array<EdDSA>;

  beforeEach(async () => {
    const signers = await generateSigners();
    guardMessageEncs = signers.guardSigners;
    vi.resetAllMocks();
    mockSubmit = vi.fn();
    detection = new TestGuardDetection({
      submit: mockSubmit,
      messageEnc: guardMessageEncs[0],
      guardsPublicKey: signers.guardPks,
      getPeerId: () => Promise.resolve('myPeerId'),
    });
    detection.setNeedGuardThreshold(7);
  });

  describe('init', () => {
    /**
     * @target GuardDetection.init should call sendMessage with broadcast message of type register
     * @dependencies
     * @scenario
     * - mock submit function for GuardDetection
     * - call init
     * @expect
     * - must call submitFn once
     * - second argument of called submitFn must be an empty list
     * - first argument must be a json contain `type=registerMessage`
     */
    it('should call sendMessage with broadcast message of type register', async () => {
      await detection.init();
      expect(mockSubmit).toHaveBeenCalledTimes(1);
      expect(mockSubmit).toHaveBeenCalledWith(expect.any(String), []);
      const msg = JSON.parse(mockSubmit.mock.calls[0][0]);
      expect(msg.type).toEqual(registerMessage);
    });
    /**
     * @target GuardDetection.init should call not sendMessage with broadcast message when all guards have inactive guards have nonce
     * @dependencies
     * @scenario
     * - mock submit function for GuardDetection
     * - call init
     * @expect
     * - must call submitFn once
     * - second argument of called submitFn must be an empty list
     * - first argument must be a json contain `type=registerMessage`
     */
    it('should call not sendMessage with broadcast message when all guards have inactive guards have nonce', async () => {
      const info = detection.getInfo();
      info.forEach((item) => item.nonce.push(new Nonce()));
      await detection.init();
      expect(mockSubmit).toHaveBeenCalledTimes(0);
    });
  });

  describe('update', () => {
    /**
     * @target GuardDetection.update should call init when active guards contain less than threshold
     * @dependencies
     * @scenario
     * - mock GuardDetection.init
     * - call update
     * @expected
     * - GuardDetection.init must call
     */
    it('should call init when active guards contain less than threshold', async () => {
      detection.init = vi.fn();
      const currentTime = 1685683141;
      vi.setSystemTime(new Date(currentTime * 1000));
      const info = detection.getInfo();
      info.forEach((item, index) => {
        item.lastUpdate = index < 5 ? currentTime : 0;
        item.peerId = index < 5 ? `peerId-${index}` : '';
      });
      await detection.update();
      expect(detection.init).toHaveBeenCalledTimes(1);
    });

    /**
     * @target GuardDetection.update should do nothing when all guards are active
     * @dependencies
     * @scenario
     * - update detection.info and set for all peerId and current time
     * - mock Date.now to return expected timestamp
     * - call update
     * @expected
     * - mockSubmit must not call
     */
    it('should do nothing when all guards are active', async () => {
      const info = detection.getInfo();
      const currentTime = 1685683141;
      info.forEach((item, index) => {
        item.lastUpdate = currentTime;
        item.peerId = `peerId-${index}`;
      });
      vi.setSystemTime(new Date(currentTime * 1000));
      await detection.update();
      expect(mockSubmit).toHaveBeenCalledTimes(0);
    });

    /**
     * @target GuardDetection.update should call submitMessage for each timed out guard
     * @dependencies
     * @scenario
     * - update detection.info and set for all peerId and current time
     * - set time of current time - 2 minutes for one of guards
     * - mock Date.now to return expected timestamp
     * - call update
     * @expected
     * - mockSubmit must call once
     * - mockSubmit must call with message type of heartbeatMessage
     */
    it('should call submitMessage for each timed out guard', async () => {
      const info = detection.getInfo();
      const currentTime = 1685683141;
      info.forEach((item, index) => {
        item.lastUpdate = currentTime;
        item.peerId = `peerId-${index}`;
      });
      info[2].lastUpdate = currentTime - 2 * 60; // 2 minutes
      vi.setSystemTime(new Date(currentTime * 1000));
      await detection.update();
      expect(mockSubmit).toHaveBeenCalledTimes(1);
      expect(mockSubmit).toHaveBeenCalledWith(expect.any(String), [`peerId-2`]);
      const msg = JSON.parse(mockSubmit.mock.calls[0][0]);
      expect(msg.type).toEqual(heartbeatMessage);
    });
  });

  describe('processMessage', () => {
    /**
     * @target GuardDetection.processMessage should call handleRegisterMessage
     * when message type is registerMessage
     * @dependencies
     * @scenario
     * - mock handleRegisterMessage
     * - call processMessage
     * @expected
     * - mocked function must call with expected arguments
     */
    it('should call handleRegisterMessage when message type is registerMessage', async () => {
      const mockedFn = ((detection as any).handleRegisterMessage = vi.fn());
      await detection.processMessage(registerMessage, {}, '', 1, 'peerId', 0);
      expect(mockedFn).toHaveBeenCalledTimes(1);
      expect(mockedFn).toHaveBeenCalledWith({}, 'peerId', 1);
    });

    /**
     * @target GuardDetection.processMessage should call handleHeartbeatMessage
     * when message type is heartbeatMessage
     * @dependencies
     * @scenario
     * - mock handleHeartbeatMessage
     * - call processMessage
     * @expected
     * - mocked function must call with expected arguments
     */
    it('should call handleHeartbeatMessage when message type is heartbeatMessage', async () => {
      const mockedFn = ((detection as any).handleHeartbeatMessage = vi.fn());
      await detection.processMessage(heartbeatMessage, {}, '', 1, 'peerId', 0);
      expect(mockedFn).toHaveBeenCalledTimes(1);
      expect(mockedFn).toHaveBeenCalledWith({}, 'peerId', 1);
    });

    /**
     * @target GuardDetection.processMessage should call handleApproveMessage
     * when message type is approveMessage
     * @dependencies
     * @scenario
     * - mock handleApproveMessage
     * - call processMessage
     * @expected
     * - mocked function must call with expected arguments
     */
    it('should call handleApproveMessage when message type is approveMessage', async () => {
      const mockedFn = ((detection as any).handleApproveMessage = vi.fn());
      await detection.processMessage(approveMessage, {}, '', 1, 'peerId', 0);
      expect(mockedFn).toHaveBeenCalledTimes(1);
      expect(mockedFn).toHaveBeenCalledWith({}, 'peerId', 1);
    });
  });

  describe('activeGuards', () => {
    /**
     * @target GuardDetection.activeGuards should return list of valid guards
     * @dependencies
     * @scenario
     * - change info list of detection and set current time for even guards
     * - get list of active guards
     * @expect
     * - returned list must contain 5 element
     * - peerId of returned list must be peerId-0 to peerId-8 with even index
     */
    it('should return list of valid guards', async () => {
      const info = detection.getInfo();
      const currentTime = 1685683141;
      vi.setSystemTime(new Date(currentTime * 1000));
      info.forEach((item, index) => {
        if (index % 2 == 0 && index !== 0) {
          // exclude my index
          item.lastUpdate = currentTime;
          item.peerId = `peerId-${index}`;
        }
      });
      const guards = await detection.activeGuards();
      expect(guards.length).toEqual(5);
      expect(guards.map((item) => item.peerId).sort()).toEqual([
        'myPeerId',
        'peerId-2',
        'peerId-4',
        'peerId-6',
        'peerId-8',
      ]);
    });

    /**
     * @target GuardDetection.activeGuards should not return timed out guard
     * @dependencies
     * @scenario
     * - change info list of detection and set current time and peerId for all guards
     * - set last update time for one guard ( index 3 ) to 2 minutes before
     * - get list of active guards
     * @expect
     * - returned list must contain 9 element
     * - peerId of returned list must not contain peerId-3
     */
    it('should not return timed out guard', async () => {
      const info = detection.getInfo();
      const currentTime = 1685683141;
      vi.setSystemTime(new Date(currentTime * 1000));
      const myPk = await guardMessageEncs[0].getPk();
      info.forEach((item, index) => {
        if (item.publicKey !== myPk) {
          item.lastUpdate = currentTime;
          item.peerId = `peerId-${index}`;
        }
      });
      info[3].lastUpdate = currentTime - 2 * 60;
      const guards = await detection.activeGuards();
      expect(guards.length).toEqual(9);
      expect(guards.map((item) => item.peerId).indexOf('peerId-3')).toEqual(-1);
    });
  });

  describe('register', () => {
    /**
     * @target GuardDetection.register should call callback with false if public key is invalid
     * @dependencies
     * @scenario
     * - mock Date.now
     * - fill list of info for all guards
     * - call register for one public key with invalid peerId
     * @expected
     * - callback must call with (false and any string)
     */
    it('should call callback with false if public key is invalid', async () => {
      const currentTime = 1685683141;
      vi.setSystemTime(new Date(currentTime * 1000));
      const callback = vi.fn();
      await detection.register('peerId-1', 'invalid public key', callback);
      expect(callback).toHaveBeenCalledTimes(1);
      expect(callback).toHaveBeenCalledWith(false, expect.any(String));
    });

    /**
     * @target GuardDetection.register should call callback with false if the guard is in the list but peerId is not the same
     * @dependencies
     * @scenario
     * - set some peerId for one guard
     * - mock Date.now to return valid date
     * - call register with different peerId
     * @expected
     * - callback must call with (false and any string)
     */
    it('should call callback with false if the guard is in the list but peerId is not the same', async () => {
      const currentTime = 1685683141;
      vi.setSystemTime(new Date(currentTime * 1000));
      const info = detection.getInfo();
      info[1].peerId = 'newPeerId-1';
      info[1].lastUpdate = currentTime;
      const callback = vi.fn();
      await detection.register(
        'peerId-1',
        await guardMessageEncs[1].getPk(),
        callback,
      );
      await expect(callback).toHaveBeenCalledTimes(1);
      await expect(callback).toHaveBeenCalledWith(false, expect.any(String));
    });

    /**
     * @target GuardDetection.register should call callback with true if the guard is in the list and peerId is valid
     * @dependencies
     * @scenario
     * - set some peerId for one guard
     * - mock Date.now to return valid date
     * - call register with same peerId
     * @expected
     * - callback must call with (true)
     */
    it('should call callback with true if the guard is in the list and peerId is valid', async () => {
      const currentTime = 1685683141;
      vi.setSystemTime(new Date(currentTime * 1000));
      const info = detection.getInfo();
      info[1].peerId = 'peerId-1';
      info[1].lastUpdate = currentTime;
      const callback = vi.fn();
      await detection.register(
        'peerId-1',
        await guardMessageEncs[1].getPk(),
        callback,
      );
      await expect(callback).toHaveBeenCalledTimes(1);
      await expect(callback).toHaveBeenCalledWith(true);
    });

    /**
     * @target GuardDetection.register should call send message if guard is not in active state
     * @dependencies
     * @scenario
     * - call register for once inactive guard
     * @expected
     * - submitMsg called once
     * - submitMsg called with second argument as passed peerId
     * - submitMsg called with message type of registerMessage
     */
    it('should call send message if guard is not in active state', async () => {
      await detection.register(
        'peerId-1',
        await guardMessageEncs[1].getPk(),
        vi.fn(),
      );
      expect(mockSubmit).toHaveBeenCalledTimes(1);
      expect(mockSubmit.mock.calls[0][1]).toEqual(['peerId-1']);
      const msg = JSON.parse(mockSubmit.mock.calls[0][0]);
      expect(msg.type).toEqual(registerMessage);
    });
  });

  describe('handleRegisterMessage', () => {
    /**
     * @target GuardDetection.handleRegisterMessage should call submitMsg
     * @dependencies
     * @scenario
     * - mock addNonce of guardDetection to return expected nonce
     * - call handleRegisterMessage
     * @expect
     * - submitMsg must call with selected guard as peerId
     * - passed string must contain
     *   - approveMessage as type
     *   - mocked nonce as nonce
     *   - passed nonce as receivedNonce
     */
    it('should call submitMsg', async () => {
      vi.spyOn(detection as any, 'addNonce').mockReturnValue('new nonce');
      await detection.mockedHandleRegister(
        { nonce: 'random nonce' },
        await guardMessageEncs[1].getPk(),
        1,
      );
      expect(mockSubmit).toHaveBeenCalledTimes(1);
      expect(mockSubmit).toHaveBeenCalledWith(expect.any(String), [
        await guardMessageEncs[1].getPk(),
      ]);
      const msg = JSON.parse(mockSubmit.mock.calls[0][0]);
      expect(msg.type).toEqual(approveMessage);
      expect(msg.payload.nonce).toEqual('new nonce');
      expect(msg.payload.receivedNonce).toEqual('random nonce');
    });
  });

  describe('handleApproveMessage', () => {
    /**
     * @target GuardDetection.handleApproveMessage should update guard state if nonce is valid
     * @dependencies
     * @scenario
     * - mock Date.now to return expected time
     * - add nonce to one of guards nonce list
     * - call handleApproveMessage
     * @expected
     * - nonce list of guard must be empty
     * - peerId of guard must set
     * - last update of guard must set
     * - submitMsg must not call
     */
    it('should update guard state if nonce is valid', async () => {
      const currentTime = 1685683141;
      vi.setSystemTime(new Date(currentTime * 1000));
      const info = detection.getInfo();
      const guard = info[2];
      guard.nonce = [new Nonce()];
      await detection.mockedHandleApprove(
        { receivedNonce: guard.nonce[0].bytes },
        'peerId-2',
        2,
      );
      expect(guard.nonce).toEqual([]);
      expect(guard.peerId).toEqual('peerId-2');
      expect(guard.lastUpdate).toEqual(currentTime);
      expect(mockSubmit).toHaveBeenCalledTimes(0);
    });

    /**
     * @target GuardDetection.handleApproveMessage should call all callbacks with true
     * @dependencies
     * @scenario
     * - mock Date.now to return expected time
     * - add nonce to one of guards nonce list
     * - add two mock fn as callback to list of callbacks of guard
     * - call handleApproveMessage
     * @expected
     * - both mock functions called once with true
     * - callback list must be empty list
     */
    it('should update guard state if nonce is valid', async () => {
      const currentTime = 1685683144;
      vi.setSystemTime(new Date(currentTime * 1000));
      const info = detection.getInfo();
      const guard = info[4];
      const fn1 = vi.fn(),
        fn2 = vi.fn();
      guard.nonce = [new Nonce()];
      guard.callback = [fn1, fn2];
      await detection.mockedHandleApprove(
        { receivedNonce: guard.nonce[0].bytes },
        'peerId-4',
        4,
      );
      expect(fn1).toHaveBeenCalledTimes(1);
      expect(fn2).toHaveBeenCalledTimes(1);
      expect(fn1).toHaveBeenCalledWith(true);
      expect(fn2).toHaveBeenCalledWith(true);
      expect(guard.callback).toEqual([]);
    });

    /**
     * @target GuardDetection.handleApproveMessage should call submitMsg when nonce set in payload
     * @dependencies
     * @scenario
     * - add nonce to one of guards nonce list
     * - call handleApproveMessage
     * @expected
     * - submitMsg must call once with second arg as ['peerId-3']
     * - first call arg must be a json with
     *   - type as approveMessage
     *   - {nonce: 'new nonce'} as payload
     */
    it('should call submitMsg when nonce set in payload', async () => {
      const info = detection.getInfo();
      const guard = info[3];
      guard.nonce = [new Nonce()];
      await detection.mockedHandleApprove(
        { receivedNonce: guard.nonce[0].bytes, nonce: 'new nonce' },
        'peerId-3',
        3,
      );
      expect(mockSubmit).toHaveBeenCalledTimes(1);
      expect(mockSubmit).toHaveBeenCalledWith(expect.any(String), ['peerId-3']);
      const msg = JSON.parse(mockSubmit.mock.calls[0][0]);
      expect(msg.type).toEqual(approveMessage);
      expect(msg.payload).toEqual({ receivedNonce: 'new nonce' });
    });

    /**
     * @target GuardDetection.handleApproveMessage should do nothing when nonce is invalid
     * @dependencies
     * @scenario
     * - mock date.now
     * - add a nonce for specific guard
     * - call handleApproveMessage
     * @expected
     * - submit must not call
     * - selected guard nonce list size must be 1
     * - selected guard must not have peerId
     * - selected guard last update must not change
     */
    it('should do nothing when nonce is invalid', async () => {
      const currentTime = 1685683142;
      vi.setSystemTime(new Date(currentTime * 1000));
      const info = detection.getInfo();
      const guard = info[3];
      guard.nonce = [new Nonce()];
      await detection.mockedHandleApprove(
        { receivedNonce: 'invalid nonce', nonce: 'new nonce' },
        'peerId-3',
        3,
      );
      expect(mockSubmit).toHaveBeenCalledTimes(0);
      expect(guard.nonce.length).toEqual(1);
      expect(guard.peerId).toEqual('');
      expect(guard.lastUpdate).toEqual(0);
    });
  });

  describe('handleHeartbeatMessage', () => {
    /**
     * @target GuardDetection.handleHeartbeatMessage should call send message with received nonce
     * @dependencies
     * @scenario
     * - call handleHeartbeatMessage with 'random nonce' in payload
     * @expect
     * - submitMsg call once
     * - passed string must contain
     *   - approveMessage as type
     *   - 'random nonce' as receivedNonce
     */
    it('should call send message with received nonce', async () => {
      await detection.mockedHandleHeartbeat(
        { nonce: 'random nonce' },
        'peerId-3',
        3,
      );
      expect(mockSubmit).toHaveBeenCalledTimes(1);
      expect(mockSubmit).toHaveBeenCalledWith(expect.any(String), ['peerId-3']);
      const msg = JSON.parse(mockSubmit.mock.calls[0][0]);
      expect(msg.type).toEqual(approveMessage);
      expect(msg.payload.receivedNonce).toEqual('random nonce');
    });
  });

  describe('addNonce', () => {
    /**
     * @target GuardDetection.addNonce should call clearNonce
     * @dependencies
     * @scenario
     * - mock clearNonce
     * - call addNonce
     * @expect
     * - mocked clearNonce must call once
     */
    it('should call clearNonce', () => {
      const mocked = vi
        .spyOn(detection as any, 'clearNonce')
        .mockReturnValue(undefined);
      detection.mockAddNonce();
      expect(mocked).toHaveBeenCalledTimes(1);
    });

    /**
     * @target GuardDetection.addNonce should add nonce to entered guard index only
     * @dependencies
     * @scenario
     * - call addNonce with index 3 twice
     * @expect
     * - all guards info nonce list must be empty expect index 3
     */
    it('should add nonce to entered guard index only', () => {
      detection.mockAddNonce(3);
      detection.mockAddNonce(3);
      const infos = detection.getInfo();
      infos.forEach((info, index) => {
        expect(info.nonce.length).toEqual(index === 3 ? 2 : 0);
      });
    });

    /**
     * @target GuardDetection.addNonce should add nonce to all guards when no index entered
     * @dependencies
     * @scenario
     * - call addNonce twice
     * @expect
     * - all guards info nonce list must have length of 2
     */
    it('should add nonce to all guards when no index entered', () => {
      detection.mockAddNonce();
      detection.mockAddNonce();
      const infos = detection.getInfo();
      // expect(info[3].nonce.length).toEqual(1)
      infos.forEach((info) => {
        expect(info.nonce.length).toEqual(2);
      });
    });
  });

  describe('clearNonce', () => {
    /**
     * @target GuardDetection.clearNonce should remove all old nonce in list
     * @dependencies
     * @scenario
     * - mock Date.now
     * - add two nonce in each of guards info list
     *   - first a timed out nonce
     *   - second a valid nonce
     * - call clearNonce
     * @expect
     * - all guards info nonce list must have length of 1
     */
    it('should remove all old nonce in list', () => {
      const currentTime = 1685683147;
      vi.setSystemTime(new Date(currentTime * 1000));
      const infos = detection.getInfo();
      infos.forEach((info) => {
        const oldNonce1 = new Nonce();
        const oldNonce2 = new Nonce();
        oldNonce1.timestamp =
          currentTime - detection.getMessageValidDuration() - 1;
        oldNonce2.timestamp =
          currentTime - detection.getMessageValidDuration() + 1;
        info.nonce = [oldNonce1, oldNonce2];
      });
      detection.mockClearNonce();
      infos.map((info) => {
        expect(info.nonce.length).toEqual(1);
      });
    });
  });
});
