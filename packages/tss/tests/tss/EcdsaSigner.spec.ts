import { EcdsaSigner } from '../../lib';
import { GuardDetection } from '@rosen-bridge/detection';
import { ECDSA } from '@rosen-bridge/encryption';
import { describe, expect, it, vi } from 'vitest';

describe('EcdsaSigner', () => {
  const currentTime = 1686286005068;

  describe('signPromised', () => {
    /**
     * @target TssSigner.signPromised should throw error when derivationPath is not defined
     * @dependencies
     * @scenario
     * - generate EcdsaSigner object using mocked data
     * - call signPromised with undefined derivationPath and check thrown exception
     * @expected
     * - it should throw Error
     */
    it('should throw error when derivationPath is not defined', async () => {
      const sk = await ECDSA.randomKey();
      const ecdsaMessageEnc = new ECDSA(sk);
      vi.restoreAllMocks();
      vi.setSystemTime(new Date(currentTime));
      const detection = new GuardDetection({
        messageEnc: ecdsaMessageEnc,
        guardsPublicKey: [],
        submit: vi.fn(),
        getPeerId: () => Promise.resolve('myPeerId'),
      });
      const ecdsaSigner = new EcdsaSigner({
        submitMsg: vi.fn(),
        callbackUrl: '',
        messageEnc: ecdsaMessageEnc,
        detection: detection,
        guardsPk: [],
        tssApiUrl: '',
        getPeerId: () => Promise.resolve('myPeerId'),
        shares: [],
      });

      await expect(async () => {
        await ecdsaSigner.signPromised('message', 'chainCode', undefined);
      }).rejects.toThrow(Error);
    });
  });

  describe('verify', () => {
    /**
     * @target TssSigner.verify should return true when signature is valid
     * @dependencies
     * @scenario
     * - generate EcdsaSigner object using mocked data
     * - call verify with valid args
     * @expected
     * - it should return true
     */
    it('should return true when signature is valid', async () => {
      const sk = await ECDSA.randomKey();
      const ecdsaMessageEnc = new ECDSA(sk);
      const detection = new GuardDetection({
        messageEnc: ecdsaMessageEnc,
        guardsPublicKey: [],
        submit: vi.fn(),
        getPeerId: () => Promise.resolve('myPeerId'),
      });
      const ecdsaSigner = new EcdsaSigner({
        submitMsg: vi.fn(),
        callbackUrl: '',
        messageEnc: ecdsaMessageEnc,
        detection: detection,
        guardsPk: [],
        tssApiUrl: '',
        getPeerId: () => Promise.resolve('myPeerId'),
        shares: [],
      });

      const result = await ecdsaSigner.verify(
        '00f163ee51bcaeff9cdff5e0e3c1a646abd19885fffbab0b3b4236e0cf95c9f5',
        'e243735e768eff64e5f74f51e997cb7841b9cf2213429c7254e9b3ac002b236c7e0f5700a72984f438168b9e532d47bd34eb23562cc105cfa395976f5b1b7d88.01',
        '02083407ed38e12ac9ebb0e456f9e8bb3d69bb55f3e2980864399245ccb591b7b2',
      );

      expect(result).toBe(true);
    });

    /**
     * @target TssSigner.verify should return false when signature is invalid
     * @dependencies
     * @scenario
     * - generate EcdsaSigner object using mocked data
     * - call verify with invalid args
     * @expected
     * - it should return false
     */
    it('should return false when signature is invalid', async () => {
      const sk = await ECDSA.randomKey();
      const ecdsaMessageEnc = new ECDSA(sk);
      const detection = new GuardDetection({
        messageEnc: ecdsaMessageEnc,
        guardsPublicKey: [],
        submit: vi.fn(),
        getPeerId: () => Promise.resolve('myPeerId'),
      });
      const ecdsaSigner = new EcdsaSigner({
        submitMsg: vi.fn(),
        callbackUrl: '',
        messageEnc: ecdsaMessageEnc,
        detection: detection,
        guardsPk: [],
        tssApiUrl: '',
        getPeerId: () => Promise.resolve('myPeerId'),
        shares: [],
      });

      const result = await ecdsaSigner.verify(
        '00f163ee51bcaeff9cdff5e0e3c1a646abd19885fffbab0b3b4236e0cf95c9f5',
        'e243735e768eff64e5f74f51e997cb7841b9cf2213429c7254e9b3ac002b236c7e0f5700a72984f438168b9e532d47bd34eb23562cc105cfa395976f5b1b7d80.01',
        '02083407ed38e12ac9ebb0e456f9e8bb3d69bb55f3e2980864399245ccb591b7b2',
      );

      expect(result).toBe(false);
    });
  });
});
