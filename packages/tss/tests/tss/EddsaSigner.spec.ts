import { EddsaSigner } from '../../lib';
import { EdDSA } from '@rosen-bridge/encryption';
import { GuardDetection } from '@rosen-bridge/detection';
import { describe, expect, it, vi } from 'vitest';

describe('EddsaSigner', () => {
  const currentTime = 1686286005068;

  describe('signPromised', () => {
    /**
     * @target TssSigner.signPromised should throw error when derivationPath is defined
     * @dependencies
     * @scenario
     * - generate EddsaSigner object using mocked data
     * - call signPromised with derivationPath and check thrown exception
     * @expected
     * - it should throw Error
     */
    it('should throw error when derivationPath is defined', async () => {
      const sk = await EdDSA.randomKey();
      const eddsaMessageEnc = new EdDSA(sk);
      vi.restoreAllMocks();
      vi.setSystemTime(new Date(currentTime));
      const detection = new GuardDetection({
        messageEnc: eddsaMessageEnc,
        guardsPublicKey: [],
        submit: vi.fn(),
        getPeerId: () => Promise.resolve('myPeerId'),
      });
      const eddsaSigner = new EddsaSigner({
        submitMsg: vi.fn(),
        callbackUrl: '',
        messageEnc: eddsaMessageEnc,
        detection: detection,
        guardsPk: [],
        tssApiUrl: '',
        getPeerId: () => Promise.resolve('myPeerId'),
        shares: [],
      });

      await expect(async () => {
        await eddsaSigner.signPromised('message', 'chainCode', [0]);
      }).rejects.toThrow(Error);
    });
  });

  describe('verify', () => {
    /**
     * @target TssSigner.verify should return true when signature is valid
     * @dependencies
     * @scenario
     * - generate EddsaSigner object using mocked data
     * - call verify with valid args
     * @expected
     * - it should return true
     */
    it('should return true when signature is valid', async () => {
      const sk = await EdDSA.randomKey();
      const eddsaMessageEnc = new EdDSA(sk);
      const detection = new GuardDetection({
        messageEnc: eddsaMessageEnc,
        guardsPublicKey: [],
        submit: vi.fn(),
        getPeerId: () => Promise.resolve('myPeerId'),
      });
      const eddsaSigner = new EddsaSigner({
        submitMsg: vi.fn(),
        callbackUrl: '',
        messageEnc: eddsaMessageEnc,
        detection: detection,
        guardsPk: [],
        tssApiUrl: '',
        getPeerId: () => Promise.resolve('myPeerId'),
        shares: [],
      });

      const result = await eddsaSigner.verify(
        '00f163ee51bcaeff9cdff5e0e3c1a646abd19885fffbab0b3b4236e0cf95c9f5',
        '35b27be04dcd6d745c59f5e79f5466b5549e6158f65ba0e2884691163a7acf936e709f6d19cf666151e4a7e3eb59ebaf58e72dfacac517cb0b32ea0dac118808',
        '8d325970f72f8416ac9d0e5633e8a611c95ff482288615cd35f82bac443bdd9f',
      );

      expect(result).toBe(true);
    });

    /**
     * @target TssSigner.verify should return false when signature is invalid
     * @dependencies
     * @scenario
     * - generate EddsaSigner object using mocked data
     * - call verify with invalid args
     * @expected
     * - it should return false
     */
    it('should return false when signature is invalid', async () => {
      const sk = await EdDSA.randomKey();
      const eddsaMessageEnc = new EdDSA(sk);
      const detection = new GuardDetection({
        messageEnc: eddsaMessageEnc,
        guardsPublicKey: [],
        submit: vi.fn(),
        getPeerId: () => Promise.resolve('myPeerId'),
      });
      const eddsaSigner = new EddsaSigner({
        submitMsg: vi.fn(),
        callbackUrl: '',
        messageEnc: eddsaMessageEnc,
        detection: detection,
        guardsPk: [],
        tssApiUrl: '',
        getPeerId: () => Promise.resolve('myPeerId'),
        shares: [],
      });

      const result = await eddsaSigner.verify(
        '00f163ee51bcaeff9cdff5e0e3c1a646abd19885fffbab0b3b4236e0cf95c9f5',
        '35b27be04dcd6d745c59f5e79f5466b5549e6158f65ba0e2884691163a7acf936e709f6d19cf666151e4a7e3eb59ebaf58e72dfacac517cb0b32ea0dac118800',
        '8d325970f72f8416ac9d0e5633e8a611c95ff482288615cd35f82bac443bdd9f',
      );

      expect(result).toBe(false);
    });
  });
});
