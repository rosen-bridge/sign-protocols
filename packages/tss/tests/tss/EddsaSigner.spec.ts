import { EdDSA, EddsaSigner, GuardDetection } from '../../lib';
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
      const signer = new EdDSA(sk);
      vi.restoreAllMocks();
      vi.setSystemTime(new Date(currentTime));
      const detection = new GuardDetection({
        signer: signer,
        guardsPublicKey: [],
        submit: vi.fn(),
        getPeerId: () => Promise.resolve('myPeerId'),
      });
      const eddsaSigner = new EddsaSigner({
        submitMsg: vi.fn(),
        callbackUrl: '',
        secret: sk,
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
});
