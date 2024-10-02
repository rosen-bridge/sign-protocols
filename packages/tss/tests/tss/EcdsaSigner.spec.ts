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
      const signer = new ECDSA(sk);
      vi.restoreAllMocks();
      vi.setSystemTime(new Date(currentTime));
      const detection = new GuardDetection({
        signer: signer,
        guardsPublicKey: [],
        submit: vi.fn(),
        getPeerId: () => Promise.resolve('myPeerId'),
      });
      const ecdsaSigner = new EcdsaSigner({
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
        await ecdsaSigner.signPromised('message', 'chainCode', undefined);
      }).rejects.toThrow(Error);
    });
  });
});
