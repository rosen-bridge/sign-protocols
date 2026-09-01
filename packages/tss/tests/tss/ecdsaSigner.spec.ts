import { describe, expect, it, vi } from 'vitest';

import { GuardDetection } from '@rosen-bridge/detection';
import { ECDSA } from '@rosen-bridge/encryption';

import { EcdsaSigner } from '../../lib';

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
     * @target TssSigner.verify should return true when signature and signatureRecovery are valid
     * @dependencies
     * @scenario
     * - generate EcdsaSigner object using mocked data
     * - call verify with valid signature and signatureRecovery
     * @expected
     * - it should return true
     */
    it('should return true when signature and signatureRecovery are valid', async () => {
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
        'e243735e768eff64e5f74f51e997cb7841b9cf2213429c7254e9b3ac002b236c7e0f5700a72984f438168b9e532d47bd34eb23562cc105cfa395976f5b1b7d88',
        '02083407ed38e12ac9ebb0e456f9e8bb3d69bb55f3e2980864399245ccb591b7b2',
        '01',
      );

      expect(result).toBe(true);
    });

    /**
     * @target TssSigner.verify should return false when signatureRecovery is not provided
     * @dependencies
     * @scenario
     * - generate EcdsaSigner object using mocked data
     * - call verify with an otherwise-valid signature but no signatureRecovery
     * @expected
     * - it should return false
     */
    it('should return false when signatureRecovery is not provided', async () => {
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
        'e243735e768eff64e5f74f51e997cb7841b9cf2213429c7254e9b3ac002b236c7e0f5700a72984f438168b9e532d47bd34eb23562cc105cfa395976f5b1b7d88',
        '02083407ed38e12ac9ebb0e456f9e8bb3d69bb55f3e2980864399245ccb591b7b2',
      );

      expect(result).toBe(false);
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
        'e243735e768eff64e5f74f51e997cb7841b9cf2213429c7254e9b3ac002b236c7e0f5700a72984f438168b9e532d47bd34eb23562cc105cfa395976f5b1b7d80',
        '02083407ed38e12ac9ebb0e456f9e8bb3d69bb55f3e2980864399245ccb591b7b2',
        '01',
      );

      expect(result).toBe(false);
    });

    /**
     * @target TssSigner.verify should return true when signatureRecovery recovers to signerPublicKey
     * @dependencies
     * @scenario
     * - generate EcdsaSigner object using mocked data
     * - call verify with a valid signature and its matching signatureRecovery
     * @expected
     * - it should return true
     */
    it('should return true when signatureRecovery recovers to signerPublicKey', async () => {
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
        '011eb0f4c9e53ec10be13d24d40b01415d71ebdc06c8539acb2641d9709d2197',
        'abc7153560a9fca1ee346db1e00c7f5e0452b0baf6952f5200ea9ed30b19a6d83a080aecad1ec165e12c794e37601bfa2f537928949fa535d27d79f3905d0974',
        '03156a915838874bddce4581fcfe4de5a004a885d5e255228ec641b7383510ee36',
        '01',
      );

      expect(result).toBe(true);
    });

    /**
     * @target TssSigner.verify should return false when signatureRecovery recovers to a different public key
     * @dependencies
     * @scenario
     * - generate EcdsaSigner object using mocked data
     * - call verify with a valid signature but a signatureRecovery that recovers to another key
     * @expected
     * - it should return false
     */
    it('should return false when signatureRecovery recovers to a different public key', async () => {
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
        '011eb0f4c9e53ec10be13d24d40b01415d71ebdc06c8539acb2641d9709d2197',
        'abc7153560a9fca1ee346db1e00c7f5e0452b0baf6952f5200ea9ed30b19a6d83a080aecad1ec165e12c794e37601bfa2f537928949fa535d27d79f3905d0974',
        '03156a915838874bddce4581fcfe4de5a004a885d5e255228ec641b7383510ee36',
        '00',
      );

      expect(result).toBe(false);
    });

    /**
     * @target TssSigner.verify should return false without throwing when signatureRecovery is unrecoverable
     * @dependencies
     * @scenario
     * - generate EcdsaSigner object using mocked data
     * - call verify with a valid signature but an out-of-range signatureRecovery
     * @expected
     * - it should resolve to false, not reject
     */
    it('should return false without throwing when signatureRecovery is unrecoverable', async () => {
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

      await expect(
        ecdsaSigner.verify(
          '011eb0f4c9e53ec10be13d24d40b01415d71ebdc06c8539acb2641d9709d2197',
          'abc7153560a9fca1ee346db1e00c7f5e0452b0baf6952f5200ea9ed30b19a6d83a080aecad1ec165e12c794e37601bfa2f537928949fa535d27d79f3905d0974',
          '03156a915838874bddce4581fcfe4de5a004a885d5e255228ec641b7383510ee36',
          '02',
        ),
      ).resolves.toBe(false);
    });

    /**
     * @target TssSigner.verify should return false when base signature is invalid regardless of signatureRecovery
     * @dependencies
     * @scenario
     * - generate EcdsaSigner object using mocked data
     * - call verify with an invalid signature and a well-formed signatureRecovery
     * @expected
     * - it should return false
     */
    it('should return false when base signature is invalid regardless of signatureRecovery', async () => {
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
        'e243735e768eff64e5f74f51e997cb7841b9cf2213429c7254e9b3ac002b236c7e0f5700a72984f438168b9e532d47bd34eb23562cc105cfa395976f5b1b7d80',
        '02083407ed38e12ac9ebb0e456f9e8bb3d69bb55f3e2980864399245ccb591b7b2',
        '01',
      );

      expect(result).toBe(false);
    });
  });

  describe('recoverPublicKey', () => {
    /**
     * @target TssSigner.recoverPublicKey should recover the signer's compressed public key
     * @dependencies
     * @scenario
     * - generate EcdsaSigner object using mocked data
     * - call recoverPublicKey with a valid message, signature and recovery id
     * @expected
     * - it should return the expected compressed public key hex
     */
    it("should recover the signer's compressed public key", async () => {
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

      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const recoveredPublicKey = (ecdsaSigner as any).recoverPublicKey(
        '011eb0f4c9e53ec10be13d24d40b01415d71ebdc06c8539acb2641d9709d2197',
        'abc7153560a9fca1ee346db1e00c7f5e0452b0baf6952f5200ea9ed30b19a6d83a080aecad1ec165e12c794e37601bfa2f537928949fa535d27d79f3905d0974',
        '01',
      );

      expect(recoveredPublicKey).toBe(
        '03156a915838874bddce4581fcfe4de5a004a885d5e255228ec641b7383510ee36',
      );
    });

    /**
     * @target TssSigner.recoverPublicKey should return undefined when the recovery id is unrecoverable
     * @dependencies
     * @scenario
     * - generate EcdsaSigner object using mocked data
     * - call recoverPublicKey with an out-of-range recovery id
     * @expected
     * - it should return undefined instead of throwing
     */
    it('should return undefined when the recovery id is unrecoverable', async () => {
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

      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const recoveredPublicKey = (ecdsaSigner as any).recoverPublicKey(
        '011eb0f4c9e53ec10be13d24d40b01415d71ebdc06c8539acb2641d9709d2197',
        'abc7153560a9fca1ee346db1e00c7f5e0452b0baf6952f5200ea9ed30b19a6d83a080aecad1ec165e12c794e37601bfa2f537928949fa535d27d79f3905d0974',
        '02',
      );

      expect(recoveredPublicKey).toBeUndefined();
    });
  });
});
