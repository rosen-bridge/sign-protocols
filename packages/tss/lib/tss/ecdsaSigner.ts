import pkg from 'secp256k1';

import { Sign, SignerConfig, SignResult } from '../types/signer';
import { TssSigner } from './tssSigner';

export class EcdsaSigner extends TssSigner {
  constructor(config: SignerConfig) {
    super({
      logger: config.logger,
      guardsPk: config.guardsPk,
      signingCrypto: 'ecdsa',
      messageEnc: config.messageEnc,
      submitMsg: config.submitMsg,
      messageValidDuration: config.messageValidDuration,
      timeoutSeconds: config.timeoutSeconds,
      tssApiUrl: config.tssApiUrl,
      callbackUrl: config.callbackUrl,
      detection: config.detection,
      turnDurationSeconds: config.turnDurationSeconds,
      turnNoWorkSeconds: config.turnNoWorkSeconds,
      getPeerId: config.getPeerId,
      shares: config.shares,
      thresholdTTL: config.thresholdTTL,
      responseDelay: config.responseDelay,
      signPerRoundLimit: config.signPerRoundLimit,
    });
  }

  /**
   * sign message and return promise
   * @param message
   * @param chainCode
   * @param derivationPath
   */
  signPromised = (
    message: string,
    chainCode: string,
    derivationPath?: number[],
  ): Promise<SignResult> => {
    return new Promise<SignResult>((resolve, reject) => {
      if (!derivationPath)
        throw Error(`derivationPath is required in ECDSA signing`);
      this.sign(
        message,
        (
          status: boolean,
          message?: string,
          signature?: string,
          signatureRecovery?: string,
        ) => {
          if (status && signature && signatureRecovery)
            resolve({
              signature,
              signatureRecovery,
            });
          reject(message);
        },
        chainCode,
        derivationPath,
      )
        .then(() => null)
        .catch((e) => reject(e));
    });
  };

  /**
   * handles signing data callback in case of successful sign
   * @param sign
   * @param signature
   * @param signatureRecovery
   */
  handleSuccessfulSign = async (
    sign: Sign,
    signature?: string,
    signatureRecovery?: string,
  ): Promise<void> => {
    if (signature && signatureRecovery) {
      sign.callback(true, undefined, signature, signatureRecovery);
    } else {
      throw Error(
        'signature and signature recovery are required when ECDSA sign is successful',
      );
    }
  };

  /**
   * recover the signer's public key from a signed message digest and its recovery id
   * returns undefined if the public key can not be recovered, e.g. an invalid recovery id
   * @param message hex string
   * @param signature hex string
   * @param signatureRecovery hex encoded recovery id, as returned alongside `signature`
   */
  protected recoverPublicKey = (
    message: string,
    signature: string,
    signatureRecovery: string,
  ): string | undefined => {
    try {
      const msg = Buffer.from(message, 'hex');
      const sign = Buffer.from(signature, 'hex');
      const recoveryId = parseInt(signatureRecovery, 16);
      const recoveredPublicKey = pkg.ecdsaRecover(sign, recoveryId, msg, true);
      return Buffer.from(recoveredPublicKey).toString('hex');
    } catch (e) {
      this.logger.warn(
        `failed to recover public key from signature [${signature}] and signatureRecovery [${signatureRecovery}]: ${e}`,
      );
      return undefined;
    }
  };

  /**
   * verify message signature, and that signatureRecovery recovers to signerPublicKey
   * returns false when signatureRecovery is not provided, since a genuine ECDSA
   * signature produced by tss-api always includes a recovery id
   * @param message hex string
   * @param signature hex string
   * @param signerPublicKey hex string
   * @param signatureRecovery hex encoded recovery id
   */
  verify = async (
    message: string,
    signature: string,
    signerPublicKey: string,
    signatureRecovery?: string,
  ): Promise<boolean> => {
    const baseError = `signature is invalid [signature:${signature}, message:${message}, pk:${signerPublicKey}]`;
    const msg = Buffer.from(message, 'hex');
    const sign = Buffer.from(signature, 'hex');
    const publicKey = Buffer.from(signerPublicKey, 'hex');
    if (!pkg.ecdsaVerify(sign, msg, publicKey)) {
      this.logger.debug(baseError);
      return false;
    }

    if (signatureRecovery === undefined) {
      this.logger.debug(`${baseError}: signatureRecovery is undefined`);
      return false;
    }

    const recoveredPublicKey = this.recoverPublicKey(
      message,
      signature,
      signatureRecovery,
    );
    if (recoveredPublicKey === undefined) {
      this.logger.debug(
        `${baseError}: failed to recover Pk from the signature and message`,
      );
      return false;
    }

    if (recoveredPublicKey !== signerPublicKey) {
      this.logger.debug(
        `${baseError}: recovered Pk and signer Pk are not equal [${recoveredPublicKey} != ${signerPublicKey}]`,
      );
      return false;
    }
    this.logger.trace(
      `signature [${signature}] with recovery [${signatureRecovery}] is verified on message [${message}] and public key [${signerPublicKey}]`,
    );
    return true;
  };
}
