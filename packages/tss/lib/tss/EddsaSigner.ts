import * as ed from '@noble/ed25519';
import { Sign, SignerConfig, SignResult } from '../types/signer';
import { TssSigner } from './TssSigner';

export class EddsaSigner extends TssSigner {
  constructor(config: SignerConfig) {
    super({
      logger: config.logger,
      guardsPk: config.guardsPk,
      signingCrypto: 'eddsa',
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
      if (derivationPath)
        throw Error(`derivationPath is not supported in EdDSA signing`);
      this.sign(
        message,
        (status: boolean, message?: string, signature?: string) => {
          if (status && signature)
            resolve({
              signature: signature,
              signatureRecovery: undefined,
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
  ): Promise<void> => {
    if (signature) {
      sign.callback(true, undefined, signature);
    } else {
      throw Error('signature is required when EdDSA sign is successful');
    }
  };

  /**
   * verify message signature
   * @param message
   * @param signature
   * @param signerPublicKey
   */
  verify = async (
    message: string,
    signature: string,
    signerPublicKey: string,
  ): Promise<boolean> => {
    return ed.verifyAsync(signature, message, signerPublicKey);
  };
}
