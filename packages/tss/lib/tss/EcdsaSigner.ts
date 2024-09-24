import { ECDSA } from '@rosen-bridge/encryption';
import { EcdsaConfig, Sign, SignResult } from '../types/signer';
import { TssSigner } from './TssSigner';

export class EcdsaSigner extends TssSigner {
  constructor(config: EcdsaConfig) {
    super({
      logger: config.logger,
      guardsPk: config.guardsPk,
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
      signer: new ECDSA(config.secret),
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
}
