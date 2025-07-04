import {
  PendingSign,
  Sign,
  SignApprovePayload,
  SignCachedPayload,
  SignRequestPayload,
  SignResult,
  SignStartPayload,
  TssSigner,
} from '../../lib';
import { ActiveGuard } from '@rosen-bridge/detection';

export class TestTssSigner extends TssSigner {
  /**
   * get list of signs in current object
   */
  getSigns = () => this.signs as Array<Sign>;

  /**
   * get list of signatures in current object's cache
   */
  getSignCache = () => this.signCache as Record<string, SignResult>;

  /**
   * get list of pending signs in current object
   */
  getPendingSigns = () => this.pendingSigns as Array<PendingSign>;

  /**
   * calling protected function addSignToCache
   * @param message
   * @param signResult
   */
  callAddSignToCache = (message: string, signResult: SignResult) =>
    this.addSignToCache(message, signResult);

  /**
   * calling protected function getUnknownGuards
   * @param guards
   */
  mockedGetUnknownGuards = (guards: Array<ActiveGuard>) =>
    this.getUnknownGuards(guards);

  /**
   * calling protected function getInvalidGuards
   * @param guards
   */
  mockedGetInvalidGuards = (guards: Array<ActiveGuard>) =>
    this.getInvalidGuards(guards);

  /**
   * calling protected function getSign
   * @param msg
   */
  mockedGetSign = (msg: string) => this.getSign(msg);

  /**
   * calls protected function removeSign
   * @param msg
   */
  callRemoveSign = (msg: string) => this.removeSign(msg);

  /**
   * calling protected function isNoWorkTime
   */
  mockedIsNoWorkTime = () => this.isNoWorkTime();

  /**
   * calling protected function getPendingSign
   * @param msg
   */
  mockedGetPendingSign = (msg: string) => this.getPendingSign(msg);

  /**
   * calling protected function getApprovedGuards
   * @param timestamp
   * @param payload
   * @param signs
   */
  mockedGetApprovedGuards = (
    timestamp: number,
    payload: SignApprovePayload,
    signs: Array<string>,
  ) => this.getApprovedGuards(timestamp, payload, signs);

  /**
   * calling protected function handleRequestMessage
   * @param payload
   * @param sender
   * @param guardIndex
   * @param timestamp
   * @param sendRegister
   */
  mockedHandleRequestMessage = (
    payload: SignRequestPayload,
    sender: string,
    guardIndex: number,
    timestamp: number,
    sendRegister: boolean,
  ) =>
    this.handleRequestMessage(
      payload,
      sender,
      guardIndex,
      timestamp,
      sendRegister,
    );

  /**
   * calling protected function handleApproveMessage
   * @param payload
   * @param sender
   * @param guardIndex
   * @param signature
   */
  mockedHandleApproveMessage = (
    payload: SignApprovePayload,
    sender: string,
    guardIndex: number,
    signature: string,
  ) => this.handleApproveMessage(payload, sender, guardIndex, signature);

  /**
   * calling protected function handleSignCachedMessage
   * @param payload
   * @param sender
   */
  callHandleSignCachedMessage = (payload: SignCachedPayload, sender: string) =>
    this.handleSignCachedMessage(payload, sender);

  /**
   * calling protected function handleStartMessage
   * @param payload
   * @param timestamp
   * @param guardIndex
   * @param sender
   */
  mockedHandleStartMessage = (
    payload: SignStartPayload,
    timestamp: number,
    guardIndex: number,
    sender: string,
  ) => this.handleStartMessage(payload, timestamp, guardIndex, sender);

  /**
   * calling protected function updateThreshold
   */
  mockedUpdateThreshold = () => this.updateThreshold();

  /**
   * calls protected function sign
   * @param msg
   * @param callback
   * @param chainCode
   * @param derivationPath
   * @returns
   */
  callSign = async (
    msg: string,
    callback: (status: boolean, message?: string, args?: string) => unknown,
    chainCode: string,
    derivationPath?: number[],
  ) => this.sign(msg, callback, chainCode, derivationPath);

  /**
   * calls verify
   * @param message
   * @param signature
   * @param signerPublicKey
   */
  verify = async (
    message: string,
    signature: string,
    signerPublicKey: string,
  ) => true;

  /**
   * calls protected function getPkAndVerifySignature
   * @param message
   * @param signature
   * @param chainCode
   * @param derivationPath
   */
  callGetPkAndVerifySignature = async (
    message: string,
    signature: string,
    chainCode: string,
    derivationPath?: number[],
  ) =>
    this.getPkAndVerifySignature(message, signature, chainCode, derivationPath);

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
    if (signature) {
      sign.callback(true, undefined, signature, signatureRecovery);
    } else {
      throw Error('signature is required when sign is successful');
    }
  };

  /**
   * calls protected function wrappedHandleSuccessfulSign
   * @param sign
   * @param signature
   * @param signatureRecovery
   */
  callWrappedHandleSuccessfulSign = async (
    sign: Sign,
    signature?: string,
    signatureRecovery?: string,
  ) => this.wrappedHandleSuccessfulSign(sign, signature, signatureRecovery);

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
      this.sign(
        message,
        (
          status: boolean,
          message?: string,
          signature?: string,
          signatureRecovery?: string,
        ) => {
          if (status && signature)
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
}
