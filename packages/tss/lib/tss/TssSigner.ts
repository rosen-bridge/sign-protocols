import { Communicator } from '@rosen-bridge/communication';
import {
  PublicKeyID,
  GetPublicKeyResponse,
  PendingSign,
  Sign,
  SignApprovePayload,
  SignCachedPayload,
  SignerBaseConfig,
  SignMessageType,
  SignRequestPayload,
  SignResult,
  SignStartPayload,
  StatusEnum,
  Threshold,
} from '../types/signer';
import { GuardDetection, ActiveGuard } from '@rosen-bridge/detection';
import {
  defaultThresholdTTL,
  defaultTimeoutDefault,
  signTurnDurationDefault,
  signTurnNoWorkDefault,
} from '../const/const';
import {
  approveMessage,
  cachedMessage,
  getPkUrl,
  requestMessage,
  signUrl,
  startMessage,
  thresholdUrl,
} from '../const/signer';
import { DummyLogger } from '@rosen-bridge/abstract-logger';
import { Mutex } from 'await-semaphore';
import axios, { AxiosInstance, AxiosResponse } from 'axios';

export abstract class TssSigner extends Communicator {
  protected readonly axios: AxiosInstance;
  protected readonly callbackUrl: string;
  protected readonly signingCrypto: string;
  protected threshold: Threshold;
  protected readonly thresholdTTL: number;
  protected readonly turnDuration: number;
  protected readonly turnNoWork: number;
  protected readonly timeout: number;
  protected readonly responseDelay: number;
  protected lastUpdateRound: number;
  protected signs: Array<Sign>;
  protected signCache: Record<string, SignResult>;
  protected pendingSigns: Array<PendingSign>;
  protected readonly detection: GuardDetection;
  protected readonly getPeerId: () => Promise<string>;
  protected readonly pendingAccessMutex: Mutex;
  protected readonly signAccessMutex: Mutex;
  protected readonly shares: Array<string>;
  protected readonly signPerRoundLimit: number;
  protected readonly signCacheTTLSeconds: number;

  /**
   * get threshold value from tss-api instance if threshold didn't set or expired and set for this and detection
   * this function calls on every update
   */
  protected updateThreshold = async () => {
    try {
      if (this.threshold.expiry < Date.now()) {
        const res = await this.axios.get<{ threshold: number }>(thresholdUrl, {
          params: { crypto: this.signingCrypto },
        });
        const threshold = res.data.threshold + 1;
        this.detection.setNeedGuardThreshold(threshold);
        this.threshold = {
          expiry: Date.now() + this.thresholdTTL,
          value: threshold,
        };
      }
    } catch (error) {
      this.logger.warn(
        `an error occurred when try getting threshold from tss ${error}`,
      );
      if (error instanceof Error && error.stack) {
        this.logger.warn(error.stack);
      }
    }
  };

  constructor(config: SignerBaseConfig) {
    super(
      config.logger ? config.logger : new DummyLogger(),
      config.messageEnc,
      config.submitMsg,
      config.guardsPk,
      config.messageValidDuration,
    );
    this.axios = axios.create({
      baseURL: config.tssApiUrl,
    });
    this.signingCrypto = config.signingCrypto;
    this.callbackUrl = config.callbackUrl;
    this.detection = config.detection;
    this.turnDuration = config.turnDurationSeconds
      ? config.turnDurationSeconds
      : signTurnDurationDefault;
    this.turnNoWork = config.turnNoWorkSeconds
      ? config.turnNoWorkSeconds
      : signTurnNoWorkDefault;
    this.threshold = {
      expiry: 0,
      value: -1,
    };
    this.lastUpdateRound = 0;
    this.timeout = config.timeoutSeconds
      ? config.timeoutSeconds
      : defaultTimeoutDefault;
    this.thresholdTTL = config.thresholdTTL
      ? config.thresholdTTL
      : defaultThresholdTTL;
    this.getPeerId = config.getPeerId;
    this.shares = config.shares;
    this.signs = [];
    this.signCache = {};
    this.pendingSigns = [];
    this.pendingAccessMutex = new Mutex();
    this.signAccessMutex = new Mutex();
    this.responseDelay = config.responseDelay ?? 5;
    this.signPerRoundLimit = config.signPerRoundLimit ?? 2;
    this.signCacheTTLSeconds = config.signCacheTTLSeconds ?? 7_200;
  }

  /**
   * cleanup all timed out signatures
   */
  protected cleanup = async () => {
    this.logger.debug('try cleaning timed out signs');
    const timeout = this.getDate() - this.timeout;
    const turn = this.getGuardTurn();
    const releaseSign = await this.signAccessMutex.acquire();
    this.signs = this.signs.filter((sign) => sign.addedTime > timeout);
    releaseSign();
    const releasePending = await this.pendingAccessMutex.acquire();
    this.pendingSigns = this.pendingSigns.filter(
      (pending) => pending.index === turn,
    );
    releasePending();
  };

  /**
   * cache a signature
   * @param message
   * @param signResult
   */
  protected addSignToCache = (message: string, signResult: SignResult) => {
    if (Object.hasOwn(this.signCache, message)) {
      this.logger.debug(
        `Got signature [${signResult.signature}.${signResult.signatureRecovery}] to cache but message [${message}] has already a signature: ${this.signCache[message].signature}.${this.signCache[message].signatureRecovery}`,
      );
      return;
    }
    this.signCache[message] = signResult;
    setTimeout(() => {
      delete this.signCache[message];
    }, this.signCacheTTLSeconds * 1000);
  };

  /**
   * update signing process for all signatures.
   * check if this guards turn
   * and founded guards are enough
   * run start message for all signs
   */
  update = async () => {
    await this.cleanup();
    const myIndex = await this.getIndex();
    const currentGuardIndex = this.getGuardTurn();
    if (myIndex !== currentGuardIndex) {
      this.logger.debug(`not my turn [${myIndex} != ${currentGuardIndex}]`);
      return;
    }
    if (this.signs.length === 0) {
      this.logger.debug('nothing to sign');
      return;
    }
    await this.updateThreshold();
    const activeGuards = await this.detection.activeGuards();
    if (activeGuards.length < this.threshold.value) {
      this.logger.debug(
        `not enough guards [${activeGuards.length} < ${this.threshold.value}]`,
      );
      return;
    }
    const timestamp = this.getDate();
    const round = Math.floor(timestamp / this.turnDuration);
    if (round !== this.lastUpdateRound) {
      this.lastUpdateRound = round;
      this.logger.debug('processing signs to start');
      for (const sign of this.signs.slice(0, this.signPerRoundLimit)) {
        if (sign.posted) continue;
        this.logger.debug(`new sign found with [${sign.msg}]`);
        const payload: SignRequestPayload = {
          msg: sign.msg,
          guards: activeGuards,
        };
        await this.sendMessage(requestMessage, payload, [], timestamp);
        const release = await this.signAccessMutex.acquire();
        sign.request = {
          guards: [...activeGuards],
          index: await this.getIndex(),
          timestamp,
        };
        sign.signs = Array(this.guardPks.length).fill('');
        sign.signs[await this.getIndex()] = await this.signPayload(
          {
            msg: sign.msg,
            guards: activeGuards,
            initGuardIndex: await this.getIndex(),
          },
          timestamp,
        );
        release();
      }
    }
  };

  /**
   * check if this guard turn
   */
  getGuardTurn = () => {
    const currentTime = this.getDate();
    return Math.floor(currentTime / this.turnDuration) % this.guardPks.length;
  };

  /**
   * check if we are in last seconds of round or not
   */
  protected isNoWorkTime = () => {
    const currentTime = this.getDate();
    const round = Math.floor(currentTime / this.turnDuration);
    return (round + 1) * this.turnDuration - currentTime <= this.turnNoWork;
  };

  /**
   * add new sign to queue
   * if other guards proceed this sign we also process it
   * @param msg
   * @param callback
   * @param chainCode
   * @param derivationPath
   */
  protected sign = async (
    msg: string,
    callback: (
      status: boolean,
      message?: string,
      signature?: string,
      signatureRecovery?: string,
    ) => unknown,
    chainCode: string,
    derivationPath?: number[],
  ) => {
    if (this.getSign(msg, true)) {
      throw Error('already signing this message');
    }

    if (Object.hasOwn(this.signCache, msg)) {
      const signResult = this.signCache[msg]!;

      this.logger.info(
        `Using cached signature [${signResult.signature}.${signResult.signatureRecovery}] for message [${msg}]`,
      );

      callback(
        true,
        undefined,
        signResult.signature,
        signResult.signatureRecovery,
      );
      return;
    }

    const release = await this.signAccessMutex.acquire();
    this.logger.info(`adding new message [${msg}] to signing queue`);
    this.signs.push({
      msg,
      callback,
      signs: [],
      addedTime: this.getDate(),
      posted: false,
      chainCode,
      derivationPath,
    });
    release();

    const pending = this.getPendingSign(msg);
    if (pending) {
      this.logger.info(
        `processing pending request for [${msg}] from other guards`,
      );
      await this.handleRequestMessage(
        { msg: msg, guards: pending.guards },
        pending.sender,
        pending.index,
        pending.timestamp,
      );
    }
  };

  /**
   * sign message and return promise
   * @param message
   * @param chainCode
   * @param derivationPath
   */
  abstract signPromised: (
    message: string,
    chainCode: string,
    derivationPath?: number[],
  ) => Promise<SignResult>;

  /**
   * process new message
   * @param messageType
   * @param payload
   * @param sign
   * @param senderIndex
   * @param peerId
   * @param timestamp
   */
  processMessage = (
    messageType: string,
    payload: unknown,
    sign: string,
    senderIndex: number,
    peerId: string,
    timestamp: number,
  ) => {
    switch (messageType as SignMessageType) {
      case requestMessage:
        return this.handleRequestMessage(
          payload as SignRequestPayload,
          peerId,
          senderIndex,
          timestamp,
        );
      case approveMessage:
        return this.handleApproveMessage(
          payload as SignApprovePayload,
          peerId,
          senderIndex,
          sign,
        );
      case cachedMessage:
        return this.handleSignCachedMessage(
          payload as SignCachedPayload,
          peerId,
        );
      case startMessage:
        return this.handleStartMessage(
          payload as SignStartPayload,
          timestamp,
          senderIndex,
          peerId,
        );
    }
    this.logger.warn(`invalid message type [${messageType}] arrived`);
  };

  /**
   * get a list of guards and return unknown guards info from selected list
   * @param guards
   */
  protected getUnknownGuards = async (guards: Array<ActiveGuard>) => {
    const myActiveGuards = await this.detection.activeGuards();
    return guards.filter((guard) => {
      return (
        myActiveGuards.filter((item) => item.publicKey === guard.publicKey)
          .length === 0
      );
    });
  };

  /**
   * get a list of guards and return a list of invalid guards
   * one guard is invalid if p2pId of detected guard differ from selected guard in list
   * @param guards
   */
  protected getInvalidGuards = async (guards: Array<ActiveGuard>) => {
    const myActiveGuards = await this.detection.activeGuards();
    return guards.filter((guard) => {
      return (
        myActiveGuards.filter(
          (item) =>
            item.publicKey === guard.publicKey && item.peerId !== guard.peerId,
        ).length > 0
      );
    });
  };

  /**
   * handle sign request message. verify guard turn and message
   * then return approve message
   * @param payload
   * @param sender
   * @param guardIndex
   * @param timestamp
   * @param sendRegister
   */
  protected handleRequestMessage = async (
    payload: SignRequestPayload,
    sender: string,
    guardIndex: number,
    timestamp: number,
    sendRegister = true,
  ) => {
    if (this.getGuardTurn() !== guardIndex) {
      if (sendRegister)
        this.logger.warn(
          `Got a request to sign message from [${sender}] but its not his turn`,
        );
      return;
    }
    if ((await this.getInvalidGuards(payload.guards)).length > 0) {
      if (sendRegister)
        this.logger.warn(`Invalid guard set passed to sign from [${sender}]`);
      return;
    }

    // check signCache
    if (Object.hasOwn(this.signCache, payload.msg)) {
      this.logger.info(
        `signing request for message [${
          payload.msg
        }] arrived and result exist in cache. sending cache signature [${
          this.signCache[payload.msg].signature
        }.${this.signCache[payload.msg].signatureRecovery}]...`,
      );

      // respond with sign cached message
      const responsePayload: SignCachedPayload = {
        msg: payload.msg,
        signature: this.signCache[payload.msg].signature,
        signatureRecovery: this.signCache[payload.msg].signatureRecovery,
      };
      return this.sendMessage(
        cachedMessage,
        responsePayload,
        [sender],
        timestamp,
      );
    }

    const sign = this.getSign(payload.msg);
    if (sign) {
      const unknown = await this.getUnknownGuards(payload.guards);
      this.logger.debug(
        `unknown guards found in signing request ${JSON.stringify(unknown)}`,
      );
      if (sendRegister) {
        for (const guard of unknown) {
          await this.detection.register(
            guard.peerId,
            guard.publicKey,
            (status, message) => {
              if (status) {
                this.handleRequestMessage(
                  payload,
                  sender,
                  guardIndex,
                  timestamp,
                  false,
                );
              } else {
                this.logger.warn(
                  `Can not register guard [${guard.publicKey}] with peer Id [${guard.peerId}]: ${message}`,
                );
              }
            },
          );
        }
      }

      if (unknown.length === 0) {
        this.logger.info(
          `signing request for message [${sign.msg}] approved. sending approval message`,
        );
        const responsePayload: SignApprovePayload = {
          msg: payload.msg,
          guards: payload.guards,
          initGuardIndex: guardIndex,
        };
        await this.sendMessage(
          approveMessage,
          responsePayload,
          [sender],
          timestamp,
        );
      }
    } else {
      this.logger.info(
        `new signing message arrived [${payload.msg}] but not in signing queue yet. store it for future use`,
      );
      const pending = this.getPendingSign(payload.msg);
      const release = await this.pendingAccessMutex.acquire();
      if (pending) {
        pending.guards = payload.guards;
        pending.index = guardIndex;
        pending.timestamp = timestamp;
        pending.sender = sender;
      } else {
        this.pendingSigns.push({
          msg: payload.msg,
          index: guardIndex,
          guards: payload.guards,
          timestamp,
          sender,
        });
      }
      release();
    }
  };

  /**
   * find a signing message in sign queue.
   * @param msg
   * @param searchPosted: if true search all element.
   *    otherwise only search in element which does not post to tss backend
   */
  protected getSign = (msg: string, searchPosted = false) => {
    const filtered = this.signs.filter((item) => item.msg === msg);
    if (filtered.length === 0) {
      return undefined;
    }
    if (!filtered[0].posted || searchPosted) {
      return filtered[0];
    }
    return undefined;
  };

  /**
   * remove a signing message in sign queue.
   * @param msg
   */
  protected removeSign = (msg: string) => {
    return this.signAccessMutex.acquire().then((release) => {
      this.signs = this.signs.filter((item) => item.msg !== msg);
      release();
    });
  };

  /**
   * get a message in list of pending signature.
   * @param msg
   */
  protected getPendingSign = (msg: string) => {
    const filtered = this.pendingSigns.filter((item) => item.msg === msg);
    if (filtered.length === 0) {
      return undefined;
    }
    return filtered[0];
  };

  /**
   * handle signing approve message.
   * collect signatures and if required count of signatures are arrived start signing process
   * ignore signing process if in NoWorkTime
   * @param payload
   * @param sender
   * @param guardIndex
   * @param signature
   */
  protected handleApproveMessage = async (
    payload: SignApprovePayload,
    sender: string,
    guardIndex: number,
    signature: string,
  ) => {
    const sign = this.getSign(payload.msg);
    if (!sign) {
      this.logger.warn(
        `approve message arrived but signing message not found [${payload.msg}]`,
      );
      return;
    }
    const myPk = await this.messageEnc.getPk();

    if (sign.request && !this.isNoWorkTime()) {
      return await this.signAccessMutex.acquire().then(async (release) => {
        try {
          sign.signs[guardIndex] = signature;
          const approvedGuards = await this.getApprovedGuards(
            sign.request!.timestamp,
            {
              msg: sign.msg,
              guards: sign.request!.guards,
              initGuardIndex: await this.getIndex(),
            },
            sign.signs,
          );
          if (approvedGuards.length >= this.threshold.value) {
            if (this.getSign(payload.msg)) {
              const payload: SignStartPayload = {
                msg: sign.msg,
                signs: sign.signs,
                guards: sign.request!.guards,
              };
              await this.sendMessage(
                startMessage,
                payload,
                approvedGuards
                  .filter((item) => item.publicKey !== myPk)
                  .map((item) => item.peerId),
                sign.request!.timestamp,
              );
              await this.startSign(sign.msg, approvedGuards);
            }
          } else {
            this.logger.debug(
              `[${approvedGuards.length}] out of required [${this.threshold.value}] guards approved message [${sign.msg}]. Signs are: ${sign.signs}`,
            );
          }
        } catch (e) {
          this.logger.warn(
            `an error occurred while handling approve message: ${e}`,
          );
        }
        release();
      });
    } else {
      this.logger.debug(
        'new message arrived but current guard is in no-work-period',
      );
    }
  };

  /**
   * handle sign cached message
   * store the signature in local cache
   * and call the callback
   * @param payload
   * @param sender
   */
  protected handleSignCachedMessage = async (
    payload: SignCachedPayload,
    sender: string,
  ) => {
    const sign = this.getSign(payload.msg);
    if (!sign) {
      this.logger.debug(
        `handleSignCachedMessage: signing message not found [${payload.msg}]`,
      );
      return;
    }

    const signVerified = await this.getPkAndVerifySignature(
      sign.msg,
      payload.signature,
      sign.chainCode,
      sign.derivationPath,
    );

    if (signVerified === false) {
      this.logger.warn(
        `handleSignCachedMessage: failed to verify signature [${payload.signature}] with msg [${sign.msg}] and peerId [${sender}]`,
      );
      return;
    }

    this.logger.debug(
      `handleSignCachedMessage: signature is valid [${payload.signature}] with msg [${sign.msg}]`,
    );

    await this.wrappedHandleSuccessfulSign(
      sign,
      payload.signature,
      payload.signatureRecovery,
    );

    return this.removeSign(payload.msg);
  };

  /**
   * handle start sign message.
   * process all signatures in message and if all verified start signing process with selected list of guards
   * @param payload
   * @param timestamp
   * @param guardIndex
   * @param sender
   */
  protected handleStartMessage = async (
    payload: SignStartPayload,
    timestamp: number,
    guardIndex: number,
    sender: string,
  ) => {
    const sign = this.getSign(payload.msg);
    if (!sign) {
      this.logger.warn(
        `start sign message arrived but signing message not found [${payload.msg}]`,
      );
      return;
    }
    if (this.getGuardTurn() !== guardIndex) {
      this.logger.warn(
        `Got a request to sign message from [${sender}] but its not his turn`,
      );
      return;
    }
    const payloadToSign: SignApprovePayload = {
      msg: payload.msg,
      guards: payload.guards,
      initGuardIndex: guardIndex,
    };
    const myPk = await this.messageEnc.getPk();
    if (payload.guards.filter((item) => item.publicKey === myPk).length == 0) {
      this.logger.warn(
        `Got a request to sign message from [${sender}] but I'm not involved`,
      );
      return;
    }
    const approvedGuards = await this.getApprovedGuards(
      timestamp,
      payloadToSign,
      payload.signs,
    );
    if (approvedGuards.length >= this.threshold.value) {
      await this.signAccessMutex.acquire().then(async (release) => {
        await this.startSign(sign.msg, approvedGuards);
        release();
      });
    }
  };

  /**
   * process list of selected guards and list of signs
   * then return list of all approved guards
   * @param timestamp
   * @param payload
   * @param signs
   */
  protected getApprovedGuards = async (
    timestamp: number,
    payload: SignApprovePayload,
    signs: Array<string>,
  ): Promise<Array<ActiveGuard>> => {
    return (
      await Promise.all(
        payload.guards.map(async (guard) => {
          const index = this.guardPks.indexOf(guard.publicKey);
          if (index === -1) return undefined;
          const sign = signs[index];
          if (sign === '') return undefined;
          const verifiedSign = await this.messageEnc.verify(
            TssSigner.generatePayloadToSign(
              payload,
              timestamp,
              guard.publicKey,
            ),
            sign,
            guard.publicKey,
          );
          return verifiedSign ? guard : undefined;
        }),
      )
    ).filter((item) => item !== undefined) as Array<ActiveGuard>;
  };

  /**
   * start signing process for specific message
   * @param message
   * @param guards
   */
  startSign = (message: string, guards: Array<ActiveGuard>) => {
    const sign = this.getSign(message);
    if (sign) {
      sign.posted = true;
      const remainingTime = this.timeout - (this.getDate() - sign.addedTime);
      const data = {
        peers: guards.map((item) => ({
          shareID: this.shares[this.guardPks.indexOf(item.publicKey)],
          p2pID: item.peerId,
        })),
        message: message,
        crypto: this.signingCrypto,
        operationTimeout: remainingTime - this.responseDelay,
        callBackUrl: this.callbackUrl,
        chainCode: sign.chainCode,
        derivationPath: sign.derivationPath,
      };
      this.logger.debug(
        `requesting tss-api to sign. data: ${JSON.stringify(data)}`,
      );
      return this.axios.post(signUrl, data).catch((err) => {
        this.logger.warn('Can not communicate with tss backend');
        this.logger.debug(err.stack);
        if (sign.callback) {
          this.signAccessMutex.acquire().then((release) => {
            sign.callback(false, err.status_code);
            this.signs = this.signs.filter((item) => item.msg !== sign.msg);
            release();
          });
        }
      });
    }
  };

  /**
   * request tss-api for a public-key using an identifier
   * @param id
   * @returns publicKey | undefined
   */
  protected getPk = async (id: PublicKeyID): Promise<string | undefined> => {
    this.logger.debug(
      `getPk requesting tss-api to get public key. crypto: ${this.signingCrypto}`,
    );
    try {
      // tss-api responds with http error if requested public key be unavailable
      const result: AxiosResponse<GetPublicKeyResponse> = await this.axios.post(
        getPkUrl,
        { ...id, crypto: this.signingCrypto },
      );
      this.logger.debug(
        `getPk done id: [${JSON.stringify(id)}] ${JSON.stringify(result.data)}`,
      );
      return result.data.publicKey;
    } catch (error) {
      this.logger.error(`getPk error from tss-api, ${JSON.stringify(error)}`);
    }
    return undefined;
  };

  /**
   * handle signing data callback for a message and process callback function
   * @param status
   * @param message
   * @param signature
   * @param signatureRecovery
   * @param error
   */
  handleSignData = async (
    status: StatusEnum,
    message: string,
    signature?: string,
    signatureRecovery?: string,
    error?: string,
  ) => {
    const sign = this.getSign(message, true);
    if (sign === undefined || !sign.posted) {
      throw Error('Invalid message');
    }
    if (status === StatusEnum.Success) {
      await this.wrappedHandleSuccessfulSign(
        sign,
        signature,
        signatureRecovery,
      );
    } else {
      sign.callback(false, error);
    }
    return this.removeSign(message);
  };

  /**
   * handles signing data callback in case of successful sign
   * @param sign
   * @param signature
   * @param signatureRecovery
   */
  abstract handleSuccessfulSign: (
    sign: Sign,
    signature?: string,
    signatureRecovery?: string,
  ) => Promise<void>;

  /**
   * a wrapper to cache sign result after handleSuccessfulSign
   * @param sign
   * @param signature
   * @param signatureRecovery
   */
  protected wrappedHandleSuccessfulSign = async (
    sign: Sign,
    signature?: string,
    signatureRecovery?: string,
  ) => {
    await this.handleSuccessfulSign(sign, signature, signatureRecovery);
    this.addSignToCache(sign.msg, {
      signature: signature!,
      signatureRecovery,
    });
  };

  /**
   * verify message signature
   * @param message
   * @param signature
   * @param chainCode
   * @param derivationPath
   */
  protected getPkAndVerifySignature = async (
    message: string,
    signature: string,
    chainCode: string,
    derivationPath?: number[],
  ): Promise<boolean> => {
    const pkId: PublicKeyID = {
      chainCode: chainCode,
      derivationPath: derivationPath ?? [],
    };

    const publicKey = await this.getPk(pkId);

    if (publicKey === undefined) {
      this.logger.error(
        `getPkAndVerifySignature: failed to get public key [${this.signingCrypto}] with chaincode [${chainCode}] and derivation path [${derivationPath}]`,
      );
      return false;
    }

    // TODO: also verify signatureRecovery. local:ergo/rosen-bridge/sign-protocols#31
    return await this.verify(message, signature, publicKey);
  };

  /**
   * verify message signature
   * @param message
   * @param signature
   * @param signerPublicKey
   */
  abstract verify: (
    message: string,
    signature: string,
    signerPublicKey: string,
  ) => Promise<boolean>;
}
