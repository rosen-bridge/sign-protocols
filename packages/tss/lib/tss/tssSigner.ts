import { createHash, randomUUID } from 'node:crypto';
import secp from 'secp256k1';

import { DummyLogger } from '@rosen-bridge/abstract-logger';
import { Communicator } from '@rosen-bridge/communication';
import { GuardDetection, ActiveGuard } from '@rosen-bridge/detection';
import { Mutex } from '@rosen-bridge/semaphore';
import axios, { Axios, AxiosResponse } from '@rosen-clients/rate-limited-axios';

import packageJson from '../../package.json' with { type: 'json' };
import {
  defaultThresholdTTL,
  defaultTimeoutDefault,
  signTurnDurationDefault,
  signTurnNoWorkDefault,
} from '../const/const';
import {
  approveMessage,
  boundResultMessage,
  cachedMessage,
  getPkUrl,
  requestMessage,
  signUrl,
  startMessage,
  thresholdUrl,
} from '../const/signer';
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
  BoundSignProfile,
  BoundSignOperation,
  BoundSignStage,
  BoundResultTransportCapability,
  BoundSignTranscript,
  BoundSignSelection,
  BoundSignResultPayload,
  PendingBoundResult,
} from '../types/signer';

export abstract class TssSigner extends Communicator {
  /**
   * version of the tss signing protocol's message envelope and semantics,
   * tied to this package's own version. shared by EcdsaSigner and
   * EddsaSigner, which only differ in signing crypto, not in the message
   * protocol itself.
   */
  protected readonly protocolVersion = packageJson.version;
  protected readonly axios: Axios;
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
  private readonly boundProfiles = new WeakSet<BoundSignProfile>();

  private isResultTransportProfile = (
    profile: BoundSignProfile,
  ): profile is BoundSignProfile & {
    schema: 2;
    resultTransport: BoundResultTransportCapability;
  } =>
    profile.schema === 2 &&
    profile.resultTransport?.capability === 'bound-result-transport' &&
    profile.resultTransport.version === 1;

  private boundTranscript = (
    profile: BoundSignProfile,
  ): BoundSignTranscript => {
    if (!this.isResultTransportProfile(profile))
      throw Error('Bound result transport is not enabled');
    return {
      capability: profile.resultTransport.capability,
      version: profile.resultTransport.version,
      profileHash: profile.profileHash,
    };
  };

  private hasExactKeys = (value: object, keys: string[]) =>
    Object.keys(value).sort().join(',') === [...keys].sort().join(',');

  private hasValidTranscript = (
    sign: Sign,
    transcript: BoundSignTranscript | undefined,
  ) => {
    const profile = sign.bound?.profile;
    return Boolean(
      profile &&
        this.isResultTransportProfile(profile) &&
        transcript &&
        typeof transcript === 'object' &&
        this.hasExactKeys(transcript, [
          'capability',
          'version',
          'profileHash',
        ]) &&
        transcript.capability === profile.resultTransport.capability &&
        transcript.version === profile.resultTransport.version &&
        transcript.profileHash === profile.profileHash,
    );
  };

  private withBoundTranscript = <
    T extends SignRequestPayload | SignApprovePayload | SignStartPayload,
  >(
    sign: Sign,
    payload: T,
  ): T => {
    if (!sign.bound || !this.isResultTransportProfile(sign.bound.profile))
      return payload;
    return {
      ...payload,
      bound: this.boundTranscript(sign.bound.profile),
    };
  };

  private normalizedGuards = (guards: readonly ActiveGuard[]) =>
    guards.map((guard) => ({
      publicKey: guard.publicKey,
      peerId: guard.peerId,
      index: guard.index,
    }));

  private isExactRoster = (
    profile: BoundSignProfile,
    guards: readonly ActiveGuard[],
  ) =>
    guards.length === profile.guardPublicKeys.length &&
    guards.every(
      (guard, index) =>
        guard.publicKey === profile.guardPublicKeys[index] &&
        guard.index === index &&
        typeof guard.peerId === 'string' &&
        guard.peerId.length > 0,
    ) &&
    new Set(guards.map((guard) => guard.publicKey)).size === guards.length &&
    new Set(guards.map((guard) => guard.peerId)).size === guards.length;

  private profileOrderedDetectedRoster = (
    profile: BoundSignProfile,
    detected: readonly ActiveGuard[],
  ): ActiveGuard[] | undefined => {
    if (detected.length !== profile.guardPublicKeys.length) return undefined;
    const byIndex = new Map<number, ActiveGuard>();
    for (const guard of detected) {
      if (
        !Number.isInteger(guard.index) ||
        guard.index < 0 ||
        guard.index >= profile.guardPublicKeys.length ||
        byIndex.has(guard.index) ||
        guard.publicKey !== profile.guardPublicKeys[guard.index] ||
        typeof guard.peerId !== 'string' ||
        guard.peerId.length === 0
      )
        return undefined;
      byIndex.set(
        guard.index,
        Object.freeze({
          publicKey: guard.publicKey,
          peerId: guard.peerId,
          index: guard.index,
        }),
      );
    }
    const ordered = profile.guardPublicKeys.map(
      (_, index) => byIndex.get(index)!,
    );
    return this.isExactRoster(profile, ordered) ? ordered : undefined;
  };

  private selectionHash = (
    sign: Sign,
    fullRoster: readonly ActiveGuard[],
    selectedGuards: readonly ActiveGuard[],
  ) =>
    createHash('sha256')
      .update(
        JSON.stringify({
          ...this.boundTranscript(sign.bound!.profile),
          msg: sign.msg,
          fullRoster: this.normalizedGuards(fullRoster),
          selectedGuards: this.normalizedGuards(selectedGuards),
        }),
        'utf8',
      )
      .digest('hex');

  private makeSelection = (
    sign: Sign,
    fullRoster: readonly ActiveGuard[],
    selectedGuards: readonly ActiveGuard[],
  ): BoundSignSelection =>
    Object.freeze({
      selectionHash: this.selectionHash(sign, fullRoster, selectedGuards),
      fullRoster: Object.freeze(
        this.normalizedGuards(fullRoster).map((guard) => Object.freeze(guard)),
      ),
      selectedGuards: Object.freeze(
        this.normalizedGuards(selectedGuards).map((guard) =>
          Object.freeze(guard),
        ),
      ),
    });

  private sameGuards = (
    left: readonly ActiveGuard[],
    right: readonly ActiveGuard[],
  ) =>
    JSON.stringify(this.normalizedGuards(left)) ===
    JSON.stringify(this.normalizedGuards(right));

  private installSelection = (
    sign: Sign,
    selection: BoundSignSelection,
    myPk: string,
  ) => {
    if (
      sign.boundSelection &&
      (sign.boundSelection.selectionHash !== selection.selectionHash ||
        !this.sameGuards(
          sign.boundSelection.selectedGuards,
          selection.selectedGuards,
        ))
    )
      throw Error('Conflicting bound signing selection');
    sign.boundSelection ??= selection;
    if (!selection.selectedGuards.some((guard) => guard.publicKey === myPk)) {
      sign.boundResultOnly = true;
      sign.posted = true;
    }
  };

  private failBoundSign = (sign: Sign, error: unknown) => {
    if (!sign.bound || sign.boundSettled) return;
    sign.boundPendingResults = undefined;
    sign.boundFailed = true;
    sign.posted = true;
    sign.boundSettled = true;
    sign.callback(
      false,
      error instanceof Error ? error.message : String(error),
    );
  };

  private hasAcceptedBoundResult = (
    sign: Sign,
    payload: BoundSignResultPayload,
  ) => {
    if (!sign.boundResult) return false;
    if (
      sign.boundResult.signature !== payload.signature ||
      sign.boundResult.signatureRecovery !== payload.signatureRecovery
    )
      throw Error('Conflicting bound signing result');
    return true;
  };

  /** Returns only a result verified against this exact issued profile, never a signing cache hit. */
  getBoundResult = (
    message: string,
    profile: BoundSignProfile,
  ): SignResult | undefined => {
    if (!this.boundProfiles.has(profile))
      throw Error('Unknown bound signing profile');
    const sign = this.getSign(message, true);
    return sign?.bound?.profile === profile && sign.boundResult
      ? { ...sign.boundResult }
      : undefined;
  };

  private assertBoundLocal = (profile: BoundSignProfile) => {
    if (
      !this.boundProfiles.has(profile) ||
      this.signingCrypto !== profile.crypto ||
      this.protocolVersion !== profile.protocolVersion ||
      JSON.stringify(this.guardPks) !==
        JSON.stringify(profile.guardPublicKeys) ||
      JSON.stringify(this.shares) !== JSON.stringify(profile.shareIds) ||
      (profile.schema === 2) !== this.isResultTransportProfile(profile) ||
      (profile.schema === 1 && profile.resultTransport !== undefined)
    ) {
      throw Error('Bound signing profile changed');
    }
  };

  /** Captures a signer-issued profile; this does not authorize a payment. */
  prepareBoundProfile = async (
    chainCode: string,
    derivationPath: readonly number[],
    resultTransport?: BoundResultTransportCapability,
  ): Promise<BoundSignProfile> => {
    const guards = [...this.guardPks];
    const shares = [...this.shares];
    const path = [...derivationPath];
    if (
      this.signingCrypto !== 'ecdsa' ||
      // The backend uses the exact ASCII text as its HMAC key, without hex decoding.
      // Keep the existing 64-character operational ceiling, not a fixed key length.
      typeof chainCode !== 'string' ||
      !/^(?:[0-9a-f]{2}){1,32}$/.test(chainCode) ||
      path.some(
        (index) =>
          !Number.isSafeInteger(index) || index < 0 || index > 0xffffffff,
      ) ||
      guards.length === 0 ||
      guards.length !== shares.length ||
      new Set(guards).size !== guards.length ||
      new Set(shares).size !== shares.length ||
      [...guards, ...shares].some(
        (value) => typeof value !== 'string' || value.length === 0,
      )
    ) {
      throw Error('Invalid bound signing profile');
    }
    const rawThreshold = await this.readBoundThreshold(guards.length);
    const publicKey = await this.getPk({
      chainCode,
      derivationPath: [...path],
    });
    if (
      !publicKey ||
      !/^(02|03)[0-9a-f]{64}$/.test(publicKey) ||
      !secp.publicKeyVerify(Buffer.from(publicKey, 'hex'))
    )
      throw Error('Bound signing public key unavailable');
    if (
      resultTransport !== undefined &&
      (typeof resultTransport !== 'object' ||
        !this.hasExactKeys(resultTransport, ['capability', 'version']) ||
        resultTransport.capability !== 'bound-result-transport' ||
        resultTransport.version !== 1)
    )
      throw Error('Invalid bound result transport capability');
    const capturedTransport = resultTransport
      ? Object.freeze({
          capability: resultTransport.capability,
          version: resultTransport.version,
        })
      : undefined;
    const fields = {
      schema: capturedTransport ? (2 as const) : (1 as const),
      curve: 'secp256k1' as const,
      crypto: 'ecdsa' as const,
      protocolVersion: this.protocolVersion,
      guardPublicKeys: Object.freeze(guards),
      shareIds: Object.freeze(shares),
      chainCode,
      derivationPath: Object.freeze(path),
      rawThreshold,
      effectiveThreshold: rawThreshold + 1,
      publicKey,
      ...(capturedTransport
        ? { resultTransport: capturedTransport }
        : undefined),
    };
    // SHA-256 of UTF-8 JSON in this fixed field order, excluding profileHash.
    const profile: BoundSignProfile = Object.freeze({
      ...fields,
      profileHash: createHash('sha256')
        .update(JSON.stringify(fields), 'utf8')
        .digest('hex'),
    });
    this.boundProfiles.add(profile);
    this.assertBoundLocal(profile);
    return profile;
  };

  private readBoundThreshold = async (guardCount: number): Promise<number> => {
    const response = await this.axios.get<{ threshold: number }>(thresholdUrl, {
      params: { crypto: 'ecdsa' },
    });
    const raw = response.data.threshold;
    if (!Number.isSafeInteger(raw) || raw < 0 || raw >= guardCount)
      throw Error('Invalid bound signing threshold');
    return raw;
  };

  private boundGate = (sign: Sign, stage: BoundSignStage) => {
    const bound = sign.bound;
    if (!bound) return undefined;
    const { profile, hooks } = bound;
    return {
      authorize: async () => {
        try {
          if (sign.boundFailed) throw Error('Bound signing operation failed');
          this.assertBoundLocal(profile);
          const threshold = await this.readBoundThreshold(
            profile.guardPublicKeys.length,
          );
          const key = await this.getPk({
            chainCode: profile.chainCode,
            derivationPath: [...profile.derivationPath],
          });
          if (threshold !== profile.rawThreshold || key !== profile.publicKey)
            throw Error('Bound backend profile changed');
          await hooks.authorize(profile, stage);
        } catch (error) {
          if (stage === 'result' || !sign.boundBackendAttempted)
            this.failBoundSign(sign, error);
          throw error;
        }
      },
      assertCurrent: () => {
        try {
          if (sign.boundFailed) throw Error('Bound signing operation failed');
          hooks.assertCurrent(profile, stage);
          this.assertBoundLocal(profile);
          if (
            this.getSign(sign.msg, true) !== sign ||
            (stage === 'backend' &&
              (sign.posted || sign.boundResultOnly === true)) ||
            this.getDate() - sign.addedTime >= this.timeout
          ) {
            throw Error('Bound signing operation no longer dispatchable');
          }
          if (stage !== 'result') sign.boundDispatchAttempted = true;
        } catch (error) {
          if (stage === 'result' || !sign.boundBackendAttempted)
            this.failBoundSign(sign, error);
          throw error;
        }
      },
    };
  };

  private verifySignResult = (
    sign: Sign,
    signature: string,
    recovery?: string,
  ) =>
    sign.bound
      ? this.verify(sign.msg, signature, sign.bound.profile.publicKey, recovery)
      : this.getPkAndVerifySignature(
          sign.msg,
          signature,
          sign.chainCode,
          sign.derivationPath,
          recovery,
        );

  private sendSignMessage = (
    sign: Sign,
    stage: Exclude<BoundSignStage, 'backend' | 'result'>,
    payload: SignRequestPayload | SignApprovePayload | SignStartPayload,
    peers: string[],
    timestamp: number,
  ) => {
    if (sign.bound) {
      payload = JSON.parse(JSON.stringify(payload));
      if (
        this.isResultTransportProfile(sign.bound.profile) &&
        (!this.hasValidTranscript(sign, payload.bound) ||
          !this.isExactRoster(sign.bound.profile, payload.guards))
      )
        throw Error('Invalid bound result transport transcript');
      if (
        new Set(payload.guards.map((guard) => guard.publicKey)).size !==
          payload.guards.length ||
        new Set(payload.guards.map((guard) => guard.peerId)).size !==
          payload.guards.length ||
        payload.guards.some(
          (guard) =>
            sign.bound!.profile.guardPublicKeys.indexOf(guard.publicKey) !==
            guard.index,
        )
      ) {
        throw Error('Invalid bound signing participants');
      }
    }
    return this.sendMessage(
      stage,
      payload,
      peers,
      timestamp,
      this.boundGate(sign, stage),
    );
  };

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
    // Keep bound outcomes long enough to reject late protocol messages, then
    // retire the full operation rather than retaining its hooks forever.
    const boundRetireBefore =
      timeout - Math.max(this.messageValidDuration, this.signCacheTTLSeconds);
    const timedOutSigns = this.signs.filter(
      (sign) => !sign.bound && sign.addedTime <= timeout,
    );
    this.signs = this.signs.filter((sign) => {
      if (sign.bound) {
        if (sign.addedTime <= timeout)
          this.failBoundSign(sign, Error('Bound signing timed out'));
        return sign.addedTime > boundRetireBefore;
      }
      return sign.addedTime > timeout;
    });
    releaseSign();
    for (const sign of timedOutSigns) {
      this.logger.debug(
        `sign [${sign.msg}] timed out (posted: ${sign.posted}). notifying caller`,
      );
      sign.callback(false, 'Timed out');
    }
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
    if (
      !this.signs.some((sign) => sign.bound) &&
      activeGuards.length < this.threshold.value
    ) {
      this.logger.debug(
        `not enough guards [${activeGuards.length} < ${this.threshold.value}]`,
      );
      return;
    }
    const timestamp = this.getDate();
    const round = Math.floor(timestamp / this.turnDuration);
    if (round !== this.lastUpdateRound) {
      const eligible = this.signs
        .filter((sign) => !sign.bound || !sign.posted)
        .flatMap((sign) => {
          if (sign.posted) {
            this.logger.debug(
              `skipped signing message [${sign.msg}] due to being posted`,
            );
            return [];
          }
          if (
            sign.bound &&
            (sign.boundFailed ||
              sign.boundSettled ||
              sign.boundResult !== undefined ||
              sign.boundResultOnly)
          )
            return [];
          if (
            activeGuards.length <
            (sign.bound?.profile.effectiveThreshold ?? this.threshold.value)
          )
            return [];
          const resultTransport = Boolean(
            sign.bound && this.isResultTransportProfile(sign.bound.profile),
          );
          const requestGuards = resultTransport
            ? this.profileOrderedDetectedRoster(
                sign.bound!.profile,
                activeGuards,
              )
            : activeGuards;
          return requestGuards
            ? [{ sign, resultTransport, requestGuards }]
            : [];
        })
        .slice(0, this.signPerRoundLimit);
      if (eligible.length === 0) return;
      // Claim the round synchronously only after eligible work exists. Concurrent
      // update ticks then observe the claim before request preparation awaits.
      this.lastUpdateRound = round;
      this.logger.debug('processing signs to start');
      for (const { sign, resultTransport, requestGuards } of eligible) {
        this.logger.debug(`new sign found with [${sign.msg}]`);
        const payload: SignRequestPayload = this.withBoundTranscript(sign, {
          msg: sign.msg,
          guards: requestGuards,
        });
        if (resultTransport) {
          const release = await this.signAccessMutex.acquire();
          try {
            const index = await this.getIndex();
            sign.request = {
              guards: [...requestGuards],
              index,
              timestamp,
            };
            sign.signs = Array(this.guardPks.length).fill('');
            sign.signs[index] = await this.signPayload(
              this.withBoundTranscript(sign, {
                msg: sign.msg,
                guards: requestGuards,
                initGuardIndex: index,
              }),
              timestamp,
            );
          } finally {
            release();
          }
          try {
            await this.sendSignMessage(sign, 'request', payload, [], timestamp);
          } catch (error) {
            this.failBoundSign(sign, error);
            throw error;
          }
        } else {
          await this.sendSignMessage(sign, 'request', payload, [], timestamp);
          const release = await this.signAccessMutex.acquire();
          try {
            sign.request = {
              guards: [...activeGuards],
              index: await this.getIndex(),
              timestamp,
            };
            sign.signs = Array(this.guardPks.length).fill('');
            sign.signs[await this.getIndex()] = await this.signPayload(
              this.withBoundTranscript(sign, {
                msg: sign.msg,
                guards: activeGuards,
                initGuardIndex: await this.getIndex(),
              }),
              timestamp,
            );
          } finally {
            release();
          }
        }
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
    bound?: BoundSignOperation,
  ) => {
    if (bound) {
      if (!/^[0-9a-f]{64}$/.test(msg))
        throw Error('Bound signing requires a 32-byte digest');
      this.assertBoundLocal(bound.profile);
    }
    const joinExistingSign = () => {
      const signObject = this.getSign(msg, true);
      if (!signObject) return false;
      if (bound || signObject.bound)
        throw Error('already signing this message');
      this.logger.info(`Already signing message [${msg}]`);
      const oldCallback = signObject.callback;
      signObject.callback = (
        status: boolean,
        message?: string,
        signature?: string,
        signatureRecovery?: string,
      ) => {
        callback(status, message, signature, signatureRecovery);
        oldCallback(status, message, signature, signatureRecovery);
      };
      return true;
    };
    if (joinExistingSign()) return;

    if (!bound && Object.hasOwn(this.signCache, msg)) {
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
    try {
      if (joinExistingSign()) return;
      if (bound) delete this.signCache[msg];
      this.logger.info(`adding new message [${msg}] to signing queue`);
      this.signs.push({
        msg,
        callback,
        signs: [],
        addedTime: this.getDate(),
        posted: false,
        chainCode,
        derivationPath,
        bound,
      });
    } finally {
      release();
    }

    const pending = this.getPendingSign(msg);
    if (pending) {
      this.logger.info(
        `processing pending request for [${msg}] from other guards`,
      );
      await this.handleRequestMessage(
        {
          msg: msg,
          guards: pending.guards,
          ...(pending.bound === undefined ? {} : { bound: pending.bound }),
        },
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
   * check if message is in sign
   * @param message
   */
  isInSign = async (message: string): Promise<boolean> => {
    if (this.getSign(message, true)) {
      return true;
    }
    return false;
  };

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
      case boundResultMessage:
        return this.handleBoundResultMessage(
          payload as BoundSignResultPayload,
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
    const exactSign = this.getSign(payload.msg, true);
    if (exactSign?.bound) {
      if (this.isResultTransportProfile(exactSign.bound.profile)) {
        if (
          exactSign.boundSelection ||
          exactSign.boundResultOnly ||
          !this.hasValidTranscript(exactSign, payload.bound) ||
          !this.isExactRoster(exactSign.bound.profile, payload.guards)
        )
          return;
      } else if (payload.bound !== undefined) {
        return;
      }
    }
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
    if (
      !this.getSign(payload.msg, true)?.bound &&
      Object.hasOwn(this.signCache, payload.msg)
    ) {
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
        const responsePayload: SignApprovePayload = this.withBoundTranscript(
          sign,
          {
            msg: payload.msg,
            guards: payload.guards,
            initGuardIndex: guardIndex,
          },
        );
        await this.sendSignMessage(
          sign,
          'approve',
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
      const capturedGuards = payload.guards.map((guard) => ({ ...guard }));
      const capturedBound =
        payload.bound === undefined
          ? undefined
          : Object.freeze({ ...payload.bound });
      if (pending) {
        pending.guards = capturedGuards;
        pending.bound = capturedBound;
        pending.index = guardIndex;
        pending.timestamp = timestamp;
        pending.sender = sender;
      } else {
        this.pendingSigns.push({
          msg: payload.msg,
          index: guardIndex,
          guards: capturedGuards,
          bound: capturedBound,
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
      this.signs = this.signs.filter((item) => item.msg !== msg || item.bound);
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

    const request = sign.request;
    if (request && !this.isNoWorkTime()) {
      return await this.signAccessMutex.acquire().then(async (release) => {
        try {
          const resultTransport = Boolean(
            sign.bound && this.isResultTransportProfile(sign.bound.profile),
          );
          if (resultTransport) {
            const expectedSender = request.guards[guardIndex];
            if (
              !this.hasValidTranscript(sign, payload.bound) ||
              !this.sameGuards(payload.guards, request.guards) ||
              payload.initGuardIndex !== request.index ||
              expectedSender?.publicKey !==
                sign.bound!.profile.guardPublicKeys[guardIndex] ||
              expectedSender.peerId !== sender
            )
              return;
          } else if (payload.bound !== undefined) {
            return;
          }
          sign.signs[guardIndex] = signature;
          const approvedGuards = await this.getApprovedGuards(
            request.timestamp,
            this.withBoundTranscript(sign, {
              msg: sign.msg,
              guards: request.guards,
              initGuardIndex: await this.getIndex(),
            }),
            sign.signs,
            sign.bound?.profile,
          );
          if (
            approvedGuards.length >=
            (sign.bound?.profile.effectiveThreshold ?? this.threshold.value)
          ) {
            if (this.getSign(payload.msg)) {
              if (
                resultTransport &&
                approvedGuards.length !==
                  sign.bound!.profile.guardPublicKeys.length
              )
                return;
              const selectedGuards = resultTransport
                ? approvedGuards.slice(
                    0,
                    sign.bound!.profile.effectiveThreshold,
                  )
                : approvedGuards;
              const selection = resultTransport
                ? this.makeSelection(sign, request.guards, selectedGuards)
                : undefined;
              if (selection) this.installSelection(sign, selection, myPk);
              const startPayload: SignStartPayload = this.withBoundTranscript(
                sign,
                {
                  msg: sign.msg,
                  signs: [...sign.signs],
                  guards: [...request.guards],
                  ...(selection
                    ? {
                        selection: {
                          selectionHash: selection.selectionHash,
                          selectedGuards: this.normalizedGuards(
                            selection.selectedGuards,
                          ),
                        },
                      }
                    : undefined),
                },
              );
              await this.sendSignMessage(
                sign,
                'start',
                startPayload,
                (resultTransport ? request.guards : approvedGuards)
                  .filter((item) => item.publicKey !== myPk)
                  .map((item) => item.peerId),
                request.timestamp,
              );
              if (!sign.boundResultOnly)
                await this.startSign(sign.msg, selectedGuards);
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
          if (sign.bound && this.isResultTransportProfile(sign.bound.profile)) {
            this.failBoundSign(sign, e);
            throw e;
          }
        } finally {
          release();
        }
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
    if (sign?.bound) return;
    if (!sign) {
      this.logger.debug(
        `handleSignCachedMessage: signing message not found [${payload.msg}]`,
      );
      return;
    }

    const signVerified = await this.verifySignResult(
      sign,
      payload.signature,
      payload.signatureRecovery,
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
    if (sign.bound && this.isResultTransportProfile(sign.bound.profile)) {
      const profile = sign.bound.profile;
      const senderGuard = payload.guards[guardIndex];
      if (
        !this.hasValidTranscript(sign, payload.bound) ||
        !this.isExactRoster(profile, payload.guards) ||
        senderGuard?.peerId !== sender ||
        !payload.selection ||
        !this.hasExactKeys(payload.selection, [
          'selectionHash',
          'selectedGuards',
        ])
      )
        return;
      const payloadToSign: SignApprovePayload = {
        msg: payload.msg,
        guards: payload.guards,
        initGuardIndex: guardIndex,
        bound: payload.bound,
      };
      const approvedGuards = await this.getApprovedGuards(
        timestamp,
        payloadToSign,
        payload.signs,
        profile,
      );
      if (approvedGuards.length !== profile.guardPublicKeys.length) return;
      const expectedSelected = approvedGuards.slice(
        0,
        profile.effectiveThreshold,
      );
      const expected = this.makeSelection(
        sign,
        payload.guards,
        expectedSelected,
      );
      if (
        payload.selection.selectionHash !== expected.selectionHash ||
        !this.sameGuards(
          payload.selection.selectedGuards,
          expected.selectedGuards,
        )
      )
        return;
      const myPk = await this.messageEnc.getPk();
      this.installSelection(sign, expected, myPk);
      const pendingResults = sign.boundPendingResults?.filter(
        (item): item is PendingBoundResult => item !== undefined,
      );
      sign.boundPendingResults = undefined;
      if (sign.boundResultOnly) {
        for (const pending of pendingResults ?? []) {
          await this.handleBoundResultMessage(
            pending.payload,
            pending.senderIndex,
            pending.senderPeerId,
          );
          if (sign.boundSettled || sign.boundFailed) break;
        }
      } else {
        await this.signAccessMutex.acquire().then(async (release) => {
          try {
            await this.startSign(sign.msg, [...expected.selectedGuards]);
          } finally {
            release();
          }
        });
      }
      return;
    }
    if (payload.bound !== undefined || payload.selection !== undefined) return;
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
      sign.bound?.profile,
    );
    if (
      approvedGuards.length >=
      (sign.bound?.profile.effectiveThreshold ?? this.threshold.value)
    ) {
      await this.signAccessMutex.acquire().then(async (release) => {
        try {
          await this.startSign(sign.msg, approvedGuards);
        } finally {
          release();
        }
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
    profile?: BoundSignProfile,
  ): Promise<Array<ActiveGuard>> => {
    if (
      profile &&
      (new Set(payload.guards.map((guard) => guard.publicKey)).size !==
        payload.guards.length ||
        new Set(payload.guards.map((guard) => guard.peerId)).size !==
          payload.guards.length)
    ) {
      throw Error('Duplicate bound signing guards');
    }
    return (
      await Promise.all(
        payload.guards.map(async (guard) => {
          const index = (profile?.guardPublicKeys ?? this.guardPks).indexOf(
            guard.publicKey,
          );
          if (index === -1) return undefined;
          const sign = signs[index];
          if (sign === '') return undefined;
          const verifiedSign = await this.messageEnc.verify(
            TssSigner.generatePayloadToSign(
              payload,
              timestamp,
              guard.publicKey,
              profile?.protocolVersion ?? this.protocolVersion,
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
  startSign = async (message: string, guards: Array<ActiveGuard>) => {
    const sign = this.getSign(message);
    if (!sign && this.getSign(message, true)?.bound)
      throw Error('Bound signing operation no longer dispatchable');
    if (sign) {
      const profile = sign.bound?.profile;
      if (profile && this.isResultTransportProfile(profile)) {
        const myPk = await this.messageEnc.getPk();
        if (
          !sign.boundSelection ||
          sign.boundResultOnly ||
          !sign.boundSelection.selectedGuards.some(
            (guard) => guard.publicKey === myPk,
          ) ||
          !this.sameGuards(guards, sign.boundSelection.selectedGuards) ||
          guards.length !== profile.effectiveThreshold
        )
          throw Error('Bound result-only member cannot dispatch backend');
      }
      if (
        profile &&
        (guards.length < profile.effectiveThreshold ||
          new Set(guards.map((guard) => guard.publicKey)).size !==
            guards.length ||
          new Set(guards.map((guard) => guard.peerId)).size !== guards.length ||
          guards.some(
            (guard) => !profile.guardPublicKeys.includes(guard.publicKey),
          ))
      ) {
        throw Error('Invalid bound signing participants');
      }
      const remainingTime = this.timeout - (this.getDate() - sign.addedTime);
      if (sign.bound) sign.boundCallbackId ??= randomUUID();
      const data = {
        peers: guards.map((item) => ({
          shareID: (profile?.shareIds ?? this.shares)[
            (profile?.guardPublicKeys ?? this.guardPks).indexOf(item.publicKey)
          ],
          p2pID: item.peerId,
        })),
        message: message,
        crypto: this.signingCrypto,
        operationTimeout: remainingTime - this.responseDelay,
        callBackUrl: sign.bound
          ? `${this.callbackUrl}${this.callbackUrl.includes('?') ? '&' : '?'}boundOperationId=${sign.boundCallbackId}`
          : this.callbackUrl,
        chainCode: profile?.chainCode ?? sign.chainCode,
        derivationPath: profile
          ? [...profile.derivationPath]
          : sign.derivationPath,
      };
      this.logger.debug(
        `requesting tss-api to sign. data: ${JSON.stringify(data)}`,
      );
      const gate = this.boundGate(sign, 'backend');
      if (gate) {
        await gate.authorize();
        gate.assertCurrent();
      }
      sign.posted = true;
      if (sign.bound) sign.boundBackendAttempted = true;
      return this.axios.post(signUrl, data).catch((err) => {
        this.logger.warn('Can not communicate with tss backend');
        this.logger.debug(err.stack);
        if (sign.bound) {
          this.failBoundSign(sign, err);
          return;
        }
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
   * @returns the compressed public key, or undefined in case of failure
   */
  getPk = async (id: PublicKeyID): Promise<string | undefined> => {
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

  private sendBoundResult = async (
    sign: Sign,
    signature: string,
    signatureRecovery: string,
  ) => {
    const profile = sign.bound?.profile;
    const selection = sign.boundSelection;
    if (
      !profile ||
      !this.isResultTransportProfile(profile) ||
      !selection ||
      !sign.boundBackendAttempted ||
      sign.boundResultOnly
    )
      throw Error('Bound result producer is not selected');
    const myPk = await this.messageEnc.getPk();
    if (!selection.selectedGuards.some((guard) => guard.publicKey === myPk))
      throw Error('Bound result producer is not selected');
    const payload: BoundSignResultPayload = {
      msg: sign.msg,
      bound: this.boundTranscript(profile),
      selectionHash: selection.selectionHash,
      signature,
      signatureRecovery,
    };
    await this.sendMessage(
      boundResultMessage,
      payload,
      selection.fullRoster
        .filter((guard) => guard.publicKey !== myPk)
        .map((guard) => guard.peerId),
      undefined,
      this.boundGate(sign, 'result'),
    );
    sign.boundResultEmitted = true;
  };

  protected handleBoundResultMessage = async (
    payload: BoundSignResultPayload,
    senderIndex: number,
    senderPeerId: string,
  ) => {
    if (
      !payload ||
      typeof payload !== 'object' ||
      !this.hasExactKeys(payload, [
        'msg',
        'bound',
        'selectionHash',
        'signature',
        'signatureRecovery',
      ]) ||
      typeof payload.msg !== 'string' ||
      typeof payload.selectionHash !== 'string' ||
      typeof payload.signature !== 'string' ||
      typeof payload.signatureRecovery !== 'string'
    )
      return;
    const sign = this.getSign(payload.msg, true);
    const profile = sign?.bound?.profile;
    if (
      !sign ||
      !profile ||
      !this.isResultTransportProfile(profile) ||
      sign.boundFailed ||
      (sign.boundSettled && !sign.boundResult) ||
      !this.hasValidTranscript(sign, payload.bound) ||
      !/^[0-9a-f]{64}$/.test(payload.selectionHash) ||
      !/^[0-9a-f]{128}$/.test(payload.signature) ||
      !/^[0-9a-f]{2}$/.test(payload.signatureRecovery) ||
      !Number.isSafeInteger(senderIndex) ||
      senderIndex < 0 ||
      senderIndex >= profile.guardPublicKeys.length
    )
      return;
    let selection = sign.boundSelection;
    if (!selection) {
      if (this.getDate() - sign.addedTime >= this.timeout) {
        this.failBoundSign(sign, Error('Bound signing timed out'));
        return;
      }
      const release = await this.signAccessMutex.acquire();
      try {
        selection = sign.boundSelection;
        if (!selection) {
          if (sign.boundFailed || sign.boundSettled) return;
          sign.boundPendingResults ??= Array(
            profile.guardPublicKeys.length,
          ).fill(undefined);
          sign.boundPendingResults[senderIndex] = Object.freeze({
            payload: Object.freeze({
              ...payload,
              bound: Object.freeze({ ...payload.bound }),
            }),
            senderIndex,
            senderPeerId,
          });
          return;
        }
      } finally {
        release();
      }
    }
    if (
      !sign.boundResultOnly ||
      payload.selectionHash !== selection.selectionHash
    )
      return;
    const senderPk = profile.guardPublicKeys[senderIndex];
    const selectedSender = selection.selectedGuards.find(
      (guard) => guard.publicKey === senderPk,
    );
    if (!selectedSender || selectedSender.peerId !== senderPeerId) return;
    if (this.hasAcceptedBoundResult(sign, payload)) return;
    if (sign.boundSettled) return;
    const gate = this.boundGate(sign, 'result')!;
    try {
      await gate.authorize();
    } catch (error) {
      if (this.hasAcceptedBoundResult(sign, payload)) return;
      throw error;
    }
    if (this.hasAcceptedBoundResult(sign, payload)) return;
    try {
      gate.assertCurrent();
    } catch (error) {
      if (this.hasAcceptedBoundResult(sign, payload)) return;
      throw error;
    }
    let verified: boolean;
    try {
      verified = await this.verifySignResult(
        sign,
        payload.signature,
        payload.signatureRecovery,
      );
    } catch (error) {
      if (this.hasAcceptedBoundResult(sign, payload)) return;
      throw error;
    }
    if (this.hasAcceptedBoundResult(sign, payload)) return;
    try {
      gate.assertCurrent();
    } catch (error) {
      if (this.hasAcceptedBoundResult(sign, payload)) return;
      throw error;
    }
    if (!verified) return;
    const release = await this.signAccessMutex.acquire();
    try {
      if (this.hasAcceptedBoundResult(sign, payload)) return;
      if (sign.boundSettled || sign.boundFailed) return;
      gate.assertCurrent();
      sign.boundResult = Object.freeze({
        signature: payload.signature,
        signatureRecovery: payload.signatureRecovery,
      });
      sign.boundPendingResults = undefined;
      sign.boundSettled = true;
      await this.handleSuccessfulSign(
        sign,
        payload.signature,
        payload.signatureRecovery,
      );
    } finally {
      release();
    }
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
    boundOperationId?: string,
  ) => {
    const sign = this.getSign(message, true);
    if (sign === undefined || !sign.posted) {
      throw Error('Invalid message');
    }
    if (
      sign.bound
        ? !boundOperationId || sign.boundCallbackId !== boundOperationId
        : boundOperationId !== undefined
    )
      throw Error('Invalid callback operation');
    if (sign.bound && !sign.boundBackendAttempted)
      throw Error('Bound backend was not invoked');

    if (status === StatusEnum.Success) {
      if (!signature) {
        throw Error('signature is required when sign was successful');
      }

      const signVerified = await this.verifySignResult(
        sign,
        signature,
        signatureRecovery,
      );

      if (signVerified === false) {
        this.logger.warn(
          `verification of trusted signature [${signature}] with message [${sign.msg}] is failed`,
        );
        return;
      }

      await this.wrappedHandleSuccessfulSign(
        sign,
        signature,
        signatureRecovery,
      );
    } else {
      if (sign.bound) this.failBoundSign(sign, error);
      else sign.callback(false, error);
    }
    // Bound records are retired by cleanup. Removing by digest here could erase
    // a newer legacy operation queued while this callback awaited verification.
    if (!sign.bound) return this.removeSign(message);
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
    if (sign.bound) {
      const resultTransport = this.isResultTransportProfile(sign.bound.profile);
      if (sign.boundResult) {
        if (
          sign.boundResult.signature !== signature ||
          sign.boundResult.signatureRecovery !== signatureRecovery
        ) {
          throw Error('Conflicting bound signing result');
        }
        return;
      }
      if (resultTransport && !signatureRecovery)
        throw Error('Bound result transport requires signature recovery');
      sign.boundResult = Object.freeze({
        signature: signature!,
        signatureRecovery,
      });
      sign.boundPendingResults = undefined;
      sign.posted = true;
      if (resultTransport) {
        try {
          await this.sendBoundResult(sign, signature!, signatureRecovery!);
        } catch (error) {
          this.failBoundSign(sign, error);
          throw error;
        }
      }
      if (!sign.boundSettled) {
        sign.boundSettled = true;
        await this.handleSuccessfulSign(sign, signature, signatureRecovery);
      }
      return;
    }
    await this.handleSuccessfulSign(sign, signature, signatureRecovery);
    this.addSignToCache(sign.msg, {
      signature: signature!,
      signatureRecovery,
    });
  };

  /**
   * verify message signature, together with its signatureRecovery when provided
   * @param message
   * @param signature
   * @param chainCode
   * @param derivationPath
   * @param signatureRecovery
   */
  protected getPkAndVerifySignature = async (
    message: string,
    signature: string,
    chainCode: string,
    derivationPath?: number[],
    signatureRecovery?: string,
  ): Promise<boolean> => {
    const pkId: PublicKeyID = {
      chainCode: chainCode,
      derivationPath: derivationPath ?? [],
    };

    const publicKey = await this.getPk(pkId);

    if (publicKey === undefined) {
      this.logger.error(
        `failed to get public key [${this.signingCrypto}] with chaincode [${chainCode}] and derivation path [${derivationPath}]`,
      );
      return false;
    }

    return this.verify(message, signature, publicKey, signatureRecovery);
  };

  /**
   * verify message signature
   * @param message
   * @param signature
   * @param signerPublicKey
   * @param signatureRecovery when provided, implementations should also verify it recovers to signerPublicKey
   */
  abstract verify: (
    message: string,
    signature: string,
    signerPublicKey: string,
    signatureRecovery?: string,
  ) => Promise<boolean>;
}
