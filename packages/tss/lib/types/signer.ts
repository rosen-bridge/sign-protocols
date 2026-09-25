import { AbstractLogger } from '@rosen-bridge/abstract-logger';
import { GuardDetection, ActiveGuard } from '@rosen-bridge/detection';
import { EncryptionHandler } from '@rosen-bridge/encryption';

export interface SignerBaseConfig {
  logger?: AbstractLogger;
  guardsPk: Array<string>;
  signingCrypto: string;
  messageEnc: EncryptionHandler;
  submitMsg: (message: string, guards: Array<string>) => unknown;
  messageValidDuration?: number;
  timeoutSeconds?: number;
  tssApiUrl: string;
  callbackUrl: string;
  detection: GuardDetection;
  turnDurationSeconds?: number;
  turnNoWorkSeconds?: number;
  getPeerId: () => Promise<string>;
  shares: Array<string>;
  thresholdTTL?: number;
  responseDelay?: number;
  signPerRoundLimit?: number;
  signCacheTTLSeconds?: number;
}

export type SignerConfig = Omit<SignerBaseConfig, 'signingCrypto'>;

export interface Sign {
  bound?: BoundSignOperation;
  boundCallbackId?: string;
  boundFailed?: boolean;
  boundSettled?: boolean;
  boundDispatchAttempted?: boolean;
  boundBackendAttempted?: boolean;
  boundResultEmitted?: boolean;
  boundResultOnly?: boolean;
  boundSelection?: BoundSignSelection;
  boundResult?: SignResult;
  boundPendingResults?: Array<PendingBoundResult | undefined>;
  msg: string;
  callback: (
    status: boolean,
    message?: string,
    signature?: string,
    signatureRecovery?: string,
  ) => unknown;
  request?: {
    guards: Array<ActiveGuard>;
    index: number;
    timestamp: number;
  };
  signs: Array<string>;
  addedTime: number;
  posted: boolean;
  chainCode: string;
  derivationPath?: number[];
}

export interface BoundSignProfile {
  readonly schema: 1 | 2;
  readonly curve: 'secp256k1';
  readonly profileHash: string;
  readonly crypto: 'ecdsa';
  readonly protocolVersion: string;
  readonly guardPublicKeys: readonly string[];
  readonly shareIds: readonly string[];
  readonly chainCode: string;
  readonly derivationPath: readonly number[];
  readonly rawThreshold: number;
  readonly effectiveThreshold: number;
  readonly publicKey: string;
  readonly resultTransport?: BoundResultTransportCapability;
}

export interface BoundResultTransportCapability {
  readonly capability: 'bound-result-transport';
  readonly version: 1;
}

export interface BoundSignTranscript {
  readonly capability: 'bound-result-transport';
  readonly version: 1;
  readonly profileHash: string;
}

export interface BoundSignSelectionPayload {
  selectionHash: string;
  selectedGuards: Array<ActiveGuard>;
}

export interface BoundSignSelection {
  readonly selectionHash: string;
  readonly selectedGuards: readonly Readonly<ActiveGuard>[];
  readonly fullRoster: readonly Readonly<ActiveGuard>[];
}

export type BoundSignStage =
  | 'request'
  | 'approve'
  | 'start'
  | 'backend'
  | 'result';

export interface BoundSignHooks {
  authorize(profile: BoundSignProfile, stage: BoundSignStage): Promise<void>;
  assertCurrent(profile: BoundSignProfile, stage: BoundSignStage): void;
}

export interface BoundSignOperation {
  readonly profile: BoundSignProfile;
  readonly hooks: BoundSignHooks;
}

export interface PendingSign {
  msg: string;
  guards: Array<ActiveGuard>;
  bound?: BoundSignTranscript;
  index: number;
  timestamp: number;
  sender: string;
}
export interface SignRequestPayload {
  msg: string;
  guards: Array<ActiveGuard>;
  bound?: BoundSignTranscript;
}

export interface SignApprovePayload {
  msg: string;
  guards: Array<ActiveGuard>;
  initGuardIndex: number;
  bound?: BoundSignTranscript;
}

export interface SignCachedPayload {
  msg: string;
  signature: string;
  signatureRecovery: string | undefined;
}

export interface SignStartPayload {
  msg: string;
  guards: Array<ActiveGuard>;
  signs: Array<string>;
  bound?: BoundSignTranscript;
  selection?: BoundSignSelectionPayload;
}

export interface BoundSignResultPayload {
  msg: string;
  bound: BoundSignTranscript;
  selectionHash: string;
  signature: string;
  signatureRecovery: string;
}

export interface PendingBoundResult {
  readonly payload: BoundSignResultPayload;
  readonly senderIndex: number;
  readonly senderPeerId: string;
}

export interface PublicKeyID {
  chainCode: string;
  derivationPath: Array<number>;
}

export interface GetPublicKeyResponse {
  publicKey: string;
}

export type SignMessageType =
  | 'request'
  | 'approve'
  | 'cached'
  | 'start'
  | 'bound-result-v1';

export enum StatusEnum {
  Success = 'success',
  Failed = 'failed',
}

export interface Threshold {
  value: number;
  expiry: number;
}

export interface SignResult {
  signature: string;
  signatureRecovery: string | undefined;
}
