import { EncryptionHandler } from '@rosen-bridge/encryption';
import { AbstractLogger } from '@rosen-bridge/abstract-logger';
import { GuardDetection, ActiveGuard } from '@rosen-bridge/detection';

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

export interface PendingSign {
  msg: string;
  guards: Array<ActiveGuard>;
  index: number;
  timestamp: number;
  sender: string;
}
export interface SignRequestPayload {
  msg: string;
  guards: Array<ActiveGuard>;
}

export interface SignApprovePayload {
  msg: string;
  guards: Array<ActiveGuard>;
  initGuardIndex: number;
}

export interface SignCachedPayload {
  msg: string;
  guards: Array<ActiveGuard>;
  initGuardIndex: number;
  signature: string;
  signatureRecovery: string | undefined;
}

export interface SignStartPayload {
  msg: string;
  guards: Array<ActiveGuard>;
  signs: Array<string>;
}

export type SignMessageType = 'request' | 'approve' | 'cached' | 'start';

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
