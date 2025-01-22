import { AbstractLogger } from '@rosen-bridge/abstract-logger';
import { EncryptionHandler } from '@rosen-bridge/encryption';
import { randomBytes } from '@noble/hashes/utils';

export interface ActiveGuard {
  peerId: string;
  publicKey: string;
  index: number;
}

export interface GuardDetectionConfig {
  logger?: AbstractLogger;
  guardsPublicKey: string[];
  messageEnc: EncryptionHandler;
  submit: (msg: string, peers: Array<string>) => unknown;
  activeTimeoutSeconds?: number;
  heartbeatTimeoutSeconds?: number;
  messageValidDurationSeconds?: number;
  getPeerId: () => Promise<string>;
}

export interface GuardInfo {
  peerId: string;
  nonce: Array<Nonce>;
  lastUpdate: number; // timestamp
  publicKey: string;
  callback: Array<(value: boolean) => unknown>;
  index: number;
}

export class Nonce {
  bytes: string;
  timestamp: number;

  constructor() {
    this.bytes = Buffer.from(randomBytes(32)).toString('hex');
    this.timestamp = Date.now() / 1000;
  }
}

export interface DetectionRegisterPayload {
  nonce: string;
}

export interface DetectionApprovePayload {
  nonce?: string;
  receivedNonce: string;
}
export interface DetectionHeartbeatPayload {
  nonce: string;
}

export type DetectionMessageType = 'register' | 'approval' | 'heartbeat';
