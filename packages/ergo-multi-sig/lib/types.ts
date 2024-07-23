import * as wasm from 'ergo-lib-wasm-nodejs';
import { AbstractLogger } from '@rosen-bridge/abstract-logger';
import { MultiSigUtils } from './MultiSigUtils';

interface ApproveSigner {
  id: string;
  challenge: string;
}

interface Signer {
  id?: string;
  pub: string;
  unapproved: Array<ApproveSigner>;
}

interface SingleCommitmentJson {
  hint: string;
  pubkey: {
    op: string;
    h: string;
  };
  type: string;
  a: string;
  secret?: string;
  position: string;
}

interface SingleProofJson {
  hint: string,
  pubkey: {
    op: string,
    h: string,
  },
  challenge: string,
  proof: string,
  position: string
}

interface CommitmentJson {
  secretHints: { [index: string]: Array<SingleProofJson> };
  publicHints: { [index: string]: Array<SingleCommitmentJson> };
}

interface TxQueued {
  tx?: wasm.ReducedTransaction;
  boxes: Array<wasm.ErgoBox>;
  dataBoxes: Array<wasm.ErgoBox>;
  secret?: wasm.TransactionHintsBag;
  simulatedBag?: wasm.TransactionHintsBag;
  signs: Record<string, PublishedProof>
  commitments: Record<string, PublishedCommitment>
  commitmentSigns: Record<string, string>
  resolve?: (value: wasm.Transaction | PromiseLike<wasm.Transaction>) => void;
  reject?: (reason?: any) => void;
  createTime: number;
  requiredSigner: number;
}

interface GeneralPayload {
  index?: number;
  id?: string;
}

interface RegisterPayload extends GeneralPayload {
  nonce: string;
  myId: string;
}

interface ApprovePayload extends GeneralPayload {
  nonce: string;
  nonceToSign?: string;
  myId: string;
}

interface SingleCommitment {
  a: string;
  position: string;
}

interface SingleProof {
  proof: string;
  position: string;
}


interface PublishedCommitment {
  [index: string]: Array<SingleCommitment>;
}

interface PublishedProof {
  [index: string]: Array<SingleProof>;
}

interface CommitmentPayload extends GeneralPayload {
  txId: string;
  commitment: PublishedCommitment;
}

interface InitiateSignPayload extends GeneralPayload {
  txId: string;
  committedInds: Array<number>;
  cmts: Array<PublishedCommitment>;
  simulated: Array<PublishedCommitment>;
  simulatedProofs: Array<PublishedProof>;
}

interface SignPayload extends GeneralPayload {
  proof: PublishedProof;
  txId: string;
}

interface signedTxPayload extends GeneralPayload {
  txBytes: string;
}

type Payload =
  | RegisterPayload
  | ApprovePayload
  | CommitmentPayload
  | InitiateSignPayload
  | SignPayload
  | signedTxPayload;


interface CommunicationMessage {
  type: 'register' | 'approve' | 'commitment' | 'sign' | 'initiateSign' | 'signedTx';
  sign?: string;
  payload: Payload;
}

interface ErgoMultiSigConfig {
  logger?: AbstractLogger;
  multiSigUtilsInstance: MultiSigUtils;
  publicKeys: Array<string>;
  secretHex: string;
  txSignTimeout: number;
  multiSigFirstSignDelay?: number;
  submit: (msg: string, peers: Array<string>) => unknown;
  getPeerId: () => Promise<string>;
}

export {
  TxQueued,
  CommunicationMessage,
  RegisterPayload,
  CommitmentPayload,
  SignPayload,
  Signer,
  ApprovePayload,
  CommitmentJson,
  PublishedCommitment,
  SingleCommitment,
  ErgoMultiSigConfig,
  InitiateSignPayload,
  SingleProof,
  PublishedProof,
  signedTxPayload
};
