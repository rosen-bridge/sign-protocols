import type * as wasm from 'ergo-lib-wasm-nodejs';

import { GuardDetection } from '@rosen-bridge/detection';

import { MultiSigHandler, TxQueued } from '../lib';

/**
 * Test-only MultiSigHandler adapter that exposes the private boundaries needed
 * by contribution-validation fixtures without changing production visibility.
 */
export class TestMultiSigHandler extends MultiSigHandler {
  /** Expose the inherited transport method to the typed method spy. */
  declare sendMessage: (
    messageType: string,
    payload: unknown,
    peers: string[],
    timestamp?: number,
    beforeSubmit?: () => undefined,
  ) => Promise<void>;

  /** Install the native wallet whose contribution calls are observed. */
  installProver = (prover: wasm.Wallet): void => {
    Object.assign(this, { prover });
  };

  /** Return the handler's guard-detection dependency for response mocking. */
  getGuardDetection = (): GuardDetection =>
    Reflect.get(this, 'guardDetection') as GuardDetection;

  /** Mark one queue entry as permanently refused by contribution validation. */
  markContributionFailed = (transaction: TxQueued): void => {
    (Reflect.get(this, 'failedContributions') as WeakSet<TxQueued>).add(
      transaction,
    );
  };

  /** Replace a queued entry while retaining the original transaction object. */
  replaceQueuedTransaction = (txId: string, transaction: TxQueued): void => {
    (Reflect.get(this, 'transactions') as Map<string, TxQueued>).set(txId, {
      ...transaction,
    });
  };

  /** Invoke the private round-state reset used by replacement fixtures. */
  cleanQueuedTransaction = (transaction: TxQueued): void => {
    const cleanTxState = Reflect.get(this, 'cleanTxState') as (
      queued: TxQueued,
    ) => void;
    cleanTxState.call(this, transaction);
  };

  /** Reverse communication keys in place to model an unannounced mutation. */
  reverseCommunicationKeys = (): void => {
    (Reflect.get(this, 'guardPks') as string[]).reverse();
  };
}
