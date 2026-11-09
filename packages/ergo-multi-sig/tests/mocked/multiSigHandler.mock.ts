import * as wasm from 'ergo-lib-wasm-nodejs';
import { vi } from 'vitest';

import { GuardDetection } from '@rosen-bridge/detection';
import { ECDSA } from '@rosen-bridge/encryption';

import type { ContributionRequest } from '../../lib';
import { TestMultiSigHandler } from '../testMultiSigHandler';

/** Create the mocked outbound network sink used by handler fixtures. */
export const mockSubmit = () => vi.fn();

/** Create the mocked queue-rejection callback used by handler fixtures. */
export const mockTransactionReject = () => vi.fn();

/** Create a peer-ID response callback for GuardDetection construction. */
export const mockPeerId = (peerId: string) =>
  vi.fn<() => Promise<string>>(async () => peerId);

/** Create an Ergo-state response callback for MultiSigUtils construction. */
export const mockErgoStateContext = (state: wasm.ErgoStateContext) =>
  vi.fn<() => Promise<wasm.ErgoStateContext>>(async () => state);

/** Create the default successful contribution-authorization response. */
export const mockContributionApproval = () =>
  vi.fn<(request: ContributionRequest) => Promise<void>>(async () => {});

/** Install the deterministic active-guard response used by contribution tests. */
export const mockActiveGuards = (
  detection: GuardDetection,
  publicKeys: string[],
): void => {
  vi.spyOn(detection, 'activeGuards').mockResolvedValue(
    publicKeys.map((publicKey, index) => ({
      publicKey,
      peerId: publicKey,
      index,
    })),
  );
};

/**
 * Install a real one-key native wallet and return spies for its commitment and
 * partial-signature operations.
 */
export const mockNativeContributionWallet = (
  handler: TestMultiSigHandler,
  secretHex: string,
) => {
  const keys = new wasm.SecretKeys();
  keys.add(wasm.SecretKey.dlog_from_bytes(Buffer.from(secretHex, 'hex')));
  const wallet = wasm.Wallet.from_secrets(keys);
  const commitments = vi.spyOn(
    wallet,
    'generate_commitments_for_reduced_transaction',
  );
  const signs = vi.spyOn(wallet, 'sign_reduced_transaction_multi');
  handler.installProver(wallet);
  return { commitments, signs };
};

/** Install an inert outbound sender and return its call spy. */
export const mockContributionSender = (handler: TestMultiSigHandler) => {
  const send = vi.fn<TestMultiSigHandler['sendMessage']>(async () => {});
  vi.spyOn(handler, 'sendMessage').mockImplementation(send);
  return send;
};

/**
 * Pause the next signed-envelope response until the returned resume promise is
 * resolved, while retaining the real ECDSA signature implementation.
 */
export const mockPendingEnvelopeSignature = (messageEnc: ECDSA) => {
  const entered = Promise.withResolvers<void>();
  const resume = Promise.withResolvers<void>();
  const original = messageEnc.sign.bind(messageEnc);
  vi.spyOn(messageEnc, 'sign').mockImplementationOnce(async (message) => {
    entered.resolve();
    await resume.promise;
    return original(message);
  });
  return { entered, resume };
};
