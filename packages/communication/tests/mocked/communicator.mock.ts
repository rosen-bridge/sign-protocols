import { vi } from 'vitest';

import { EdDSA } from '@rosen-bridge/encryption';

import { TestSubmissionCommunicator } from '../testSubmissionCommunicator';

/**
 * Create a mocked transport sink for communicator submissions.
 */
export const mockSubmitMessage = () => vi.fn();

/**
 * Replace getIndex with a gated response so a test can control submission.
 */
export const mockIndexWithGate = (communicator: TestSubmissionCommunicator) => {
  const entered = Promise.withResolvers<void>();
  const resume = Promise.withResolvers<void>();
  const original = communicator.getIndex;
  vi.spyOn(communicator, 'getIndex').mockImplementation(async () => {
    entered.resolve();
    await resume.promise;
    return original();
  });
  return { entered, resume };
};

/**
 * Gate the next EdDSA signature so a test can run another send concurrently.
 */
export const mockNextSignWithGate = (signer: EdDSA) => {
  const entered = Promise.withResolvers<void>();
  const resume = Promise.withResolvers<void>();
  const original = signer.sign.bind(signer);
  vi.spyOn(signer, 'sign').mockImplementationOnce(async (message) => {
    entered.resolve();
    await resume.promise;
    return original(message);
  });
  return { entered, resume };
};
