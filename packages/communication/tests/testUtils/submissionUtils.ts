import { EdDSA } from '@rosen-bridge/encryption';

import { mockSubmitMessage } from '../mocked/communicator.mock';
import { TestSubmissionCommunicator } from '../testSubmissionCommunicator';

type OperationSettlement =
  | { outcome: 'resolved' }
  | { outcome: 'rejected'; reason: unknown };

/**
 * Wait for a controlled boundary and fail if the tested operation settles
 * before reaching it.
 */
export const awaitBoundary = async (
  entered: Promise<void>,
  operation: Promise<unknown>,
  boundaryName: string,
) => {
  const settlement: Promise<OperationSettlement> = operation.then(
    () => ({ outcome: 'resolved' }),
    (reason: unknown) => ({ outcome: 'rejected', reason }),
  );
  const first = await Promise.race([
    entered.then(() => ({ outcome: 'entered' }) as const),
    settlement,
  ]);

  if (first.outcome === 'resolved') {
    throw Error(`Operation resolved before reaching ${boundaryName}`);
  }
  if (first.outcome === 'rejected') {
    const detail =
      first.reason instanceof Error ? `: ${first.reason.message}` : '';
    throw new Error(
      `Operation rejected before reaching ${boundaryName}${detail}`,
      { cause: first.reason },
    );
  }
};

/**
 * Create a submission-test communicator backed by a real EdDSA signer and a
 * mocked transport sink.
 */
export const createSubmissionFixture = async () => {
  const signer = new EdDSA(await EdDSA.randomKey());
  const submit = mockSubmitMessage();
  const communicator = new TestSubmissionCommunicator(signer, submit, [
    await signer.getPk(),
  ]);
  return { signer, submit, communicator };
};
