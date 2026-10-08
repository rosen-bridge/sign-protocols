import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  mockIndexWithGate,
  mockNextSignWithGate,
} from './mocked/communicator.mock';
import { TestSubmissionCommunicator } from './testSubmissionCommunicator';
import {
  awaitBoundary,
  createSubmissionFixture,
} from './testUtils/submissionUtils';

describe('Communicator', () => {
  describe('sendMessage', () => {
    afterEach(() => vi.restoreAllMocks());

    /**
     * @target Communicator.sendMessage rechecks after the last asynchronous
     * index lookup and preserves the envelope
     * @dependencies
     * - real EdDSA randomKey, getPk, and sign implementations
     * - native Promise.withResolvers index gate
     * - mocked Communicator.getIndex gate
     * - mocked submitMessage transport sink
     * @scenario
     * - create a communicator with a real signer and mocked transport sink
     * - gate the asynchronous index lookup
     * - start sending a message with a synchronous validator
     * - race index entry against the send operation's first settlement
     * - verify the validator and transport have not run while lookup is gated
     * - resume the lookup and await submission
     * - inspect the validator call and serialized transport envelope
     * - release the gate and drain the send operation in finally
     * @expected
     * - the validator should run once after the index lookup
     * - the transport should receive one envelope with the requested fields
     */
    it('rechecks after the last asynchronous index lookup and preserves the envelope', async () => {
      const { communicator, submit } = await createSubmissionFixture();
      const gate = mockIndexWithGate(communicator);
      const beforeSubmit = vi.fn((): undefined => {
        expect(submit).not.toHaveBeenCalled();
      });
      const pending = communicator.publish(
        'current',
        { value: 1 },
        ['peer'],
        1,
        beforeSubmit,
      );
      try {
        await awaitBoundary(
          gate.entered.promise,
          pending,
          'Communicator.getIndex',
        );
        expect(beforeSubmit).not.toHaveBeenCalled();
        gate.resume.resolve();
        await pending;
        expect(beforeSubmit).toHaveBeenCalledTimes(1);
        expect(submit).toHaveBeenCalledTimes(1);
        expect(JSON.parse(submit.mock.calls[0][0])).toEqual(
          expect.objectContaining({
            type: 'current',
            payload: { value: 1 },
            timestamp: 1,
            index: 0,
            version: '1.0.0',
          }),
        );
      } finally {
        gate.resume.resolve();
        await pending.catch(() => undefined);
      }
    });

    /**
     * @target Communicator.sendMessage prevents submission when state changes
     * at the last asynchronous boundary
     * @dependencies
     * - real EdDSA randomKey, getPk, and sign implementations
     * - native Promise.withResolvers index gate
     * - mocked Communicator.getIndex gate
     * - mocked submitMessage transport sink
     * @scenario
     * - create a communicator with a real signer and mocked transport sink
     * - gate the asynchronous index lookup and start sending a valid message
     * - race index entry against the send operation's first settlement
     * - mark the validator state stale before resuming the lookup
     * - resume the lookup and await the pending rejection
     * - inspect the transport sink
     * - release the gate and drain the send operation in finally
     * @expected
     * - the pending send should reject with the validator error
     * - the transport sink should not be called
     */
    it('prevents submission when state changes at the last asynchronous boundary', async () => {
      const { communicator, submit } = await createSubmissionFixture();
      const gate = mockIndexWithGate(communicator);
      let current = true;
      const pending = communicator.publish(
        'stale',
        {},
        [],
        1,
        (): undefined => {
          if (!current) throw Error('stale');
        },
      );
      try {
        await awaitBoundary(
          gate.entered.promise,
          pending,
          'Communicator.getIndex',
        );
        current = false;
        gate.resume.resolve();
        await expect(pending).rejects.toThrow('stale');
        expect(submit).not.toHaveBeenCalled();
      } finally {
        gate.resume.resolve();
        await pending.catch(() => undefined);
      }
    });

    /**
     * @target Communicator.sendMessage keeps concurrent sends bound to their
     * own validator
     * @dependencies
     * - real EdDSA randomKey, getPk, and sign implementations
     * - native Promise.withResolvers signature gate
     * - mocked first EdDSA.sign call
     * - mocked submitMessage transport sink
     * @scenario
     * - create a communicator with a real signer and mocked transport sink
     * - gate the first signature and start a send whose validator rejects
     * - race signature entry against the first send's first settlement
     * - complete a concurrent send whose validator accepts
     * - resume the first signature and await its rejection
     * - inspect the single submitted message type
     * - release the gate and drain the first send in finally
     * @expected
     * - only the accepted concurrent send should reach the transport sink
     * - the first send should reject with its own validator error
     */
    it('keeps concurrent sends bound to their own validator', async () => {
      const { communicator, signer, submit } = await createSubmissionFixture();
      const gate = mockNextSignWithGate(signer);
      const pending = communicator.publish('rejected', {}, [], 1, () => {
        throw Error('refused');
      });
      try {
        await awaitBoundary(gate.entered.promise, pending, 'EdDSA.sign');
        await communicator.publish('accepted', {}, [], 1, () => undefined);
        gate.resume.resolve();
        await expect(pending).rejects.toThrow('refused');
        expect(submit).toHaveBeenCalledTimes(1);
        expect(JSON.parse(submit.mock.calls[0][0]).type).toEqual('accepted');
      } finally {
        gate.resume.resolve();
        await pending.catch(() => undefined);
      }
    });

    /**
     * @target Communicator.sendMessage requires the validator type to be
     * synchronous
     * @dependencies
     * - TestSubmissionCommunicator.publish parameter types
     * - TypeScript @ts-expect-error validation
     * @scenario
     * - derive the validator type from the exposed sendMessage signature
     * - assign a synchronous validator to that type
     * - mark an asynchronous validator assignment as an expected type error
     * - inspect both runtime values
     * @expected
     * - the synchronous validator should return undefined
     * - the rejected asynchronous assignment should remain a runtime function
     */
    it('requires the validator type to be synchronous', () => {
      type Validator = NonNullable<
        Parameters<TestSubmissionCommunicator['publish']>[4]
      >;
      const valid: Validator = () => undefined;
      // Async callbacks would leave submission outside the assertion.
      // @ts-expect-error Verify that the callback type rejects them.
      const invalid: Validator = async () => {};
      expect(valid()).toBeUndefined();
      expect(typeof invalid).toEqual('function');
    });
  });
});
