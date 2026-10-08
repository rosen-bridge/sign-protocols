import { TestCommunicator } from './testCommunicator';

export class TestSubmissionCommunicator extends TestCommunicator {
  /**
   * Expose sendMessage for submission-validation tests.
   */
  publish = this.sendMessage;

  /** Expose the inherited implementation to the typed method spy. */
  declare getIndex: () => Promise<number>;
}
