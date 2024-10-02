import { Communicator } from '../lib';
import { EncryptionHandler } from '@rosen-bridge/encryption';
import { DummyLogger } from '@rosen-bridge/abstract-logger';
import { vi } from 'vitest';

export class TestCommunicator extends Communicator {
  constructor(
    signer: EncryptionHandler,
    submitMessage: (msg: string, peers: Array<string>) => unknown,
    guardPks: Array<string>,
  ) {
    super(new DummyLogger(), signer, submitMessage, guardPks);
  }

  testSendMessage = (
    messageType: string,
    payload: any,
    peers: Array<string>,
  ) => {
    return this.sendMessage(messageType, payload, peers);
  };

  processMessage = vi.fn();

  mockedGetDate = () => this.getDate();
}
