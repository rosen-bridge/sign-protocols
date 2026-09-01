import { vi } from 'vitest';

import { DummyLogger } from '@rosen-bridge/abstract-logger';
import { EncryptionHandler } from '@rosen-bridge/encryption';

import { Communicator } from '../lib';

export class TestCommunicator extends Communicator {
  protected readonly protocolVersion = '1.0.0';

  constructor(
    signer: EncryptionHandler,
    submitMessage: (msg: string, peers: Array<string>) => unknown,
    guardPks: Array<string>,
  ) {
    super(new DummyLogger(), signer, submitMessage, guardPks);
  }

  testSendMessage = (
    messageType: string,
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    payload: any,
    peers: Array<string>,
  ) => {
    return this.sendMessage(messageType, payload, peers);
  };

  processMessage = vi.fn();

  mockedGetIndex = async () => await this.getIndex();

  mockedGetDate = () => this.getDate();
}
