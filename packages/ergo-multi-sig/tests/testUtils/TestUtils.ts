import { randomBytes } from 'crypto';
import { MultiSigHandler, MultiSigUtils } from '../../lib';
import { mockedErgoStateContext, testPubs, testSecrets } from '../testData';
import TestConfigs from './TestConfigs';
import Encryption from '../../lib/utils/Encryption';

class TestUtils {
  /**
   * generates 32 bytes random data used for the identifiers such as txId
   */
  static generateRandomId = (): string => randomBytes(32).toString('hex');

  static generateMultiSigHandlerInstance = async (
    secret: string,
    submit: (msg: string, peers: Array<string>) => unknown,
    pks?: string[],
  ): Promise<MultiSigHandler> => {
    const multiSigUtilsInstance = new MultiSigUtils(async () => {
      return mockedErgoStateContext;
    });
    const pubKeys = pks ? pks : testPubs;
    const secretInd = testSecrets.indexOf(secret);
    const handler = new MultiSigHandler({
      multiSigUtilsInstance: multiSigUtilsInstance,
      publicKeys: pubKeys,
      secretHex: secret,
      txSignTimeout: TestConfigs.txSignTimeout,
      multiSigFirstSignDelay: TestConfigs.multiSigFirstSignDelay,
      submit: submit,
      getPeerId: () => Promise.resolve(testPubs[secretInd]),
    });
    return handler;
  };

  static messageToPayload = (
    message: any,
    ind: number,
    secret: string,
  ): any => {
    const payload = message.payload;
    payload.index = ind;
    payload.id = ind.toString();
    const sec = Buffer.from(secret, 'hex');
    const payloadStr = JSON.stringify(message.payload);
    message.sign = Buffer.from(
      Encryption.sign(payloadStr, Buffer.from(sec)),
    ).toString('base64');
    return message;
  };
}

export default TestUtils;
