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

  /**
   * generates a MultiSigHandler instance
   * @param secret secret of the handler
   * @param submit submit function for messages
   * @param pks public keys of the handlers
   */
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
}

export default TestUtils;
