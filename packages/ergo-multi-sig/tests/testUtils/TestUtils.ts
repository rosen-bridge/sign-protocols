import { randomBytes } from 'crypto';
import { MultiSigHandler, MultiSigUtils } from '../../lib';
import { mockedErgoStateContext } from '../testData';
import { pubs, secrets } from '../../../data';
import TestConfigs from './TestConfigs';

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
    const pubKeys = pks ? pks : pubs;
    const secretInd = secrets.indexOf(secret);
    const handler = new MultiSigHandler({
      multiSigUtilsInstance: multiSigUtilsInstance,
      publicKeys: pubKeys,
      secretHex: secret,
      txSignTimeout: TestConfigs.txSignTimeout,
      multiSigFirstSignDelay: TestConfigs.multiSigFirstSignDelay,
      submit: submit,
      getPeerId: () => Promise.resolve(pubs[secretInd]),
    });
    return handler;
  };

}

export default TestUtils;
