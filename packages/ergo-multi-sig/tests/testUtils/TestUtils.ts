import { randomBytes } from 'crypto';
import { MultiSigHandler, MultiSigUtils } from '../../lib';
import { mockedErgoStateContext, testPubs, testSecrets } from '../testData';
import TestConfigs from './TestConfigs';
import Encryption from '../../lib/utils/Encryption';
import * as wasm from 'ergo-lib-wasm-nodejs';

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

  /**
   * add a transaction to the queue without initiating sign
   * @param handler multi-sig handler
   * @param tx reduced transaction for multi-sig transaction
   * @param requiredSign number of required signatures
   * @param boxes input boxes for transaction
   * @param dataBoxes data input boxes for transaction
   */
  static addTx = async (
    handler: MultiSigHandler,
    tx: wasm.ReducedTransaction,
    requiredSign: number,
    boxes: Array<wasm.ErgoBox>,
    dataBoxes: Array<wasm.ErgoBox>,
  ) => {
    return handler
      .getQueuedTransaction(tx.unsigned_tx().id().to_str())
      .then(({ transaction, release }) => {
        transaction.tx = tx;
        transaction.boxes = boxes;
        transaction.requiredSigner = requiredSign;
        transaction.dataBoxes = dataBoxes;
        release();
      });
  };
}

export default TestUtils;
