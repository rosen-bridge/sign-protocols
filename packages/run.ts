import { MultiSigUtils } from '@rosen-bridge/ergo-multi-sig/lib';
import { mockedErgoStateContext } from '@rosen-bridge/ergo-multi-sig/tests/testData';
import TestConfigs from '@rosen-bridge/ergo-multi-sig/tests/testUtils/TestConfigs';
import { ErgoBox, ErgoBoxCandidate, Wallet } from 'ergo-lib-wasm-nodejs';
import { getChangeBoxJs, getOutBoxJs, jsToReducedTx } from './tx';
import { boxJs, pubs, secrets } from './data';
import { MultiSigHandler } from '@rosen-bridge/ergo-multi-sig/lib/MultiSigHandler';
import { DummyLogger } from '@rosen-bridge/abstract-logger';
import { GuardDetection } from '@rosen-bridge/detection';

let handlers: MultiSigHandler[] = [];
const idToHandler: { [id: string]: MultiSigHandler } = {};

const allMessages: string[] = [];

const testSubmit = async (msg: string, peers: Array<string>) => {
  const msgJson = JSON.parse(msg);
  for (const peer of peers) {
    const handler = idToHandler[peer];
    const id = handler.getPk()
    if (handler) {
      await handler.handleMessage(msg, id);
      if (msgJson.type !== 'register' && msgJson.type !== 'approve')
        allMessages.push(msg);
    }
  }
};

const generateMultiSigHandlerInstance = async (
  secret: string,
  pks?: string[],
  submit?: (msg: string, peers: Array<string>) => unknown,
): Promise<MultiSigHandler> => {
  const multiSigUtilsInstance = new MultiSigUtils(async () => {
    return mockedErgoStateContext;
  });
  const publicKeys = pks ? pks : pubs;
  const secretInd = secrets.indexOf(secret);
  const dummyGuardDetection = {
    activeGuards: async () => publicKeys.map((pk, index) => ({ publicKey: pk, peerId: `peer${index}` })),
  } as GuardDetection;

  const handler = new MultiSigHandler({
    multiSigUtilsInstance: multiSigUtilsInstance,
    secretHex: secret,
    txSignTimeout: TestConfigs.txSignTimeout,
    submit: testSubmit,
    getPeerId: () => Promise.resolve(`peer${secretInd}`),
    getPeerPks: () => publicKeys,
    guardDetection: dummyGuardDetection,
    logger: new DummyLogger(),
  });
  return handler;
};

const handleSuccessfulSign = async (tx: any): Promise<void> => {
  console.log(tx);
  const allMessagesByteSize = Buffer.byteLength(
    JSON.stringify(allMessages, null, 2),
  );
  console.log(allMessagesByteSize);
};

const test = async () => {
  handlers = await Promise.all(
    secrets.map((secret, index) =>
      generateMultiSigHandlerInstance(secret, pubs),
    ),
  );
  handlers.forEach((handler) => {
    const id = `peer${handler.getIndex()}`;
    idToHandler[id] = handler;
  });

  const fee = 1000000;
  const tree =
    '0008cd03e5bedab3f782ef17a73e9bdc41ee0e18c3ab477400f35bcf7caa54171db7ff36';
  const out = getOutBoxJs(tree, ['ERG', 10000000]);
  const ins = [boxJs];
  const dataBoxes = [];
  const change = getChangeBoxJs(ins, [out], tree, fee);
  const reduced = jsToReducedTx(ins, [out, change], dataBoxes, 1311604, fee);
  const requiredSigns = 6;
  const boxes = ins.map((i: any) => ErgoBox.from_json(JSON.stringify(i)));

  const promises = handlers.map((handler) => {
    return handler
      .sign(reduced, requiredSigns, boxes, dataBoxes)
      .then(handleSuccessfulSign);
  });

  try {
    await Promise.all(promises);
  } catch (e) {
    console.log(e);
  }

  const allMessagesByteSize = Buffer.byteLength(
    JSON.stringify(allMessages, null, 2),
  );
  const data = {
    len: allMessagesByteSize,
    messages: allMessages,
  };
  console.log(allMessagesByteSize, allMessages.length);
};

console.log('Running test')
test();
