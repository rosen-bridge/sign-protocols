import { MultiSigUtils } from '@rosen-bridge/ergo-multi-sig/lib';
import { mockedErgoStateContext } from '@rosen-bridge/ergo-multi-sig/tests/testData';
import TestConfigs from '@rosen-bridge/ergo-multi-sig/tests/testUtils/TestConfigs';
import { ErgoBox, ErgoBoxCandidate, Wallet } from 'ergo-lib-wasm-nodejs';
import { getChangeBoxJs, getOutBoxJs, jsToReducedTx } from './tx';
import { boxJs, pubs, secrets } from './data';
import { MultiSigHandler } from '@rosen-bridge/ergo-multi-sig/lib/MultiSigHandler';


let handlers: MultiSigHandler[] = [];
let idToHandler: { [id: string]: MultiSigHandler } = {};

const allMessages: string[] = [];

const testSubmit = (msg: string, peers: Array<string>) => {
  let toSend = pubs
  if (peers.length > 0) {
    toSend = peers;
  }
  const msgJson = JSON.parse(msg);
  toSend.forEach((id) => {
    const handler = idToHandler[id];
    if (handler) {
      const id = msgJson.payload.id
      handler.handleMessage(msg, '', id);
      if (msgJson.type !== 'register' && msgJson.type !== 'approve') allMessages.push(msg);
    }
  });

}

const generateMultiSigHandlerInstance = async (
  secret: string,
  pks?: string[],
  submit?: (msg: string, peers: Array<string>) => unknown,
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
    submit: testSubmit,
    getPeerId: () => Promise.resolve(pubs[secretInd]),
  });
  return handler;
};

const handleSuccessfulSign = async (
  tx: any
): Promise<void> => {
  console.log(tx)
  const allMessagesByteSize = Buffer.byteLength(JSON.stringify(allMessages, null, 2));
  console.log(allMessagesByteSize)
};

const test = async () => {
  // const handler = await generateMultiSigHandlerInstance('5bc1d17d0612e696a9138ab8e85ca2a02d0171440ec128a9ad557c28bd5ea046');
  handlers = await Promise.all(secrets.map((secret, index) => generateMultiSigHandlerInstance(secret, pubs)));
  handlers.forEach((handler) =>  {
    const id = pubs[handler.getIndex()]
    idToHandler[id] = handler;
  });
  handlers.forEach((handler) => {
   handler.handlePublicKeysChange(pubs);
  })

  const fee = 1000000
  const tree = "0008cd03e5bedab3f782ef17a73e9bdc41ee0e18c3ab477400f35bcf7caa54171db7ff36"
  const out = getOutBoxJs(tree, ['ERG', 10000000])
  const ins = [boxJs]
  const dataBoxes = []
  const change = getChangeBoxJs(ins, [out], tree, fee)
  const reduced = jsToReducedTx(ins, [out, change], dataBoxes, 1311604, fee)
  const requiredSings = 6
  const boxes = ins.map((i: any) => ErgoBox.from_json(JSON.stringify(i)))

  // todo fix
  // await handlers[0].sign(reduced, requiredSings, boxes, dataBoxes)

  for (let i = 0; i < handlers.length; i++) {
    await handlers[i].addTx(reduced, boxes, dataBoxes)
  }

  // for (let i = 0; i < handlers.length; i++) {
  //   await handlers[i].sign(reduced, requiredSings, boxes, dataBoxes)
  // }
  const promises = handlers.map((handler) => {
    return handler.sign(reduced, requiredSings, boxes, dataBoxes).then(handleSuccessfulSign)
  })

  try {
    await Promise.all(promises)
  } catch (e) {
    console.log(e)
  }

  // write all messages to a file
  const allMessagesByteSize = Buffer.byteLength(JSON.stringify(allMessages, null, 2));
  const data = {
    "len": allMessagesByteSize,
    "messages": allMessages
  }
  console.log(allMessagesByteSize, allMessages.length)

  // read allMessagesBef.json to see the messages
  // const bef = fs.readFileSync('allMessagesBef.json', 'utf8');
  // const befJson = JSON.parse(bef);
  // const beff = befJson.messages
  // const beffSize = Buffer.byteLength(JSON.stringify(beff, null, 2));
  // console.log(beffSize, beff.length)
  // fs.writeFileSync('allMessagesBef.json', JSON.stringify(data, null, 2));
}


test();

