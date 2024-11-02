import {
  Address,
  BlockHeaders,
  BoxId,
  BoxValue,
  Constant,
  Contract,
  DataInput,
  DataInputs,
  ErgoBoxCandidate,
  ErgoBoxCandidateBuilder,
  ErgoBoxCandidates,
  ErgoBoxes,
  ErgoStateContext,
  ErgoTree,
  I64,
  NetworkPrefix,
  PreHeader,
  ReducedTransaction,
  TokenAmount,
  TokenId,
  UnsignedInput,
  UnsignedInputs,
  UnsignedTransaction,
} from 'ergo-lib-wasm-nodejs';
import { headers } from '../testData';

type Asset = {
  tokenId: string;
  amount: number;
};

type ErgoBoxJs = {
  value: number;
  ergoTree: string;
  assets?: Asset[];
  additionalRegisters?: { [key: string]: string };
};

type InputBox = {
  boxId: string;
  value: number;
  assets: Asset[];
};

type TokenDict = { [tokenId: string]: number };

/**
 * Converts a number to a BoxValue
 * @param val number to convert
 */
function getBoxValue(val: number): BoxValue {
  return BoxValue.from_i64(I64.from_str(val.toString()));
}

/**
 * Converts a string to a BoxId
 * @param id string to convert
 */
function idToBoxId(id: string): BoxId {
  return BoxId.from_str(id);
}

/**
 * Converts an address to a contract
 * @param address string to convert
 */
function addressToContract(address: string): Contract {
  return Contract.pay_to_address(Address.from_mainnet_str(address));
}

/**
 * Converts a JS object to a ErgoBoxCandidate
 * @param out JS object to convert
 * @param height height of the box
 */
function jsToCandidate(out: ErgoBoxJs, height: number): ErgoBoxCandidate {
  const tree = ErgoTree.from_base16_bytes(out.ergoTree);
  const address = Address.recreate_from_ergo_tree(tree).to_base58(
    NetworkPrefix.Mainnet,
  );
  const myOut = new ErgoBoxCandidateBuilder(
    getBoxValue(out.value),
    addressToContract(address),
    height,
  );

  if (!out.assets) out.assets = [];
  out.assets.forEach((i: Asset) => {
    const tokAm = TokenAmount.from_i64(I64.from_str(i.amount.toString()));
    myOut.add_token(TokenId.from_str(i.tokenId), tokAm);
  });
  if (!out.additionalRegisters) out.additionalRegisters = {};

  const vals: string[] = Object.values(out.additionalRegisters);
  for (let i = 0; i < vals.length; i++) {
    myOut.set_register_value(
      i + 4,
      Constant.decode_from_base16(vals[i].toString()),
    );
  }
  return myOut.build();
}

/**
 * Converts a JS object to a ErgoBoxCandidate
 * @param tree ErgoTree of the box
 * @param willGet
 */
function getOutBoxJs(tree: string, willGet: [string, number]): ErgoBoxJs {
  let ergVal = Number(process.env.MIN_ERG);
  if (willGet[0].length <= 10) ergVal = willGet[1];

  const out: ErgoBoxJs = {
    value: ergVal,
    ergoTree: tree,
    assets: [],
    additionalRegisters: {},
  };

  if (willGet[0].length > 10 && willGet[1] > 0)
    out.assets = [{ tokenId: willGet[0], amount: willGet[1] }];
  return out;
}

/**
 * Converts JS objects to an UnsignedTransaction
 * @param inputs tx inputs
 * @param outputs tx outputs
 * @param dInputs tx data inputs
 * @param height height of the tx
 * @param fee fee of the tx
 */
function jsToUnsignedTx(
  inputs: InputBox[],
  outputs: ErgoBoxJs[],
  dInputs: InputBox[],
  height: number,
  fee: number,
): UnsignedTransaction {
  const unsignedInputs = new UnsignedInputs();
  for (const box of inputs) {
    const unsignedInput = UnsignedInput.from_box_id(idToBoxId(box.boxId));
    unsignedInputs.add(unsignedInput);
  }

  const dataInputs = new DataInputs();
  for (const d of dInputs) dataInputs.add(new DataInput(idToBoxId(d.boxId)));

  const unsignedOutputs = ErgoBoxCandidates.empty();
  outputs.forEach((i: ErgoBoxJs) => {
    const box = jsToCandidate(i, height);
    unsignedOutputs.add(box);
  });
  const feeBox = ErgoBoxCandidate.new_miner_fee_box(getBoxValue(fee), height);
  unsignedOutputs.add(feeBox);

  return new UnsignedTransaction(unsignedInputs, dataInputs, unsignedOutputs);
}

/**
 * Converts JS tx to a ReducedTransaction
 * @param inputs tx inputs
 * @param outputs tx outputs
 * @param dInputs tx data inputs
 * @param height height of the tx
 * @param fee fee of the tx
 */
function jsToReducedTx(
  inputs: InputBox[],
  outputs: ErgoBoxJs[],
  dInputs: InputBox[],
  height: number,
  fee: number,
): ReducedTransaction {
  const unsignedTx = jsToUnsignedTx(inputs, outputs, dInputs, height, fee);

  const blockHeaders = BlockHeaders.from_json(headers);
  const pre_header = PreHeader.from_block_header(
    blockHeaders.get(blockHeaders.len() - 1),
  );
  const ctx = new ErgoStateContext(pre_header, blockHeaders);

  return ReducedTransaction.from_unsigned_tx(
    unsignedTx,
    ErgoBoxes.from_boxes_json(inputs),
    ErgoBoxes.from_boxes_json(dInputs),
    ctx,
  );
}

/**
 * Get tokens from assets
 * @param assets assets of the box
 */
function getTokens(assets: Asset[]): TokenDict {
  const inTokens: TokenDict = {};
  assets.forEach((asset: Asset) => {
    const tid = asset.tokenId;
    if (!(tid in inTokens)) {
      inTokens[tid] = 0;
    }
    inTokens[tid] += asset.amount;
  });
  return inTokens;
}

/**
 * Get change box for the tx
 * @param ins tx inputs
 * @param outs tx outputs
 * @param changeTree ErgoTree of the change box
 * @param fee fee of the tx
 */
function getChangeBoxJs(
  ins: InputBox[],
  outs: ErgoBoxJs[],
  changeTree: string,
  fee: number,
): ErgoBoxJs {
  const inVal = ins.reduce((acc: number, i) => acc + Number(i.value), 0);
  const outVal = outs.reduce((acc: number, i) => acc + Number(i.value), 0);
  const inTokens = getTokens(ins.map((i) => i.assets).flat());
  const outAssets = outs
    .map((i) => i.assets)
    .flat()
    .filter((i): i is Asset => i !== undefined);
  const outTokens = getTokens(outAssets);

  const keys = new Set(Object.keys(inTokens).concat(Object.keys(outTokens)));

  keys.forEach((tokenId) => {
    if (!(tokenId in inTokens)) {
      inTokens[tokenId] = 0;
    }
    if (tokenId in outTokens) {
      inTokens[tokenId] -= outTokens[tokenId];
    }
  });
  let assets = Object.keys(inTokens).map((tokenId) => {
    return { tokenId, amount: inTokens[tokenId] };
  });

  if (
    inVal - outVal - fee < 0 ||
    Object.values(inTokens).filter((i) => i < 0).length > 0
  ) {
    throw new Error('Not enough funds');
  }

  assets = assets.filter((i) => i.amount > 0);
  return {
    value: inVal - outVal - fee,
    ergoTree: changeTree,
    assets: assets,
  };
}

export {
  getBoxValue,
  addressToContract,
  jsToCandidate,
  getOutBoxJs,
  jsToUnsignedTx,
  getChangeBoxJs,
  jsToReducedTx,
};
