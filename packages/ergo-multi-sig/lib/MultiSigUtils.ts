import * as wasm from 'ergo-lib-wasm-nodejs';
import { ErgoBox, ErgoBoxes, TransactionHintsBag } from 'ergo-lib-wasm-nodejs';
import {
  CommitmentJson,
  PublishedCommitment,
  PublishedProof,
  SingleCommitment,
} from './types';
import { CHALLENGE_LEN } from './const';

export class MultiSigUtils {
  getStateContext: () => Promise<wasm.ErgoStateContext>;

  constructor(getStateContextFunction: () => Promise<wasm.ErgoStateContext>) {
    this.getStateContext = getStateContextFunction;
  }

  /**
   * gets public keys hex string and convert them to the Propositions
   * @param pubKeys public keys
   */
  static publicKeyToProposition = (
    pubKeys: Array<string>,
  ): wasm.Propositions => {
    const res = new wasm.Propositions();
    pubKeys.forEach((item) => {
      res.add_proposition_from_byte(
        Uint8Array.from(Buffer.from('cd' + item, 'hex')),
      );
    });
    return res;
  };

  /**
   * extracted hints for a transaction
   * @param tx transaction
   * @param boxes boxes
   * @param dataBoxes data boxes
   * @param signed signed public keys
   * @param simulated simulated public keys
   */
  extract_hints = async (
    tx: wasm.Transaction,
    boxes: Array<wasm.ErgoBox>,
    dataBoxes: Array<wasm.ErgoBox>,
    signed: Array<string>,
    simulated: Array<string>,
  ): Promise<TransactionHintsBag> => {
    const simulatedPropositions =
      MultiSigUtils.publicKeyToProposition(simulated);
    const realPropositions = MultiSigUtils.publicKeyToProposition(signed);
    const inputBoxes = wasm.ErgoBoxes.empty();
    boxes.forEach((item) => inputBoxes.add(item));
    const dataInputBoxes = wasm.ErgoBoxes.empty();
    dataBoxes.forEach((item) => dataInputBoxes.add(item));
    const context = await this.getStateContext();

    return wasm.extract_hints(
      tx,
      context,
      inputBoxes,
      dataInputBoxes,
      realPropositions,
      simulatedPropositions,
    );
  };

  /**
   * adding hints to a transaction hints bag
   * @param currentHints current hints bag
   * @param newHints new hints bag
   * @param inputLen input length of the transaction
   */
  static add_hints = (
    currentHints: wasm.TransactionHintsBag,
    newHints: wasm.TransactionHintsBag,
    inputLen: number,
  ): void => {
    for (let index = 0; index < inputLen; index++) {
      currentHints.add_hints_for_input(
        index,
        newHints.all_hints_for_input(index),
      );
    }
  };

  /**
   * converting published commitment in the p2p network to hints bag
   * @param commitments published commitments
   * @param pubKey public key
   * @param type commitment type: simulated or real
   */
  static convertToHintBag = (
    commitments: PublishedCommitment,
    pubKey: string,
    type = 'cmtReal',
  ): TransactionHintsBag => {
    const resultJson: CommitmentJson = {
      secretHints: {},
      publicHints: {},
    };
    Object.keys(commitments).forEach((key) => {
      const inputCommitments = commitments[key];
      resultJson.secretHints[key] = [];
      if (!resultJson.publicHints[key]) {
        resultJson.publicHints[key] = [];
      }
      inputCommitments.forEach((commitment) => {
        resultJson.publicHints[key].push({
          a: commitment.a,
          hint: type,
          position: commitment.position,
          type: 'dlog',
          pubkey: {
            op: '205',
            h: pubKey,
          },
        });
      });
    });
    return wasm.TransactionHintsBag.from_json(JSON.stringify(resultJson));
  };

  /**
   * converting published proofs to hint bag
   * @param publishedProof published proofs
   * @param pubKey public keys with correct order
   * @param type proof type: simulated or real
   */
  static publishedProofToHintBag = (
    publishedProof: PublishedProof,
    pubKey: string,
    type = 'proofReal',
  ): wasm.TransactionHintsBag => {
    const resultJson: CommitmentJson = {
      secretHints: {},
      publicHints: {},
    };
    Object.keys(publishedProof).forEach((key) => {
      const proofs = publishedProof[key];
      resultJson.secretHints[key] = [];
      resultJson.publicHints[key] = [];
      proofs.forEach((proof) => {
        resultJson.secretHints[key].push({
          hint: type,
          pubkey: {
            op: '205',
            h: pubKey,
          },
          challenge: proof.proof.slice(0, CHALLENGE_LEN),
          proof: proof.proof,
          position: proof.position,
        });
      });
    });
    return wasm.TransactionHintsBag.from_json(JSON.stringify(resultJson));
  };

  /**
   * coverts published proofs to hint bag
   * @param publishedProofs published proofs
   * @param pubKeys public keys with correct order
   * @param inputLen input length of the transaction
   * @param type proof type: simulated or real
   */
  static publishedProofsToHintBag(
    publishedProofs: PublishedProof[],
    pubKeys: string[],
    inputLen: number,
    type = 'proofReal',
  ): wasm.TransactionHintsBag {
    const hints = wasm.TransactionHintsBag.empty();
    publishedProofs.forEach((publishedProof, index) => {
      const hintBag = MultiSigUtils.publishedProofToHintBag(
        publishedProof,
        pubKeys[index],
        type,
      );
      MultiSigUtils.add_hints(hints, hintBag, inputLen);
    });
    return hints;
  }

  /**
   * converting published commitments to hints bag
   * @param publishedCommitments published commitments
   * @param pubKeys public keys with correct order
   * @param inputLen input length of the transaction
   * @param type commitment type: simulated or real
   */
  static publishedCommitmentsToHintBag(
    publishedCommitments: PublishedCommitment[],
    pubKeys: string[],
    inputLen: number,
    type = 'cmtReal',
  ): wasm.TransactionHintsBag {
    const hints = wasm.TransactionHintsBag.empty();
    publishedCommitments.forEach((publishedCommitment, index) => {
      const hintBag = MultiSigUtils.convertToHintBag(
        publishedCommitment,
        pubKeys[index],
        type,
      );
      MultiSigUtils.add_hints(hints, hintBag, inputLen);
    });
    return hints;
  }

  /**
   * compare two list of published commitment and verify to be equal.
   * @param item1 published commitments
   * @param item2 published commitments
   * @param inputLength input length of the transaction
   */
  static comparePublishedCommitmentsToBeDiffer = (
    item1: PublishedCommitment,
    item2: PublishedCommitment,
    inputLength: number,
  ) => {
    for (let inputIndex = 0; inputIndex < inputLength; inputIndex++) {
      const item1InputCommitments = item1[`${inputIndex}`];
      const item2InputCommitments = item2[`${inputIndex}`];
      if (
        item1InputCommitments &&
        item2InputCommitments &&
        item1InputCommitments.length > 0 &&
        item2InputCommitments.length > 0
      ) {
        if (item2InputCommitments.length !== item1InputCommitments.length) {
          return true;
        }
        if (
          !MultiSigUtils.compareSingleInputCommitmentsAreEquals(
            item1InputCommitments,
            item2InputCommitments,
          )
        ) {
          return true;
        }
      }
    }
    return false;
  };

  /**
   * compare two single commitments to be equals
   * @param item1 single commitments
   * @param item2 single commitments
   */
  static compareSingleInputCommitmentsAreEquals = (
    item1: Array<SingleCommitment>,
    item2: Array<SingleCommitment>,
  ) => {
    const item1Sorted = item1.sort((a, b) =>
      a.position.localeCompare(b.position),
    );
    const item2Sorted = item2.sort((a, b) =>
      a.position.localeCompare(b.position),
    );
    let res = true;
    item1Sorted.map((item, index) => {
      if (item2Sorted[index].a && item.a !== item2Sorted[index].a) {
        res = false;
      }
    });
    return res;
  };

  /**
   * Convert hint bag to published commitments
   * @param hintBag hint bag
   * @param pub public key
   */
  static toReducedPublishedCommitments = (
    hintBag: wasm.TransactionHintsBag,
    pub: string,
  ): PublishedCommitment => {
    const hintJs = hintBag.to_json() as CommitmentJson;
    const publicHints = hintJs.publicHints;
    const publishCommitments: PublishedCommitment = {};
    Object.keys(publicHints).forEach((inputIndex) => {
      const inputHints = publicHints[inputIndex]
        .filter((item) => !item.secret)
        .filter((item) => item.pubkey.h === pub);
      if (inputHints) {
        publishCommitments[inputIndex] = inputHints.map((item) => ({
          a: item.a,
          position: item.position,
        }));
      }
    });
    return publishCommitments;
  };

  /**
   * Convert hint bag to published commitments
   * @param hintBag hint bag
   * @param pubs public key
   */
  static toReducedPublishedCommitmentsArray = (
    hintBag: wasm.TransactionHintsBag,
    pubs: Array<string>,
  ): PublishedCommitment[] => {
    return pubs.map((pub) =>
      MultiSigUtils.toReducedPublishedCommitments(hintBag, pub),
    );
  };

  /**
   * Convert hint bag to published proofs
   * @param hintBag hint bag
   * @param pub public key
   */
  static hintBagToPublishedProof = (
    hintBag: wasm.TransactionHintsBag,
    pub: string,
  ): PublishedProof => {
    const hintsJs: CommitmentJson = hintBag.to_json() as CommitmentJson;
    const publishedProof: PublishedProof = {};
    const privateHints = hintsJs.secretHints;
    Object.keys(privateHints).forEach((key) => {
      const hints = privateHints[key].filter(
        (hint: any) => hint.pubkey.h === pub,
      );
      publishedProof[key] = hints.map((hint: any) => ({
        proof: hint.proof,
        position: hint.position,
      }));
    });
    return publishedProof;
  };

  /**
   * Coverts hint bag to published proofs in the order of public keys
   * @param hintBag hint bag
   * @param pubs public keys
   */
  static toReducedPublishedProofsArray = (
    hintBag: wasm.TransactionHintsBag,
    pubs: Array<string>,
  ): PublishedProof[] => {
    return pubs.map((pub) =>
      MultiSigUtils.hintBagToPublishedProof(hintBag, pub),
    );
  };

  /**
   * verify that the transaction is valid
   * @param tx signed transaction
   * @param boxes boxes that are used in the transaction
   */
  verifyInput = async (tx: wasm.Transaction, boxes: Array<ErgoBox>) => {
    const context = await this.getStateContext();
    const ergoBoxes = ErgoBoxes.empty();
    for (let index = 0; index < boxes.length; index++) {
      ergoBoxes.add(boxes[index]);
    }
    for (let ind = 0; ind < tx.inputs().len(); ind++) {
      if (
        !wasm.verify_tx_input_proof(
          ind,
          context,
          tx,
          ergoBoxes,
          wasm.ErgoBoxes.empty(),
        )
      )
        return false;
    }
    return true;
  };

  /**
   * get empty prover
   */
  static getEmptyProver = (): wasm.Wallet => {
    const secretKeys = new wasm.SecretKeys();
    return wasm.Wallet.from_secrets(secretKeys);
  };
}
