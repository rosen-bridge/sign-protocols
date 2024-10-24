import { MultiSigUtils } from '../lib';
import { describe, expect, it } from 'vitest';
import { boxJs } from './testData';
import {
  getChangeBoxJs,
  getOutBoxJs,
  jsToReducedTx,
} from './testUtils/txUtils';
import { ErgoBox } from 'ergo-lib-wasm-nodejs';
import * as wasm from 'ergo-lib-wasm-nodejs';
import fs from 'fs';
import path from 'path';
import { mockedErgoStateContext } from '@rosen-bridge/ergo-multi-sig/tests/testData';

const fee = 1000000;
const tree =
  '0008cd03e5bedab3f782ef17a73e9bdc41ee0e18c3ab477400f35bcf7caa54171db7ff36';
const out = getOutBoxJs(tree, ['ERG', 10000000]);
const ins = [boxJs];
const dataBoxes: any = [];
const change = getChangeBoxJs(ins, [out], tree, fee);
const reduced = jsToReducedTx(ins, [out, change], dataBoxes, 1311604, fee);
const requiredSings = 6;
const boxes = ins.map((i: any) => ErgoBox.from_json(JSON.stringify(i)));

const senderMock = (expectedType: string, expectedPayload: any) => {
  return async (msg: string, peers: string[]) => {
    const msgJson = JSON.parse(msg);
    expect(msgJson.type).toEqual(expectedType);
    expect(msgJson.payload).toEqual(expectedPayload);
  };
};

describe('MultiSigUtils', () => {
  describe('publicKeyToProposition', () => {
    /**
     * @target MultiSigUtils.publicKeyToProposition should run without any error
     * @dependencies
     * @scenario
     * - run test with mocked public keys
     * @expected
     * - no error has been thrown
     */
    it('should run without any error', () => {
      MultiSigUtils.publicKeyToProposition([
        '028d938d67befbb8ab3513c44886c16c2bcd62ed4595b9b216b20ef03eb8fb8fb8',
        '03074e09c476bb215dc3aeff908d0b7691895a99dfc3bd950fa629defe541e0364',
        '0300e8750a242ee7d78f5b458e1f7474bd884d2b7894676412ba6b5f319d2ee410',
        '023a5b48c87cd9fece23f5acd08cb464ceb9d76e3c1ddac08206980a295546bb2e',
      ]);
    });
  });

  describe('comparePublishedCommitmentsToBeDiffer', () => {
    /**
     * @target MultiSigUtils.comparePublishedCommitmentsToBeDiffer should return
     * false when two published commitments are same
     * @dependencies
     * @scenario
     * - mock two similar commitments
     * - run test
     * - check retuned value
     * @expected
     * - returned value should be false
     */
    it('should return false when two published commitments are same', () => {
      const firstPublishedCommitment = {
        '0': [
          { a: '20', position: '0-0' },
          { a: '10', position: '0-3' },
          { a: '30', position: '0-11' },
        ],
        '1': [
          { a: '31', position: '0-1' },
          { a: '21', position: '0-4' },
          { a: '11', position: '0-12' },
        ],
        '2': [
          { a: '52', position: '0-5' },
          { a: '51', position: '0-9' },
          { a: '55', position: '0-13' },
        ],
      };
      const secondPublishedCommitment = {
        '1': [
          { a: '21', position: '0-4' },
          { a: '11', position: '0-12' },
          { a: '31', position: '0-1' },
        ],
        '2': [
          { a: '51', position: '0-9' },
          { a: '55', position: '0-13' },
          { a: '52', position: '0-5' },
        ],
        '0': [
          { a: '10', position: '0-3' },
          { a: '20', position: '0-0' },
          { a: '30', position: '0-11' },
        ],
      };
      const res = MultiSigUtils.comparePublishedCommitmentsToBeDiffer(
        firstPublishedCommitment,
        secondPublishedCommitment,
        3,
      );
      expect(res).to.be.false;
    });

    /**
     * @target MultiSigUtils.comparePublishedCommitmentsToBeDiffer should return
     * true when two published commitments have different length
     * @dependencies
     * @scenario
     * - mock two commitments with different length
     * - run test
     * - check retuned value
     * @expected
     * - returned value should be true
     */
    it('should return true when two published commitments have different length', () => {
      const firstPublishedCommitment = {
        '0': [
          { a: '20', position: '0-0' },
          { a: '10', position: '0-3' },
          { a: '30', position: '0-11' },
        ],
        '1': [
          { a: '31', position: '0-1' },
          { a: '21', position: '0-4' },
          { a: '11', position: '0-12' },
        ],
        '2': [
          { a: '52', position: '0-5' },
          { a: '51', position: '0-9' },
          { a: '55', position: '0-13' },
        ],
      };
      const secondPublishedCommitment = {
        '1': [
          { a: '11', position: '0-12' },
          { a: '31', position: '0-1' },
        ],
        '2': [
          { a: '51', position: '0-9' },
          { a: '55', position: '0-13' },
          { a: '52', position: '0-5' },
        ],
        '0': [
          { a: '10', position: '0-3' },
          { a: '20', position: '0-0' },
          { a: '30', position: '0-11' },
        ],
      };
      const res = MultiSigUtils.comparePublishedCommitmentsToBeDiffer(
        firstPublishedCommitment,
        secondPublishedCommitment,
        3,
      );
      expect(res).to.be.true;
    });

    /**
     * @target MultiSigUtils.comparePublishedCommitmentsToBeDiffer should return
     * true when two published commitments have different value
     * @dependencies
     * @scenario
     * - mock two commitments with different value
     * - run test
     * - check retuned value
     * @expected
     * - returned value should be true
     */
    it('should return true when two published commitments have different value', () => {
      const firstPublishedCommitment = {
        '0': [
          { a: '20', position: '0-0' },
          { a: '12', position: '0-3' },
          { a: '30', position: '0-11' },
        ],
        '1': [
          { a: '31', position: '0-1' },
          { a: '21', position: '0-4' },
          { a: '11', position: '0-12' },
        ],
        '2': [
          { a: '52', position: '0-5' },
          { a: '51', position: '0-9' },
          { a: '55', position: '0-13' },
        ],
      };
      const secondPublishedCommitment = {
        '1': [
          { a: '21', position: '0-4' },
          { a: '11', position: '0-12' },
          { a: '31', position: '0-1' },
        ],
        '2': [
          { a: '51', position: '0-9' },
          { a: '55', position: '0-13' },
          { a: '52', position: '0-5' },
        ],
        '0': [
          { a: '10', position: '0-3' },
          { a: '20', position: '0-0' },
          { a: '30', position: '0-11' },
        ],
      };
      const res = MultiSigUtils.comparePublishedCommitmentsToBeDiffer(
        firstPublishedCommitment,
        secondPublishedCommitment,
        3,
      );
      expect(res).to.be.true;
    });
  });

  describe('compareSingleInputCommitmentsAreEquals', () => {
    /**
     * @target MultiSigUtils.compareSingleInputCommitmentsAreEquals should return
     * true when two commitments are same
     * @dependencies
     * @scenario
     * - mock two similar commitments
     * - run test
     * - check retuned value
     * @expected
     * - returned value should be true
     */
    it('should return true when two commitments are same', () => {
      const firstCommitments = [
        { a: '2', position: '0-2' },
        { a: '1', position: '0-1' },
        { a: '3', position: '0-3' },
      ];
      const secondCommitments = [
        { a: '3', position: '0-3' },
        { a: '2', position: '0-2' },
        { a: '1', position: '0-1' },
      ];
      const res = MultiSigUtils.compareSingleInputCommitmentsAreEquals(
        firstCommitments,
        secondCommitments,
      );
      expect(res).to.be.true;
    });

    /**
     * @target MultiSigUtils.compareSingleInputCommitmentsAreEquals should return
     * false when two commitments are different
     * @dependencies
     * @scenario
     * - mock two different commitments
     * - run test
     * - check retuned value
     * @expected
     * - returned value should be false
     */
    it('should return false when two commitments are different', () => {
      const firstCommitments = [
        { a: '1', position: '0-2' },
        { a: '1', position: '0-1' },
        { a: '3', position: '0-3' },
      ];
      const secondCommitments = [
        { a: '3', position: '0-3' },
        { a: '2', position: '0-2' },
        { a: '1', position: '0-1' },
      ];
      const res = MultiSigUtils.compareSingleInputCommitmentsAreEquals(
        firstCommitments,
        secondCommitments,
      );
      expect(res).to.be.false;
    });
  });

  describe('extract_hints', () => {
    /**
     * @target MultiSigUtils.extract_hints should correctly extract hints from a transaction
     * @dependencies
     * - ergo-lib-wasm-nodejs
     * - fs
     * @scenario
     * - Read the simHintsData from the JSON file
     * - Create necessary objects from the data
     * - Create a MultiSigUtils instance with a mock getStateContext function
     * - Call extract_hints with the prepared data
     * - Compare the result with the expected simHints
     * @expected
     * - The extracted hints should match the simHints from the JSON file
     */
    it('should correctly extract hints from a transaction', async () => {
      // Read the simHintsData from the JSON file
      const simHintsDataPath = path.join(
        __dirname,
        'data',
        'simHintsData.json',
      );
      const simHintsData = JSON.parse(
        fs.readFileSync(simHintsDataPath, 'utf-8'),
      );

      const tx = wasm.Transaction.sigma_parse_bytes(
        Buffer.from(simHintsData.inputs.tx, 'base64'),
      );
      const boxes = simHintsData.inputs.boxes.map((box: any) =>
        wasm.ErgoBox.from_json(JSON.stringify(box)),
      );
      const dataBoxes: wasm.ErgoBox[] = [];
      const signed: string[] = [];
      const simulated = simHintsData.inputs.simulatedInputs;

      const multiSigUtils = new MultiSigUtils(async () => {
        return mockedErgoStateContext;
      });

      const result = await multiSigUtils.extract_hints(
        tx,
        boxes,
        dataBoxes,
        signed,
        simulated,
      );

      const expectedSimHints = wasm.TransactionHintsBag.from_json(
        JSON.stringify(simHintsData.simHints),
      );
      expect(result.to_json()).toEqual(expectedSimHints.to_json());
    });
  });

  describe('add_hints', () => {
    /**
     * @target MultiSigUtils.add_hints should correctly combine hints
     * @dependencies
     * - ergo-lib-wasm-nodejs
     * - fs
     * @scenario
     * - Read the simHintsData and other necessary data from JSON files
     * - Create a ReducedTransaction object from the data
     * - Create TransactionHintsBag objects from the data
     * - Call add_hints with the prepared data
     * - Compare the result with the expected combined hints
     * @expected
     * - The combined hints should match the expected addedHints from the JSON file
     */
    it('should correctly combine hints', async () => {
      // Read the simHintsData from the JSON file
      const simHintsDataPath = path.join(
        __dirname,
        'data',
        'simHintsData.json',
      );
      const simHintsData = JSON.parse(
        fs.readFileSync(simHintsDataPath, 'utf-8'),
      );

      const tx = wasm.ReducedTransaction.sigma_parse_bytes(
        Buffer.from(simHintsData.inputs.reduced, 'base64'),
      );
      const first = simHintsData.simHints;
      const toAdd = JSON.parse(
        fs.readFileSync(
          path.join(__dirname, 'data', 'toAddHints.json'),
          'utf-8',
        ),
      );
      const combined = JSON.parse(
        fs.readFileSync(
          path.join(__dirname, 'data', 'addedHints.json'),
          'utf-8',
        ),
      );

      const hints = wasm.TransactionHintsBag.from_json(JSON.stringify(toAdd));
      MultiSigUtils.add_hints(
        hints,
        wasm.TransactionHintsBag.from_json(JSON.stringify(first)),
        tx.unsigned_tx().inputs().len(),
      );

      const expectedSimHints = wasm.TransactionHintsBag.from_json(
        JSON.stringify(combined),
      );
      expect(hints.to_json()).toEqual(expectedSimHints.to_json());
    });
  });

  describe('publishedCommitmentsToHintBag', () => {
    /**
     * @target MultiSigUtils.publishedCommitmentsToHintBag should correctly convert published commitments to hint bag
     * @dependencies
     * - ergo-lib-wasm-nodejs
     * - fs
     * @scenario
     * - Read the publishData from the JSON file
     * - Create necessary objects from the data
     * - Call publishedCommitmentsToHintBag with the prepared data
     * - Compare the result with the expected hints
     * @expected
     * - The converted hint bag should match the expected hints from the JSON file
     */
    it('should correctly convert published commitments to hint bag', () => {
      // Read the publishData from the JSON file
      const publishDataPath = path.join(__dirname, 'data', 'publishData.json');
      const publishData = JSON.parse(fs.readFileSync(publishDataPath, 'utf-8'));

      const cmts = publishData.cmts;
      const pubs = publishData.pubs;
      const tx = wasm.ReducedTransaction.sigma_parse_bytes(
        Buffer.from(publishData.tx, 'base64'),
      );

      const inputLen = tx.unsigned_tx().inputs().len();
      const result = MultiSigUtils.publishedCommitmentsToHintBag(
        cmts,
        pubs,
        inputLen,
      );

      const expectedHints = wasm.TransactionHintsBag.from_json(
        JSON.stringify(publishData.hints),
      );
      expect(result.to_json()).toEqual(expectedHints.to_json());
    });
  });

  describe('publishedProofsToHintBag', () => {
    /**
     * @target MultiSigUtils.publishedProofsToHintBag should correctly convert published proofs to hint bag
     * @dependencies
     * - ergo-lib-wasm-nodejs
     * - fs
     * @scenario
     * - Read the publishedProofData from the JSON file
     * - Create necessary objects from the data
     * - Call publishedProofsToHintBag with the prepared data
     * - Compare the result with the expected proofs
     * @expected
     * - The converted hint bag should match the expected proofs from the JSON file
     */
    it('should correctly convert published proofs to hint bag', () => {
      // Read the publishedProofData from the JSON file
      const publishedProofDataPath = path.join(
        __dirname,
        'data',
        'publishedProofData.json',
      );
      const publishedProofData = JSON.parse(
        fs.readFileSync(publishedProofDataPath, 'utf-8'),
      );

      const inpProofs = publishedProofData.inpProofs;
      const pubs = publishedProofData.pubs;
      const tx = wasm.ReducedTransaction.sigma_parse_bytes(
        Buffer.from(publishedProofData.tx, 'base64'),
      );

      const inputLen = tx.unsigned_tx().inputs().len();
      const result = MultiSigUtils.publishedProofsToHintBag(
        inpProofs,
        pubs,
        inputLen,
        'proofSimulated',
      );

      const expectedProofs = wasm.TransactionHintsBag.from_json(
        JSON.stringify(publishedProofData.proofs),
      );
      expect(result.to_json()).toEqual(expectedProofs.to_json());
    });
  });

  describe('toReducedPublishedCommitments', () => {
    /**
     * @target MultiSigUtils.toReducedPublishedCommitments should correctly convert secret to reduced published commitments
     * @dependencies
     * - ergo-lib-wasm-nodejs
     * - fs
     * @scenario
     * - Read the reducedCommitmentData from the JSON file
     * - Create necessary objects from the data
     * - Call toReducedPublishedCommitments with the prepared data
     * - Compare the result with the expected commitments
     * @expected
     * - The reduced published commitments should match the expected commitments from the JSON file
     */
    it('should correctly convert secret to reduced published commitments', () => {
      // Read the reducedCommitmentData from the JSON file
      const reducedCommitmentDataPath = path.join(
        __dirname,
        'data',
        'reducedCommitmentData.json',
      );
      const reducedCommitmentData = JSON.parse(
        fs.readFileSync(reducedCommitmentDataPath, 'utf-8'),
      );

      const secret = wasm.TransactionHintsBag.from_json(
        JSON.stringify(reducedCommitmentData.secret),
      );
      const myPub = reducedCommitmentData.pub;

      const result = MultiSigUtils.toReducedPublishedCommitments(secret, myPub);

      expect(result).toEqual(reducedCommitmentData.cmts);
    });
  });

  describe('toReducedPublishedCommitmentsArray', () => {
    /**
     * @target MultiSigUtils.toReducedPublishedCommitmentsArray should correctly convert hints to reduced published commitments array
     * @dependencies
     * - ergo-lib-wasm-nodejs
     * - fs
     * @scenario
     * - Read the simHintsPublishData from the JSON file
     * - Create necessary objects from the data
     * - Call toReducedPublishedCommitmentsArray with the prepared data
     * - Compare the result with the expected commitments array
     * @expected
     * - The reduced published commitments array should match the expected array from the JSON file
     */
    it('should correctly convert hints to reduced published commitments array', () => {
      // Read the simHintsPublishData from the JSON file
      const simHintsPublishDataPath = path.join(
        __dirname,
        'data',
        'simHintsPublishData.json',
      );
      const simHintsPublishData = JSON.parse(
        fs.readFileSync(simHintsPublishDataPath, 'utf-8'),
      );

      const simHints = wasm.TransactionHintsBag.from_json(
        JSON.stringify(simHintsPublishData.hints),
      );
      const simulated = simHintsPublishData.pubs;

      const result = MultiSigUtils.toReducedPublishedCommitmentsArray(
        simHints,
        simulated,
      );

      expect(result).toEqual(simHintsPublishData.cmts);
    });
  });

  describe('hintBagToPublishedProof', () => {
    /**
     * @target MultiSigUtils.hintBagToPublishedProof should correctly convert hint bag to published proof
     * @dependencies
     * - ergo-lib-wasm-nodejs
     * - fs
     * @scenario
     * - Read the publishedProofData from the JSON file
     * - Create necessary objects from the data
     * - Call hintBagToPublishedProof with the prepared data
     * - Compare the result with the expected proof
     * @expected
     * - The published proof should match the expected proof from the JSON file
     */
    it('should correctly convert hint bag to published proof', () => {
      // Read the publishedProofData from the JSON file
      const publishedProofDataPath = path.join(
        __dirname,
        'data',
        'publishedProofData2.json',
      );
      const publishedProofData = JSON.parse(
        fs.readFileSync(publishedProofDataPath, 'utf-8'),
      );

      const myHint = wasm.TransactionHintsBag.from_json(
        JSON.stringify(publishedProofData.hints),
      );
      const myPub = publishedProofData.pub;

      const result = MultiSigUtils.hintBagToPublishedProof(myHint, myPub);

      expect(result).toEqual(publishedProofData.proof);
    });
  });

  describe('toReducedPublishedProofsArray', () => {
    /**
     * @target MultiSigUtils.toReducedPublishedProofsArray should correctly convert hints to reduced published proofs array
     * @dependencies
     * - ergo-lib-wasm-nodejs
     * - fs
     * @scenario
     * - Read the simPublishedProofsData from the JSON file
     * - Create necessary objects from the data
     * - Call toReducedPublishedProofsArray with the prepared data
     * - Compare the result with the expected proofs array
     * @expected
     * - The reduced published proofs array should match the expected array from the JSON file
     */
    it('should correctly convert hints to reduced published proofs array', () => {
      // Read the simPublishedProofsData from the JSON file
      const simPublishedProofsDataPath = path.join(
        __dirname,
        'data',
        'simPublishedProofsData.json',
      );
      const simPublishedProofsData = JSON.parse(
        fs.readFileSync(simPublishedProofsDataPath, 'utf-8'),
      );

      const simHints = wasm.TransactionHintsBag.from_json(
        JSON.stringify(simPublishedProofsData.hints),
      );
      const simulated = simPublishedProofsData.pubs;

      const result = MultiSigUtils.toReducedPublishedProofsArray(
        simHints,
        simulated,
      );

      expect(result).toEqual(simPublishedProofsData.proofs);
    });
  });

  describe('verifyInput', () => {
    /**
     * @target MultiSigUtils.verifyInput should correctly verify a valid transaction input
     * @dependencies
     * - ergo-lib-wasm-nodejs
     * - fs
     * @scenario
     * - Read the validTxData from the JSON file
     * - Create necessary objects from the data
     * - Create a MultiSigUtils instance with a mock getStateContext function
     * - Call verifyInput with the prepared data
     * - Check if the result is true
     * @expected
     * - The verifyInput function should return true for a valid transaction input
     */
    it('should correctly verify a valid transaction input', async () => {
      // Read the validTxData from the JSON file
      const validTxDataPath = path.join(__dirname, 'data', 'validTxData.json');
      const validTxData = JSON.parse(fs.readFileSync(validTxDataPath, 'utf-8'));

      const tx = wasm.Transaction.sigma_parse_bytes(
        Buffer.from(validTxData.tx, 'base64'),
      );
      const boxes = validTxData.boxes.map((box: string) =>
        wasm.ErgoBox.from_json(JSON.stringify(box)),
      );

      const multiSigUtilsInstance = new MultiSigUtils(async () => {
        return mockedErgoStateContext;
      });

      const result = await multiSigUtilsInstance.verifyInput(tx, boxes);

      expect(result).toBe(true);
    });
  });
});
