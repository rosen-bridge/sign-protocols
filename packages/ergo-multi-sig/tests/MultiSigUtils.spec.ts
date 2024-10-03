import { MultiSigUtils } from '../lib';
import { describe, expect, it } from 'vitest';
import { boxJs } from './testData';
import {
  getChangeBoxJs,
  getOutBoxJs,
  jsToReducedTx,
} from './testUtils/txUtils';
import { ErgoBox } from 'ergo-lib-wasm-nodejs';

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
});
