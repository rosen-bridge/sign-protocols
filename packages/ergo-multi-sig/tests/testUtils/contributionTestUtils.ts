import * as wasm from 'ergo-lib-wasm-nodejs';
import { vi } from 'vitest';

import { GuardDetection } from '@rosen-bridge/detection';
import { ECDSA } from '@rosen-bridge/encryption';

import {
  ContributionRequest,
  ErgoMultiSigConfig,
  MultiSigUtils,
} from '../../lib';
import {
  contributionCreationHeight,
  contributionFee,
  contributionOutputValue,
  contributionRequiredSigners,
  contributionTree,
} from '../contributionTestData';
import {
  mockActiveGuards,
  mockContributionApproval,
  mockContributionSender,
  mockErgoStateContext,
  mockNativeContributionWallet,
  mockPeerId,
  mockSubmit,
  mockTransactionReject,
} from '../mocked/multiSigHandler.mock';
import {
  boxJs,
  mockedErgoStateContext,
  testPubs,
  testSecrets,
} from '../testData';
import { TestMultiSigHandler } from '../testMultiSigHandler';
import TestUtils from './testUtils';
import { getChangeBoxJs, getOutBoxJs, jsToReducedTx } from './txUtils';

/** Authorization hook accepted by contribution-validation fixtures. */
export type ContributionHook = (request: ContributionRequest) => Promise<void>;

/** Output candidate used to generate the shared reduced transaction. */
const output = getOutBoxJs(contributionTree, ['ERG', contributionOutputValue]);

/** Reduced transaction shared by the contribution-validation scenarios. */
export const contributionReduced = jsToReducedTx(
  [boxJs],
  [
    output,
    getChangeBoxJs([boxJs], [output], contributionTree, contributionFee),
  ],
  [],
  contributionCreationHeight,
  contributionFee,
);

/** Input boxes matching the shared contribution reduced transaction. */
export const contributionBoxes = [
  wasm.ErgoBox.from_json(JSON.stringify(boxJs)),
];

/** Transaction identifier matching the shared contribution fixture. */
export const contributionTxId = contributionReduced.unsigned_tx().id().to_str();

/** Same-shaped box with different serialized bytes for snapshot mutations. */
export const differentContributionBox = wasm.ErgoBox.from_box_candidate(
  contributionReduced.unsigned_tx().output_candidates().get(0),
  contributionReduced.unsigned_tx().id(),
  0,
);

/**
 * Build a focused handler fixture with observable native operations and an
 * inert outbound sender.
 */
export const generateContributionFixture = async (
  hook?: ContributionHook,
  index = 0,
) => {
  vi.setSystemTime(0);
  const messageEnc = new ECDSA(testSecrets[index]);
  const submit = mockSubmit();
  const guardDetection = new GuardDetection({
    guardsPublicKey: testPubs,
    messageEnc,
    submit,
    getPeerId: mockPeerId(testPubs[index]),
  });
  mockActiveGuards(guardDetection, testPubs);
  const utils = new MultiSigUtils(mockErgoStateContext(mockedErgoStateContext));
  const config: ErgoMultiSigConfig = {
    multiSigUtilsInstance: utils,
    messageEnc,
    secretHex: testSecrets[index],
    txSignTimeout: 60,
    submit,
    guardDetection,
    commGuardsPk: [...testPubs],
    ergoGuardPks: [...testPubs],
    beforeContribution: hook,
  };
  const handler = new TestMultiSigHandler(config);
  await TestUtils.addTx(
    handler,
    contributionReduced,
    contributionRequiredSigners,
    [...contributionBoxes],
    [],
  );
  const { transaction, release } =
    await handler.getQueuedTransaction(contributionTxId);
  release();
  const reject = mockTransactionReject();
  transaction.reject = reject;
  const { commitments, signs } = mockNativeContributionWallet(
    handler,
    testSecrets[index],
  );
  const send = mockContributionSender(handler);
  return {
    handler,
    transaction,
    reject,
    commitments,
    signs,
    utils,
    submit,
    send,
  };
};

/** Build six contribution fixtures and preload five coordinator commitments. */
export const generateContributionCommittee = async (hook: ContributionHook) => {
  const members = await Promise.all(
    testSecrets
      .slice(0, contributionRequiredSigners)
      .map((_, index) => generateContributionFixture(hook, index)),
  );
  for (const member of members)
    await member.handler.generateCommitment(contributionTxId, 0);
  /** Deliver one member's published commitment to the coordinator. */
  const deliver = (index: number) =>
    members[0].handler.handleCommitment(
      testPubs[index],
      {
        txId: contributionTxId,
        commitment: members[index].transaction.commitments[testPubs[index]],
      },
      'test-envelope-verified-upstream',
      index,
    );
  for (let index = 1; index < 5; index++) await deliver(index);
  return { members, deliver };
};

/**
 * Build a handler fixture that retains the real communicator transport and
 * signer while replacing only the outbound network sink.
 */
export const generateTransportFixture = async (
  index = 0,
  hook: ContributionHook = mockContributionApproval(),
) => {
  vi.setSystemTime(0);
  const messageEnc = new ECDSA(testSecrets[index]);
  const submit = mockSubmit();
  const detection = new GuardDetection({
    guardsPublicKey: testPubs,
    messageEnc,
    submit,
    getPeerId: mockPeerId(testPubs[index]),
  });
  mockActiveGuards(detection, testPubs);
  const handler = new TestMultiSigHandler({
    multiSigUtilsInstance: new MultiSigUtils(
      mockErgoStateContext(mockedErgoStateContext),
    ),
    messageEnc,
    secretHex: testSecrets[index],
    txSignTimeout: 60,
    turnTime: 60,
    submit,
    guardDetection: detection,
    commGuardsPk: [...testPubs],
    ergoGuardPks: [...testPubs],
    beforeContribution: hook,
  });
  await TestUtils.addTx(
    handler,
    contributionReduced,
    contributionRequiredSigners,
    [...contributionBoxes],
    [],
  );
  const { transaction, release } =
    await handler.getQueuedTransaction(contributionTxId);
  release();
  transaction.reject = mockTransactionReject();
  return { handler, messageEnc, submit, transaction };
};

/** Build a six-member transport group awaiting its final commitment. */
export const generateTransportSigningGroup = async (
  hook?: ContributionHook,
) => {
  const members = await Promise.all(
    testSecrets
      .slice(0, contributionRequiredSigners)
      .map((_, index) => generateTransportFixture(index, hook)),
  );
  for (const member of members)
    await member.handler.generateCommitment(contributionTxId, 0);
  const coordinator = members[0];
  /** Deliver one member's published commitment to the transport coordinator. */
  const addCommitment = (index: number) =>
    coordinator.handler.handleCommitment(
      testPubs[index],
      {
        txId: contributionTxId,
        commitment: members[index].transaction.commitments[testPubs[index]],
      },
      'already-verified-test-envelope',
      index,
    );
  for (let index = 1; index < members.length - 1; index++)
    await addCommitment(index);
  coordinator.submit.mockClear();
  /** Deliver the final commitment that starts coordinator signing. */
  const finish = () => addCommitment(members.length - 1);
  return {
    members,
    coordinator,
    finish,
  };
};
