import * as wasm from 'ergo-lib-wasm-nodejs';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { GuardDetection } from '@rosen-bridge/detection';
import { ECDSA } from '@rosen-bridge/encryption';

import {
  ContributionRequest,
  ErgoMultiSigConfig,
  InitiateSignPayload,
  MessageType,
  MultiSigHandler,
  MultiSigUtils,
  TxQueued,
} from '../lib';
import { turnTime } from '../lib/const';
import {
  boxJs,
  mockedErgoStateContext,
  testPubs,
  testSecrets,
} from './testData';
import TestUtils from './testUtils/testUtils';
import {
  getChangeBoxJs,
  getOutBoxJs,
  jsToReducedTx,
} from './testUtils/txUtils';

const tree =
  '0008cd03e5bedab3f782ef17a73e9bdc41ee0e18c3ab477400f35bcf7caa54171db7ff36';
const out = getOutBoxJs(tree, ['ERG', 10000000]);
const reduced = jsToReducedTx(
  [boxJs],
  [out, getChangeBoxJs([boxJs], [out], tree, 1000000)],
  [],
  1311604,
  1000000,
);
const boxes = [wasm.ErgoBox.from_json(JSON.stringify(boxJs))];
const txId = reduced.unsigned_tx().id().to_str();
const differentBox = wasm.ErgoBox.from_box_candidate(
  reduced.unsigned_tx().output_candidates().get(0),
  reduced.unsigned_tx().id(),
  0,
);

type Hook = (request: ContributionRequest) => Promise<void>;

async function fixture(hook?: Hook, index = 0) {
  vi.setSystemTime(0);
  const messageEnc = new ECDSA(testSecrets[index]);
  const submit = vi.fn();
  const guardDetection = new GuardDetection({
    guardsPublicKey: testPubs,
    messageEnc,
    submit,
    getPeerId: async () => testPubs[index],
  });
  guardDetection.activeGuards = async () =>
    testPubs.map((publicKey, index) => ({
      publicKey,
      peerId: publicKey,
      index,
    }));
  const utils = new MultiSigUtils(async () => mockedErgoStateContext);
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
  const handler = new MultiSigHandler(config);
  await TestUtils.addTx(handler, reduced, 6, [...boxes], []);
  const { transaction, release } = await handler.getQueuedTransaction(txId);
  release();
  const reject = vi.fn();
  transaction.reject = reject;
  // Wrap this guard's real native wallet; simulated empty-prover calls are excluded.
  const wallet = wasm.Wallet.from_secrets(
    (() => {
      const keys = new wasm.SecretKeys();
      keys.add(
        wasm.SecretKey.dlog_from_bytes(Buffer.from(testSecrets[index], 'hex')),
      );
      return keys;
    })(),
  );
  const commitments = vi.spyOn(
    wallet,
    'generate_commitments_for_reduced_transaction',
  );
  const signs = vi.spyOn(wallet, 'sign_reduced_transaction_multi');
  // Private implementation access is limited to installing the counting native wallet.
  Object.assign(handler, { prover: wallet });
  const send = vi.fn<(type: MessageType, payload: unknown) => Promise<void>>(
    async () => {},
  );
  Object.assign(handler, { sendMessage: send });
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
}

async function committee(hook: Hook) {
  const members = await Promise.all(
    testSecrets.slice(0, 6).map((_, i) => fixture(hook, i)),
  );
  for (const member of members)
    await member.handler.generateCommitment(txId, 0);
  const deliver = (i: number) =>
    members[0].handler.handleCommitment(
      testPubs[i],
      { txId, commitment: members[i].transaction.commitments[testPubs[i]] },
      'test-envelope-verified-upstream',
      i,
    );
  for (let i = 1; i < 5; i++) await deliver(i);
  return { members, deliver };
}

afterEach(() => {
  vi.restoreAllMocks();
  vi.useRealTimers();
});

describe('contribution validation', () => {
  it('refuses a queued commitment before any native secret operation and rejects immediately', async () => {
    const failure = Error('source proof removed');
    const f = await fixture(async () => {
      throw failure;
    });
    await expect(f.handler.generateCommitment(txId)).rejects.toThrow(failure);
    expect(f.commitments).not.toHaveBeenCalled();
    expect(f.signs).not.toHaveBeenCalled();
    expect(f.reject).toHaveBeenCalledWith(failure);
  });

  it('passes a frozen exact request and permits a real native commitment', async () => {
    const hook = vi.fn(async (request) => {
      expect(Object.isFrozen(request)).toBe(true);
      expect(request).toEqual({
        txId,
        kind: 'commitment',
        reducedHex: Buffer.from(reduced.sigma_serialize_bytes()).toString(
          'hex',
        ),
      });
    });
    const f = await fixture(hook);
    await f.handler.generateCommitment(txId);
    expect(hook).toHaveBeenCalledTimes(1);
    expect(f.commitments).toHaveBeenCalledTimes(1);
    expect(f.transaction.secret).toBeDefined();
  });

  it('retains the synchronous native path when no hook is configured', async () => {
    const f = await fixture();
    const pending = f.handler.generateCommitment(txId);
    expect(f.commitments).toHaveBeenCalledTimes(1);
    await pending;
  });

  it.each([
    'queue',
    'transaction',
    'coordinator',
    'round',
    'roundCommitments',
    'roundSigns',
    'secret',
    'turn',
    'threshold',
    'committee',
    'boxes',
    'dataBoxes',
    'boxesContent',
    'dataBoxesContent',
    'boxesBytes',
    'dataBoxesBytes',
  ] as const)(
    'blocks a changed %s while authorization is pending',
    async (changed) => {
      const entered = Promise.withResolvers<void>();
      const resume = Promise.withResolvers<void>();
      const f = await fixture(async () => {
        entered.resolve();
        await resume.promise;
      });
      if (changed === 'dataBoxesBytes') f.transaction.dataBoxes.push(boxes[0]);
      const pending = f.handler.generateCommitment(txId);
      await entered.promise;
      switch (changed) {
        case 'queue':
          (
            f.handler as unknown as { transactions: Map<string, TxQueued> }
          ).transactions.set(txId, { ...f.transaction });
          break;
        case 'transaction':
          f.transaction.tx = wasm.ReducedTransaction.sigma_parse_bytes(
            reduced.sigma_serialize_bytes(),
          );
          break;
        case 'coordinator':
          f.transaction.coordinator = 1;
          break;
        case 'round':
          (
            f.handler as unknown as {
              cleanTxState: (transaction: TxQueued) => void;
            }
          ).cleanTxState(f.transaction);
          break;
        case 'secret':
          f.transaction.secret = wasm.TransactionHintsBag.empty();
          break;
        case 'roundCommitments':
          f.transaction.commitments = {};
          break;
        case 'roundSigns':
          f.transaction.signs = {};
          break;
        case 'turn':
          vi.setSystemTime(turnTime * 1000);
          break;
        case 'threshold':
          f.transaction.requiredSigner++;
          break;
        case 'committee':
          f.handler.handlePublicKeysChange([...testPubs].reverse());
          break;
        case 'boxes':
          f.transaction.boxes = [...boxes];
          break;
        case 'dataBoxes':
          f.transaction.dataBoxes = [];
          break;
        case 'boxesContent':
          f.transaction.boxes.push(boxes[0]);
          break;
        case 'dataBoxesContent':
          f.transaction.dataBoxes.push(boxes[0]);
          break;
        case 'boxesBytes':
          f.transaction.boxes[0] = differentBox;
          break;
        case 'dataBoxesBytes':
          f.transaction.dataBoxes[0] = differentBox;
          break;
      }
      resume.resolve();
      await expect(pending).rejects.toThrow('Contribution state changed');
      expect(f.commitments).not.toHaveBeenCalled();
      expect(f.signs).not.toHaveBeenCalled();
      expect(f.reject).toHaveBeenCalledWith(
        expect.objectContaining({ message: 'Contribution state changed' }),
      );
    },
  );

  it('revalidates after simulated hint extraction and creates no coordinator partial on refusal', async () => {
    let valid = true;
    const hook = vi.fn(async () => {
      if (!valid) throw Error('proof disappeared');
    });
    const { members, deliver } = await committee(hook);
    const coordinator = members[0];
    const entered = Promise.withResolvers<void>();
    const resume = Promise.withResolvers<void>();
    const extract = coordinator.utils.extract_hints.bind(coordinator.utils);
    vi.spyOn(coordinator.utils, 'extract_hints').mockImplementationOnce(
      async (...args) => {
        entered.resolve();
        await resume.promise;
        return extract(...args);
      },
    );
    const pending = deliver(5);
    await entered.promise;
    expect(hook).toHaveBeenCalledTimes(6);
    valid = false;
    resume.resolve();
    await pending;
    expect(hook).toHaveBeenCalledTimes(7);
    expect(coordinator.signs).not.toHaveBeenCalled();
    expect(coordinator.reject).toHaveBeenCalledWith(
      expect.objectContaining({ message: 'proof disappeared' }),
    );
    expect(coordinator.send).not.toHaveBeenCalledWith(
      MessageType.InitiateSign,
      expect.anything(),
      expect.anything(),
      expect.anything(),
    );
    expect(members.map((m) => m.commitments.mock.calls.length)).toEqual([
      1, 1, 1, 1, 1, 1,
    ]);
  });

  it('refuses a peer partial without claiming to retract the coordinator partial', async () => {
    let valid = true;
    const { members, deliver } = await committee(async () => {
      if (!valid) throw Error('source spent');
    });
    await deliver(5);
    expect(members[0].signs).toHaveBeenCalledTimes(1);
    const payload = members[0].send.mock.calls.find(
      (call) => call[0] === MessageType.InitiateSign,
    )![1] as InitiateSignPayload;
    valid = false;
    await members[1].handler.initiateSign(testPubs[0], payload, 0);
    expect(members[1].signs).not.toHaveBeenCalled();
    expect(members[1].reject).toHaveBeenCalledWith(
      expect.objectContaining({ message: 'source spent' }),
    );
    expect(members[0].signs).toHaveBeenCalledTimes(1);
  });

  it('permits real native partials at both signing sites when verification succeeds', async () => {
    const hook = vi.fn(async () => {});
    const { members, deliver } = await committee(hook);
    await deliver(5);
    const payload = members[0].send.mock.calls.find(
      (call) => call[0] === MessageType.InitiateSign,
    )![1] as InitiateSignPayload;
    for (let i = 1; i < members.length; i++)
      await members[i].handler.initiateSign(testPubs[0], payload, 0);
    expect(members.map((m) => m.signs.mock.calls.length)).toEqual([
      1, 1, 1, 1, 1, 1,
    ]);
    expect(hook).toHaveBeenCalledTimes(12);
    expect(members.every((m) => m.reject.mock.calls.length === 0)).toBe(true);
  });

  it.each(['coordinator-sign', 'peer-sign'] as const)(
    'blocks %s if its round changes during authorization',
    async (kind) => {
      const entered = Promise.withResolvers<void>();
      const resume = Promise.withResolvers<void>();
      const { members, deliver } = await committee(async (request) => {
        if (request.kind === kind) {
          entered.resolve();
          await resume.promise;
        }
      });
      let pending: Promise<void>;
      const target = members[kind === 'coordinator-sign' ? 0 : 1];
      if (kind === 'coordinator-sign') pending = deliver(5);
      else {
        await deliver(5);
        const payload = members[0].send.mock.calls.find(
          (call) => call[0] === MessageType.InitiateSign,
        )![1] as InitiateSignPayload;
        pending = target.handler.initiateSign(testPubs[0], payload, 0);
      }
      await entered.promise;
      target.transaction.coordinator = 1;
      resume.resolve();
      await pending;
      expect(target.signs).not.toHaveBeenCalled();
      expect(target.reject).toHaveBeenCalledWith(
        expect.objectContaining({ message: 'Contribution state changed' }),
      );
    },
  );

  it('rejects a round replaced during simulated hint extraction before consulting authorization', async () => {
    const hook = vi.fn(async () => {});
    const { members, deliver } = await committee(hook);
    const coordinator = members[0];
    const entered = Promise.withResolvers<void>();
    const resume = Promise.withResolvers<void>();
    const extract = coordinator.utils.extract_hints.bind(coordinator.utils);
    vi.spyOn(coordinator.utils, 'extract_hints').mockImplementationOnce(
      async (...args) => {
        entered.resolve();
        await resume.promise;
        return extract(...args);
      },
    );
    const pending = deliver(5);
    await entered.promise;
    coordinator.transaction.commitments = {};
    resume.resolve();
    await pending;
    expect(hook).toHaveBeenCalledTimes(6);
    expect(coordinator.signs).not.toHaveBeenCalled();
    expect(coordinator.reject).toHaveBeenCalledWith(
      expect.objectContaining({ message: 'Contribution state changed' }),
    );
  });

  it('does not revive a refused queue entry on a later contribution request', async () => {
    let valid = false;
    const f = await fixture(async () => {
      if (!valid) throw Error('source invalid');
    });
    await expect(f.handler.generateCommitment(txId)).rejects.toThrow(
      'source invalid',
    );
    valid = true;
    await expect(f.handler.generateCommitment(txId)).rejects.toThrow(
      'Contribution state changed',
    );
    expect(f.commitments).not.toHaveBeenCalled();
  });

  it('rejects the actual sign promise on authorization failure without waiting for cleanup', async () => {
    const f = await fixture(async () => {
      throw Error('source invalid');
    });
    await expect(f.handler.sign(reduced, 6, boxes, [])).rejects.toThrow(
      'source invalid',
    );
    expect(f.commitments).not.toHaveBeenCalled();
  });

  it.each(['coordinator-sign', 'peer-sign'] as const)(
    'preserves the original absolute turn across the %s queue wait',
    async (kind) => {
      for (const epoch of [1, testPubs.length]) {
        const { members, deliver } = await committee(async () => {});
        const target = members[kind === 'coordinator-sign' ? 0 : 1];
        let payload: InitiateSignPayload | undefined;
        if (kind === 'peer-sign') {
          await deliver(5);
          payload = members[0].send.mock.calls.find(
            (call) => call[0] === MessageType.InitiateSign,
          )![1] as InitiateSignPayload;
        }
        const barrier =
          await target.handler.getQueuedTransaction('test-lock-barrier');
        const pending =
          kind === 'coordinator-sign'
            ? deliver(5)
            : target.handler.initiateSign(testPubs[0], payload!, 0);
        vi.setSystemTime(epoch * turnTime * 1000);
        barrier.release();
        if (kind === 'coordinator-sign')
          await expect(pending).rejects.toThrow('Contribution state changed');
        else await pending;
        expect(target.signs).not.toHaveBeenCalled();
        expect(
          target.send.mock.calls.filter((call) =>
            [MessageType.Sign, MessageType.InitiateSign].includes(call[0]),
          ),
        ).toHaveLength(0);
        expect(target.reject).toHaveBeenCalledWith(expect.any(Error));
      }
    },
  );

  it.each([1, testPubs.length])(
    'preserves turn epoch before the coordinator scheduling waits: epoch %s',
    async (epoch) => {
      const entered = Promise.withResolvers<void>();
      const resume = Promise.withResolvers<void>();
      const f = await fixture(async () => {});
      vi.spyOn(f.handler, 'getCurrentTurnId').mockImplementationOnce(
        async () => {
          entered.resolve();
          await resume.promise;
          return testPubs[0];
        },
      );
      const pending = f.handler.handleMyTurnForTx(txId);
      await entered.promise;
      vi.setSystemTime(epoch * turnTime * 1000);
      resume.resolve();
      await expect(pending).rejects.toThrow();
      expect(f.commitments).not.toHaveBeenCalled();
    },
  );

  it.each(['public-change', 'in-place'] as const)(
    'fences communication committee mutation during authorization: %s',
    async (mode) => {
      const entered = Promise.withResolvers<void>();
      const resume = Promise.withResolvers<void>();
      const f = await fixture(async () => {
        entered.resolve();
        await resume.promise;
      });
      const pending = f.handler.generateCommitment(txId);
      await entered.promise;
      if (mode === 'public-change')
        await f.handler.changePks([...testPubs].reverse());
      else (f.handler as unknown as { guardPks: string[] }).guardPks.reverse();
      resume.resolve();
      await expect(pending).rejects.toThrow();
      expect(f.commitments).not.toHaveBeenCalled();
    },
  );

  it.each([null, undefined])(
    'normalizes hook rejection %s without an unhandled sign-chain failure',
    async (reason) => {
      const f = await fixture(async () => {
        throw reason;
      });
      const unhandled: unknown[] = [];
      const observe = (error: unknown) => {
        unhandled.push(error);
      };
      process.on('unhandledRejection', observe);
      try {
        const failure = await f.handler
          .sign(reduced, 6, boxes, [])
          .catch((error) => error);
        await new Promise((resolve) => setImmediate(resolve));
        expect(failure).toBeInstanceOf(Error);
        expect(unhandled).toEqual([]);
        expect(f.commitments).not.toHaveBeenCalled();
      } finally {
        process.off('unhandledRejection', observe);
      }
    },
  );
});
