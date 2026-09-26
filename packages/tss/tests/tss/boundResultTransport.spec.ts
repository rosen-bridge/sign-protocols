import secp from 'secp256k1';
import { describe, expect, it, vi } from 'vitest';

import { Communicator } from '@rosen-bridge/communication';
import { GuardDetection, ActiveGuard } from '@rosen-bridge/detection';
import { EdDSA } from '@rosen-bridge/encryption';

import { boundResultTransportV1 } from '../../lib';
import { EcdsaSigner } from '../../lib/tss/ecdsaSigner';
import { BoundSignHooks, StatusEnum } from '../../lib/types/signer';

const digest = 'ab'.repeat(32);
const chain = 'cd'.repeat(32);
const secret = Buffer.from('01'.repeat(32), 'hex');
const key = Buffer.from(secp.publicKeyCreate(secret)).toString('hex');

const hooks = (): BoundSignHooks => ({
  authorize: async () => {},
  assertCurrent: () => {},
});

class InspectableSigner extends EcdsaSigner {
  queue = () => this.signs;
  pending = () => this.pendingSigns;
  api = () => this.axios;
  cache = () => this.signCache;
  clean = () => this.cleanup();
  receiveBoundCallback = (
    status: StatusEnum,
    message: string,
    signature?: string,
    signatureRecovery?: string,
    error?: string,
  ) =>
    this.handleSignData(
      status,
      message,
      signature,
      signatureRecovery,
      error,
      this.signs.find((sign) => sign.msg === message)?.boundCallbackId,
    );
  approved = () => {
    const sign = this.signs[0];
    const profile = sign.bound!.profile;
    return this.getApprovedGuards(
      sign.request!.timestamp,
      {
        msg: sign.msg,
        guards: sign.request!.guards,
        initGuardIndex: sign.request!.index,
        bound: {
          capability: 'bound-result-transport',
          version: 1,
          profileHash: profile.profileHash,
        },
      },
      sign.signs,
      profile,
    );
  };
}

class SeededGuardDetection extends GuardDetection {
  seedActiveGuards = (guards: ActiveGuard[], ownIndex: number) => {
    const now = Date.now() / 1000;
    this.guardsInfo = guards.map((guard) => ({
      publicKey: guard.publicKey,
      peerId: guard.index === ownIndex ? '' : guard.peerId,
      index: guard.index,
      lastUpdate: guard.index === ownIndex ? 0 : now,
      nonce: [],
      callback: [],
    }));
  };
}

interface FixtureOptions {
  creatorIndex?: number;
  holdStartFor?: number;
  holdResultFor?: number;
  autoBackend?: boolean;
  timeoutSeconds?: number;
  signCacheTTLSeconds?: number;
  signPerRoundLimit?: number;
  legacyIndex?: number;
  throwResultSender?: number;
  rejectResultSender?: number;
  throwRequestSender?: number;
  assertRequestPreparedOnSubmit?: boolean;
  realDetectionForCreator?: boolean;
  mutateDetectedGuards?: (guards: ActiveGuard[]) => ActiveGuard[];
}

async function fourSignerFixture(options: FixtureOptions = {}) {
  const creatorIndex = options.creatorIndex ?? 0;
  const enc = await Promise.all(
    Array.from({ length: 4 }, async (_, index) =>
      options.realDetectionForCreator
        ? new EdDSA((index + 1).toString(16).padStart(64, '0'))
        : new EdDSA(await EdDSA.randomKey()),
    ),
  );
  const guardKeys = await Promise.all(enc.map((item) => item.getPk()));
  const peers = guardKeys.map((_, index) => `peer-${index}`);
  const guards: ActiveGuard[] = guardKeys.map((publicKey, index) => ({
    publicKey,
    peerId: peers[index],
    index,
  }));
  const shares = ['1', '2', '3', '4'];
  const signers: InspectableSigner[] = [];
  const detections: SeededGuardDetection[] = [];
  const backendCalls: number[] = [];
  const wire: Array<{
    sender: number;
    type: string;
    targets: number[];
    message: string;
  }> = [];
  const held: Array<{
    sender: number;
    target: number;
    type: string;
    message: string;
  }> = [];
  const deliveryErrors: string[] = [];
  const backendErrors: string[] = [];
  const setNextThreshold: Array<
    (implementation: () => Promise<{ data: { threshold: number } }>) => void
  > = [];
  const now = [1_790_000_000, 1_790_000_000, 1_790_000_000, 1_790_000_000];
  const signed = secp.ecdsaSign(Buffer.from(digest, 'hex'), secret);
  const result = {
    signature: Buffer.from(signed.signature).toString('hex'),
    signatureRecovery: signed.recid.toString(16).padStart(2, '0'),
  };

  for (let index = 0; index < 4; index++) {
    const detection = new SeededGuardDetection({
      messageEnc: enc[index],
      guardsPublicKey: guardKeys,
      submit: () => {},
      getPeerId: async () => peers[index],
    });
    if (options.realDetectionForCreator && index === creatorIndex)
      detection.seedActiveGuards(guards, index);
    else
      vi.spyOn(detection, 'activeGuards').mockResolvedValue(
        options.mutateDetectedGuards?.(guards.map((guard) => ({ ...guard }))) ??
          guards,
      );
    const signer = new InspectableSigner({
      messageEnc: enc[index],
      guardsPk: guardKeys,
      shares,
      detection,
      submitMsg: (message, recipients) => {
        const parsed = JSON.parse(message);
        if (
          parsed.type === 'request' &&
          options.assertRequestPreparedOnSubmit &&
          index === creatorIndex &&
          (!signers[index].queue()[0]?.request ||
            !signers[index].queue()[0]?.signs[index])
        )
          throw Error(
            'schema 2 request state was not prepared before emission',
          );
        if (parsed.type === 'request' && options.throwRequestSender === index)
          throw Error('request enqueue failed');
        if (
          parsed.type === 'bound-result-v1' &&
          options.throwResultSender === index
        )
          throw Error('result enqueue failed');
        if (
          parsed.type === 'bound-result-v1' &&
          options.rejectResultSender === index
        )
          return Promise.reject(Error('async result enqueue failed'));
        const targets = recipients.length
          ? recipients.map((peer) => peers.indexOf(peer))
          : [0, 1, 2, 3].filter((target) => target !== index);
        wire.push({
          sender: index,
          type: parsed.type,
          targets,
          message,
        });
        for (const target of targets) {
          if (
            (parsed.type === 'start' && options.holdStartFor === target) ||
            (parsed.type === 'bound-result-v1' &&
              options.holdResultFor === target)
          ) {
            held.push({
              sender: index,
              target,
              type: parsed.type,
              message,
            });
            continue;
          }
          setTimeout(() => {
            void signers[target]
              .handleMessage(message, peers[index])
              .catch((error) => deliveryErrors.push(String(error)));
          }, 0);
        }
      },
      callbackUrl: '',
      tssApiUrl: '',
      getPeerId: async () => peers[index],
      turnNoWorkSeconds: 0.001,
      timeoutSeconds: options.timeoutSeconds,
      signCacheTTLSeconds: options.signCacheTTLSeconds,
      signPerRoundLimit: options.signPerRoundLimit,
    });
    vi.spyOn(signer, 'getGuardTurn').mockReturnValue(creatorIndex);
    vi.spyOn(signer as never, 'getDate').mockImplementation(() => now[index]);
    const getMock = vi.spyOn(signer.api(), 'get').mockResolvedValue({
      data: { threshold: 2 },
    });
    setNextThreshold[index] = (implementation) => {
      getMock.mockImplementationOnce(implementation as never);
    };
    vi.spyOn(signer.api(), 'post').mockImplementation(async (url) => {
      if (url === 'getPK') return { data: { publicKey: key } };
      if (url === 'sign') {
        backendCalls.push(index);
        if (options.autoBackend !== false)
          queueMicrotask(() => {
            void signer
              .receiveBoundCallback(
                StatusEnum.Success,
                digest,
                result.signature,
                result.signatureRecovery,
              )
              .catch((error) => backendErrors.push(String(error)));
          });
      }
      return { data: {} };
    });
    signers.push(signer);
    detections.push(detection);
  }
  const profiles = await Promise.all(
    signers.map((signer, index) =>
      signer.prepareBoundProfile(
        chain,
        [1],
        options.legacyIndex === index ? undefined : boundResultTransportV1,
      ),
    ),
  );
  const makeMessage = async (
    sender: number,
    type: string,
    payload: object,
    timestamp = now[sender],
  ) => {
    const signature = await enc[sender].sign(
      Communicator.generatePayloadToSign(
        payload,
        timestamp,
        guardKeys[sender],
        profiles[sender].protocolVersion,
      ),
    );
    return JSON.stringify({
      type,
      payload,
      publicKey: guardKeys[sender],
      timestamp,
      sign: signature,
      index: sender,
      version: profiles[sender].protocolVersion,
    });
  };
  return {
    signers,
    detections,
    profiles,
    backendCalls,
    result,
    wire,
    held,
    deliveryErrors,
    backendErrors,
    setNextThreshold,
    guards,
    peers,
    now,
    makeMessage,
  };
}

async function queueAll(
  f: Awaited<ReturnType<typeof fourSignerFixture>>,
  customHooks?: BoundSignHooks[],
) {
  const pending = f.signers.map((signer, index) =>
    signer.signBoundPromised(
      digest,
      f.profiles[index],
      customHooks?.[index] ?? hooks(),
    ),
  );
  for (const result of pending) void result.catch(() => {});
  await vi.waitFor(() =>
    expect(f.signers.every((signer) => signer.queue().length === 1)).toBe(true),
  );
  return pending;
}

async function deliver(
  f: Awaited<ReturnType<typeof fourSignerFixture>>,
  item: (typeof f.held)[number],
  peer = f.peers[item.sender],
) {
  return f.signers[item.target].handleMessage(item.message, peer);
}

async function preparedStandby() {
  const f = await fourSignerFixture({ holdResultFor: 3 });
  const pending = await queueAll(f);
  await f.signers[0].update();
  await vi.waitFor(() =>
    expect(f.signers[3].queue()[0]?.boundResultOnly).toBe(true),
  );
  await vi.waitFor(() =>
    expect(
      f.held.filter((item) => item.type === 'bound-result-v1').length,
    ).toBeGreaterThan(0),
  );
  const valid = f.held.find((item) => item.type === 'bound-result-v1')!;
  return { f, pending, valid, payload: JSON.parse(valid.message).payload };
}

async function preparedRetiringStandby() {
  const f = await fourSignerFixture({ holdResultFor: 3 });
  let authorizeCalls = 0;
  let retired = false;
  let releaseFirst!: () => void;
  let releaseLate!: () => void;
  const firstGate = new Promise<void>((resolve) => {
    releaseFirst = resolve;
  });
  const lateGate = new Promise<void>((resolve) => {
    releaseLate = resolve;
  });
  const standbyHooks: BoundSignHooks = {
    authorize: async (_profile, stage) => {
      if (stage !== 'result') return;
      authorizeCalls += 1;
      await (authorizeCalls === 1 ? firstGate : lateGate);
      if (retired) throw Error('result authority retired');
    },
    assertCurrent: (_profile, stage) => {
      if (stage === 'result' && retired)
        throw Error('result authority retired');
    },
  };
  const pending = await queueAll(f, [hooks(), hooks(), hooks(), standbyHooks]);
  void pending[3].then(() => {
    retired = true;
    releaseLate();
  });
  await f.signers[0].update();
  await vi.waitFor(() =>
    expect(f.signers[3].queue()[0]?.boundResultOnly).toBe(true),
  );
  await vi.waitFor(() =>
    expect(
      f.held.filter((item) => item.type === 'bound-result-v1').length,
    ).toBeGreaterThan(0),
  );
  return {
    f,
    pending,
    valid: f.held.find((item) => item.type === 'bound-result-v1')!,
    releaseFirst,
    authorizeCalls: () => authorizeCalls,
  };
}

describe('bound result transport v1', () => {
  it('retries a restored full roster in the same round exactly once with a late fourth local queue', async () => {
    const f = await fourSignerFixture();
    const detected = vi.mocked(f.detections[0].activeGuards);
    detected.mockResolvedValueOnce(f.guards.slice(0, 3));
    detected.mockResolvedValue(f.guards);
    const pending = f.signers
      .slice(0, 3)
      .map((signer, index) =>
        signer.signBoundPromised(digest, f.profiles[index], hooks()),
      );
    pending.forEach((result) => void result.catch(() => {}));
    await vi.waitFor(() =>
      expect(
        f.signers.slice(0, 3).every((signer) => signer.queue().length === 1),
      ).toBe(true),
    );
    await f.signers[0].update();
    expect(f.wire.filter((message) => message.type === 'request')).toHaveLength(
      0,
    );
    expect(f.signers[0].queue()[0].request).toBeUndefined();
    await Promise.all([f.signers[0].update(), f.signers[0].update()]);
    await vi.waitFor(() => expect(f.signers[3].pending()).toHaveLength(1));
    const late = f.signers[3].signBoundPromised(digest, f.profiles[3], hooks());
    void late.catch(() => {});
    await expect(Promise.all([...pending, late])).resolves.toEqual(
      Array.from({ length: 4 }, () => f.result),
    );
    expect(f.wire.filter((message) => message.type === 'request')).toHaveLength(
      1,
    );
    expect(f.backendCalls.sort()).toEqual([0, 1, 2]);
    await f.signers[0].update();
    expect(f.wire.filter((message) => message.type === 'request')).toHaveLength(
      1,
    );
  });

  it('applies the per-round limit after retained terminal operations are excluded', async () => {
    const f = await fourSignerFixture({
      timeoutSeconds: 1,
      signPerRoundLimit: 1,
      autoBackend: false,
    });
    const expired = f.signers[0].signBoundPromised(
      'ef'.repeat(32),
      f.profiles[0],
      hooks(),
    );
    void expired.catch(() => {});
    await vi.waitFor(() => expect(f.signers[0].queue()).toHaveLength(1));
    f.now[0] += 2;
    await f.signers[0].clean();
    await expect(expired).rejects.toBe('Bound signing timed out');
    expect(f.signers[0].queue()[0]).toMatchObject({
      boundFailed: true,
      boundSettled: true,
    });

    const eligible = f.signers[0].signBoundPromised(
      digest,
      f.profiles[0],
      hooks(),
    );
    void eligible.catch(() => {});
    await vi.waitFor(() => expect(f.signers[0].queue()).toHaveLength(2));
    await f.signers[0].update();
    expect(
      f.wire.filter(
        (message) =>
          message.type === 'request' &&
          JSON.parse(message.message).payload.msg === digest,
      ),
    ).toHaveLength(1);
    expect(f.signers[0].queue()[1].request).toBeDefined();
  });

  it('preserves the schema 1 same-round request throttle', async () => {
    const f = await fourSignerFixture({ legacyIndex: 0, autoBackend: false });
    const pending = f.signers[0].signBoundPromised(
      digest,
      f.profiles[0],
      hooks(),
    );
    void pending.catch(() => {});
    await vi.waitFor(() => expect(f.signers[0].queue()).toHaveLength(1));
    await f.signers[0].update();
    await f.signers[0].update();
    expect(
      f.wire.filter(
        (message) => message.sender === 0 && message.type === 'request',
      ),
    ).toHaveLength(1);
  });

  it('normalizes the public-key-sorted detection set into profile order before request emission', async () => {
    const f = await fourSignerFixture({ realDetectionForCreator: true });
    const detected = await f.detections[0].activeGuards();
    const expectedDetection = [...f.guards].sort((left, right) =>
      left.publicKey.localeCompare(right.publicKey),
    );
    expect(detected).toEqual(expectedDetection);
    expect(detected.map((guard) => guard.index)).not.toEqual(
      f.guards.map((guard) => guard.index),
    );
    const pending = await queueAll(f);
    await f.signers[0].update();
    await expect(Promise.all(pending)).resolves.toEqual(
      Array.from({ length: 4 }, () => f.result),
    );
    const request = f.wire.find(
      (message) => message.sender === 0 && message.type === 'request',
    );
    expect(request).toBeDefined();
    expect(JSON.parse(request!.message).payload.guards).toEqual(f.guards);
    expect(f.signers[0].queue()[0].request!.guards).toEqual(f.guards);
    expect(f.backendCalls.sort()).toEqual([0, 1, 2]);
  });

  it.each([
    ['missing member', (guards: ActiveGuard[]) => guards.slice(0, 3)],
    [
      'duplicate index',
      (guards: ActiveGuard[]) => [guards[0], guards[1], guards[2], guards[2]],
    ],
    [
      'wrong index-to-key binding',
      (guards: ActiveGuard[]) => [
        guards[0],
        { ...guards[1], index: 3 },
        guards[2],
        { ...guards[3], index: 1 },
      ],
    ],
    [
      'duplicate peer identity',
      (guards: ActiveGuard[]) => [
        guards[0],
        guards[1],
        guards[2],
        { ...guards[3], peerId: guards[2].peerId },
      ],
    ],
  ])('refuses a detected full roster with %s', async (_, mutate) => {
    const f = await fourSignerFixture({
      mutateDetectedGuards: mutate,
      timeoutSeconds: 0.01,
    });
    const pending = await queueAll(f);
    await f.signers[0].update();
    expect(f.wire).toHaveLength(0);
    expect(f.backendCalls).toHaveLength(0);
    expect(f.signers[0].queue()[0].request).toBeUndefined();
    f.now.fill(f.now[0] + 1);
    await Promise.all(f.signers.map((signer) => signer.clean()));
    await Promise.allSettled(pending);
  });

  it('uses three controlled backends and resolves all four original promises through authenticated Communicators', async () => {
    const f = await fourSignerFixture();
    const pending = await queueAll(f);
    await f.signers[0].update();
    await vi.waitFor(() =>
      expect(f.signers[0].queue()[0]?.signs.every(Boolean)).toBe(true),
    );
    expect(await f.signers[0].approved()).toHaveLength(4);
    await vi.waitFor(() => expect(f.backendCalls).toHaveLength(3), {
      timeout: 1_000,
    });
    await vi.waitFor(() =>
      expect(f.signers[3].queue()[0]?.boundResultOnly).toBe(true),
    );
    await expect(Promise.all(pending)).resolves.toEqual(
      Array.from({ length: 4 }, () => f.result),
    );
    expect(f.backendCalls.sort()).toEqual([0, 1, 2]);
    expect(f.signers[3].queue()[0]).toMatchObject({
      posted: true,
      boundResultOnly: true,
      boundResult: f.result,
    });
    expect(f.signers[3].queue()[0].boundBackendAttempted).toBeUndefined();
    expect(
      f.wire.filter((message) => message.type === 'bound-result-v1'),
    ).toHaveLength(3);
    expect(
      f.signers.every((signer) => !Object.hasOwn(signer.cache(), digest)),
    ).toBe(true);
  });

  it('retains a schema 2 request received before the local operation is queued', async () => {
    const f = await fourSignerFixture();
    const pending = f.signers
      .slice(0, 3)
      .map((signer, index) =>
        signer.signBoundPromised(digest, f.profiles[index], hooks()),
      );
    for (const result of pending) void result.catch(() => {});
    await vi.waitFor(() =>
      expect(
        f.signers.slice(0, 3).every((signer) => signer.queue().length === 1),
      ).toBe(true),
    );
    await f.signers[0].update();
    await vi.waitFor(() => expect(f.signers[3].pending()).toHaveLength(1));
    expect(f.signers[3].pending()[0].bound).toEqual({
      capability: 'bound-result-transport',
      version: 1,
      profileHash: f.profiles[3].profileHash,
    });

    const standby = f.signers[3].signBoundPromised(
      digest,
      f.profiles[3],
      hooks(),
    );
    void standby.catch(() => {});
    pending.push(standby);

    await expect(Promise.all(pending)).resolves.toEqual(
      Array.from({ length: 4 }, () => f.result),
    );
    expect(f.backendCalls.sort()).toEqual([0, 1, 2]);
    expect(f.signers[3].queue()[0]).toMatchObject({
      posted: true,
      boundResultOnly: true,
      boundResult: f.result,
    });
  });

  it('records the creator request and own approval before synchronous emission', async () => {
    const f = await fourSignerFixture({ assertRequestPreparedOnSubmit: true });
    const pending = await queueAll(f);
    await f.signers[0].update();
    await expect(Promise.all(pending)).resolves.toEqual(
      Array.from({ length: 4 }, () => f.result),
    );
    expect(f.backendCalls.sort()).toEqual([0, 1, 2]);
  });

  it('fails the prepared operation when synchronous request enqueue throws', async () => {
    const f = await fourSignerFixture({ throwRequestSender: 0 });
    const pending = await queueAll(f);
    await expect(f.signers[0].update()).rejects.toThrow(
      'request enqueue failed',
    );
    await expect(pending[0]).rejects.toBe('request enqueue failed');
    expect(f.signers[0].queue()[0]).toMatchObject({
      boundFailed: true,
      boundSettled: true,
      posted: true,
    });
    expect(f.signers[0].queue()[0].request).toBeDefined();
    expect(f.backendCalls).toHaveLength(0);
  });

  it('does not upgrade a pending schema 1 request when schema 2 is queued later', async () => {
    const f = await fourSignerFixture({ autoBackend: false });
    const request = await f.makeMessage(0, 'request', {
      msg: digest,
      guards: f.guards,
    });
    await f.signers[3].handleMessage(request, f.peers[0]);
    expect(f.signers[3].pending()[0].bound).toBeUndefined();

    const pending = f.signers[3].signBoundPromised(
      digest,
      f.profiles[3],
      hooks(),
    );
    void pending.catch(() => {});
    await vi.waitFor(() => expect(f.signers[3].queue()).toHaveLength(1));
    expect(
      f.wire.filter(
        (message) => message.sender === 3 && message.type === 'approve',
      ),
    ).toHaveLength(0);
    expect(f.backendCalls).toHaveLength(0);
  });

  it('refuses a mismatched bound transcript retained before local queueing', async () => {
    const f = await fourSignerFixture({ autoBackend: false });
    const request = await f.makeMessage(0, 'request', {
      msg: digest,
      guards: f.guards,
      bound: {
        capability: 'bound-result-transport',
        version: 1,
        profileHash: '77'.repeat(32),
      },
    });
    await f.signers[3].handleMessage(request, f.peers[0]);
    expect(f.signers[3].pending()[0].bound?.profileHash).toBe('77'.repeat(32));

    const pending = f.signers[3].signBoundPromised(
      digest,
      f.profiles[3],
      hooks(),
    );
    void pending.catch(() => {});
    await vi.waitFor(() => expect(f.signers[3].queue()).toHaveLength(1));
    expect(
      f.wire.filter(
        (message) => message.sender === 3 && message.type === 'approve',
      ),
    ).toHaveLength(0);
    expect(f.backendCalls).toHaveLength(0);
  });

  it('makes an excluded creator immutable result-only across later turns', async () => {
    const f = await fourSignerFixture({
      creatorIndex: 3,
      holdResultFor: 3,
    });
    const pending = await queueAll(f);
    await f.signers[3].update();
    await vi.waitFor(() => expect(f.backendCalls.sort()).toEqual([0, 1, 2]));
    await vi.waitFor(() =>
      expect(f.signers[3].queue()[0]).toMatchObject({
        posted: true,
        boundResultOnly: true,
      }),
    );
    const before = f.wire.length;
    f.now.fill(f.now[0] + 10);
    await f.signers[3].update();
    f.now.fill(f.now[0] + 10);
    await f.signers[3].update();
    expect(f.wire).toHaveLength(before);
    expect(f.backendCalls).not.toContain(3);
    expect(
      f.held.filter((item) => item.type === 'bound-result-v1').length,
    ).toBeGreaterThan(0);
    await deliver(f, f.held.find((item) => item.type === 'bound-result-v1')!);
    await expect(pending[3]).resolves.toEqual(f.result);
  });

  it('buffers authenticated results until held start installs the selection', async () => {
    const f = await fourSignerFixture({
      holdStartFor: 3,
      holdResultFor: 3,
    });
    const pending = await queueAll(f);
    await f.signers[0].update();
    await vi.waitFor(() => expect(f.backendCalls.sort()).toEqual([0, 1, 2]));
    const start = f.held.find((item) => item.type === 'start')!;
    const results = f.held.filter((item) => item.type === 'bound-result-v1');
    expect(results).toHaveLength(3);
    for (const result of results) await deliver(f, result);
    expect(f.signers[3].queue()[0].boundSelection).toBeUndefined();
    expect(f.signers[3].queue()[0].boundResult).toBeUndefined();
    expect(
      f.signers[3].queue()[0].boundPendingResults?.filter(Boolean),
    ).toHaveLength(3);
    await deliver(f, start);
    expect(f.signers[3].queue()[0].boundResultOnly).toBe(true);
    expect(f.signers[3].queue()[0].boundPendingResults).toBeUndefined();
    await expect(pending[3]).resolves.toEqual(f.result);
    const before = f.wire.filter(
      (message) => message.type === 'bound-result-v1',
    ).length;
    await deliver(f, results[0]);
    expect(
      f.wire.filter((message) => message.type === 'bound-result-v1'),
    ).toHaveLength(before);
  });

  it('rejects non-string recovery before the pre-selection buffer', async () => {
    const f = await fourSignerFixture({
      holdStartFor: 3,
      holdResultFor: 3,
    });
    const pending = await queueAll(f);
    await f.signers[0].update();
    await vi.waitFor(() => expect(f.backendCalls.sort()).toEqual([0, 1, 2]));
    const start = f.held.find((item) => item.type === 'start')!;
    const valid = f.held.find((item) => item.type === 'bound-result-v1')!;
    const changed = structuredClone(JSON.parse(valid.message).payload);
    (changed as { signatureRecovery: unknown }).signatureRecovery = [
      changed.signatureRecovery,
    ];
    const arrayRecovery = await f.makeMessage(
      valid.sender,
      'bound-result-v1',
      changed,
    );

    await f.signers[3].handleMessage(arrayRecovery, f.peers[valid.sender]);
    expect(
      f.signers[3].queue()[0].boundPendingResults?.filter(Boolean) ?? [],
    ).toHaveLength(0);
    await deliver(f, valid);
    expect(
      f.signers[3].queue()[0].boundPendingResults?.filter(Boolean),
    ).toHaveLength(1);
    await deliver(f, start);
    await expect(pending[3]).resolves.toEqual(f.result);
  });

  it('clears buffered pre-selection results when the operation times out', async () => {
    const f = await fourSignerFixture({
      holdStartFor: 3,
      holdResultFor: 3,
      timeoutSeconds: 1,
    });
    const pending = await queueAll(f);
    await f.signers[0].update();
    await vi.waitFor(() => expect(f.backendCalls.sort()).toEqual([0, 1, 2]));
    const start = f.held.find((item) => item.type === 'start')!;
    const results = f.held.filter((item) => item.type === 'bound-result-v1');
    for (const result of results) await deliver(f, result);
    expect(
      f.signers[3].queue()[0].boundPendingResults?.filter(Boolean),
    ).toHaveLength(3);

    f.now[3] += 2;
    await f.signers[3].clean();
    await expect(pending[3]).rejects.toBe('Bound signing timed out');
    expect(f.signers[3].queue()[0].boundPendingResults).toBeUndefined();
    await deliver(f, start);
    expect(f.signers[3].queue()[0].boundSelection).toBeUndefined();
    expect(f.signers[3].queue()[0].boundResult).toBeUndefined();
    expect(f.backendCalls).not.toContain(3);
  });

  it('fails closed when one roster member remains on schema 1', async () => {
    const f = await fourSignerFixture({ legacyIndex: 3 });
    await queueAll(f);
    expect(f.profiles[3]).toMatchObject({ schema: 1 });
    expect(f.profiles[3].resultTransport).toBeUndefined();
    await f.signers[0].update();
    await vi.waitFor(() =>
      expect(
        f.wire.filter((message) => message.type === 'approve'),
      ).toHaveLength(2),
    );
    expect(f.backendCalls).toHaveLength(0);
    expect(f.wire.filter((message) => message.type === 'start')).toHaveLength(
      0,
    );
    expect(f.signers[0].queue()[0].boundSelection).toBeUndefined();
  });

  it.each([
    ['missing', undefined],
    [
      'downgraded',
      {
        capability: 'bound-result-transport',
        version: 0,
        profileHash: 'unused',
      },
    ],
    [
      'extra-field',
      {
        capability: 'bound-result-transport',
        version: 1,
        profileHash: 'unused',
        extra: true,
      },
    ],
  ])('rejects %s capability transcript before approval', async (_, bound) => {
    const f = await fourSignerFixture({ autoBackend: false });
    await queueAll(f);
    const transcript =
      bound === undefined
        ? undefined
        : { ...bound, profileHash: f.profiles[1].profileHash };
    const payload = {
      msg: digest,
      guards: f.guards,
      ...(transcript ? { bound: transcript } : undefined),
    };
    const message = await f.makeMessage(0, 'request', payload);
    await f.signers[1].handleMessage(message, f.peers[0]);
    expect(f.wire.filter((item) => item.type === 'approve')).toHaveLength(0);
    expect(f.signers[1].queue()[0].request).toBeUndefined();
  });

  it.each([
    'wrong-peer',
    'sender-index-mismatch',
    'unknown-sender',
    'nonselected-sender',
    'wrong-digest',
    'wrong-profile',
    'wrong-selection',
    'wrong-key',
    'wrong-recovery',
    'array-message',
    'array-selection',
    'array-signature',
    'array-recovery',
  ])('refuses authenticated result with %s', async (fault) => {
    const { f, pending, valid, payload } = await preparedStandby();
    if (fault === 'wrong-peer') {
      await deliver(f, valid, 'peer-wrong');
    } else if (
      fault === 'sender-index-mismatch' ||
      fault === 'unknown-sender'
    ) {
      const envelope = JSON.parse(valid.message);
      envelope.index = fault === 'unknown-sender' ? 99 : (valid.sender + 1) % 4;
      await f.signers[3].handleMessage(
        JSON.stringify(envelope),
        f.peers[valid.sender],
      );
    } else {
      const changed = structuredClone(payload);
      let sender = valid.sender;
      if (fault === 'nonselected-sender') sender = 3;
      if (fault === 'wrong-digest') changed.msg = 'ef'.repeat(32);
      if (fault === 'wrong-profile')
        changed.bound.profileHash = '01'.repeat(32);
      if (fault === 'wrong-selection') changed.selectionHash = '02'.repeat(32);
      if (fault === 'wrong-key') {
        const wrong = secp.ecdsaSign(
          Buffer.from(digest, 'hex'),
          Buffer.from('02'.repeat(32), 'hex'),
        );
        changed.signature = Buffer.from(wrong.signature).toString('hex');
        changed.signatureRecovery = wrong.recid.toString(16).padStart(2, '0');
      }
      if (fault === 'wrong-recovery')
        changed.signatureRecovery =
          changed.signatureRecovery === '00' ? '01' : '00';
      if (fault === 'array-message')
        (changed as { msg: unknown }).msg = [changed.msg];
      if (fault === 'array-selection')
        (changed as { selectionHash: unknown }).selectionHash = [
          changed.selectionHash,
        ];
      if (fault === 'array-signature')
        (changed as { signature: unknown }).signature = [changed.signature];
      if (fault === 'array-recovery')
        (changed as { signatureRecovery: unknown }).signatureRecovery = [
          changed.signatureRecovery,
        ];
      const message = await f.makeMessage(sender, 'bound-result-v1', changed);
      await f.signers[3].handleMessage(message, f.peers[sender]);
    }
    expect(f.signers[3].queue()[0].boundResult).toBeUndefined();
    await deliver(f, valid);
    await expect(pending[3]).resolves.toEqual(f.result);
  });

  it('fails the retained standby if backend source changes during result authorization', async () => {
    const { f, pending, valid } = await preparedStandby();
    let entered!: () => void;
    let release!: () => void;
    const started = new Promise<void>((resolve) => {
      entered = resolve;
    });
    const wait = new Promise<void>((resolve) => {
      release = resolve;
    });
    f.setNextThreshold[3](async () => {
      entered();
      await wait;
      return { data: { threshold: 1 } };
    });
    const received = deliver(f, valid);
    await started;
    release();
    await expect(received).rejects.toThrow('profile changed');
    await expect(pending[3]).rejects.toBe('Bound backend profile changed');
    expect(f.signers[3].queue()[0]).toMatchObject({
      posted: true,
      boundResultOnly: true,
      boundFailed: true,
      boundSettled: true,
    });
    expect(f.signers[3].queue()[0].boundResult).toBeUndefined();
  });

  it('fails the retained standby when result policy is revoked before acceptance', async () => {
    const f = await fourSignerFixture({ holdResultFor: 3 });
    let current = true;
    const custom = [
      hooks(),
      hooks(),
      hooks(),
      {
        authorize: async () => {},
        assertCurrent: () => {
          if (!current) throw Error('revoked');
        },
      },
    ];
    const pending = await queueAll(f, custom);
    await f.signers[0].update();
    await vi.waitFor(() =>
      expect(f.signers[3].queue()[0]?.boundResultOnly).toBe(true),
    );
    const valid = f.held.find((item) => item.type === 'bound-result-v1')!;
    current = false;
    await expect(deliver(f, valid)).rejects.toThrow('revoked');
    await expect(pending[3]).rejects.toBe('revoked');
    expect(f.signers[3].queue()[0].boundResult).toBeUndefined();
  });

  it('times out result-only state without resetting or accepting a late replay', async () => {
    const f = await fourSignerFixture({
      holdResultFor: 3,
      timeoutSeconds: 1,
    });
    const pending = await queueAll(f);
    await f.signers[0].update();
    await vi.waitFor(() =>
      expect(f.signers[3].queue()[0]?.boundResultOnly).toBe(true),
    );
    const valid = f.held.find((item) => item.type === 'bound-result-v1')!;
    f.now[3] += 2;
    await f.signers[3].clean();
    await expect(pending[3]).rejects.toBe('Bound signing timed out');
    await deliver(f, valid);
    expect(f.signers[3].queue()[0]).toMatchObject({
      posted: true,
      boundResultOnly: true,
      boundFailed: true,
      boundSettled: true,
    });
    expect(f.signers[3].queue()[0].boundResult).toBeUndefined();
    await f.signers[3].update();
    expect(f.backendCalls).not.toContain(3);
  });

  it('retires a timed-out bound operation after its late-message window', async () => {
    const f = await fourSignerFixture({
      timeoutSeconds: 1,
      signCacheTTLSeconds: 2,
    });
    const pending = await queueAll(f);
    f.now[0] += 2;
    await f.signers[0].clean();
    await expect(pending[0]).rejects.toBe('Bound signing timed out');
    expect(f.signers[0].queue()).toHaveLength(1);
    f.now[0] += 10_000;
    await f.signers[0].clean();
    expect(f.signers[0].queue()).toHaveLength(0);
  });

  it('fails a verified producer deterministically when result enqueue throws', async () => {
    const f = await fourSignerFixture({ throwResultSender: 0 });
    const pending = await queueAll(f);
    await f.signers[0].update();
    await expect(pending[0]).rejects.toBe('result enqueue failed');
    await vi.waitFor(() =>
      expect(f.backendErrors).toContain('Error: result enqueue failed'),
    );
    expect(f.signers[0].queue()[0]).toMatchObject({
      boundFailed: true,
      boundSettled: true,
      boundResult: f.result,
    });
    expect(f.signers[0].queue()[0].boundResultEmitted).toBeUndefined();
    const other = secp.ecdsaSign(Buffer.from(digest, 'hex'), secret, {
      data: Buffer.alloc(32, 9),
    });
    await expect(
      f.signers[0].receiveBoundCallback(
        StatusEnum.Success,
        digest,
        Buffer.from(other.signature).toString('hex'),
        other.recid.toString(16).padStart(2, '0'),
      ),
    ).rejects.toThrow('Conflicting bound signing result');
  });

  it('fails a verified producer when result enqueue rejects asynchronously', async () => {
    const f = await fourSignerFixture({ rejectResultSender: 0 });
    const pending = await queueAll(f);
    await f.signers[0].update();
    await expect(pending[0]).rejects.toBe('async result enqueue failed');
    await vi.waitFor(() =>
      expect(f.backendErrors).toContain('Error: async result enqueue failed'),
    );
    expect(f.signers[0].queue()[0]).toMatchObject({
      boundFailed: true,
      boundSettled: true,
      boundResult: f.result,
    });
    expect(f.signers[0].queue()[0].boundResultEmitted).toBeUndefined();
  });

  it('makes identical result duplicates idempotent and refuses a conflicting result', async () => {
    const { f, pending, valid, payload } = await preparedStandby();
    await deliver(f, valid);
    await deliver(f, valid);
    await expect(pending[3]).resolves.toEqual(f.result);
    const other = secp.ecdsaSign(Buffer.from(digest, 'hex'), secret, {
      data: Buffer.alloc(32, 7),
    });
    const conflictPayload = {
      ...payload,
      signature: Buffer.from(other.signature).toString('hex'),
      signatureRecovery: other.recid.toString(16).padStart(2, '0'),
    };
    const conflict = await f.makeMessage(
      valid.sender,
      'bound-result-v1',
      conflictPayload,
    );
    await expect(
      f.signers[3].handleMessage(conflict, f.peers[valid.sender]),
    ).rejects.toThrow('Conflicting bound signing result');
    expect(f.signers[3].queue()[0].boundResult).toEqual(f.result);
  });

  it('keeps concurrent identical results benign when the first settlement retires hooks', async () => {
    const c = await preparedRetiringStandby();
    const first = deliver(c.f, c.valid);
    await vi.waitFor(() => expect(c.authorizeCalls()).toBe(1));
    const second = deliver(c.f, c.valid);
    await vi.waitFor(() => expect(c.authorizeCalls()).toBe(2));
    c.releaseFirst();

    await expect(Promise.all([first, second])).resolves.toEqual([
      undefined,
      undefined,
    ]);
    await expect(c.pending[3]).resolves.toEqual(c.f.result);
    expect(c.f.signers[3].queue()[0].boundResult).toEqual(c.f.result);
  });

  it('refuses a concurrent conflicting result after the first settlement retires hooks', async () => {
    const c = await preparedRetiringStandby();
    const payload = JSON.parse(c.valid.message).payload;
    const other = secp.ecdsaSign(Buffer.from(digest, 'hex'), secret, {
      data: Buffer.alloc(32, 11),
    });
    const conflicting = await c.f.makeMessage(
      c.valid.sender,
      'bound-result-v1',
      {
        ...payload,
        signature: Buffer.from(other.signature).toString('hex'),
        signatureRecovery: other.recid.toString(16).padStart(2, '0'),
      },
    );

    const first = deliver(c.f, c.valid);
    await vi.waitFor(() => expect(c.authorizeCalls()).toBe(1));
    const second = c.f.signers[3].handleMessage(
      conflicting,
      c.f.peers[c.valid.sender],
    );
    await vi.waitFor(() => expect(c.authorizeCalls()).toBe(2));
    c.releaseFirst();

    await expect(first).resolves.toBeUndefined();
    await expect(second).rejects.toThrow('Conflicting bound signing result');
    await expect(c.pending[3]).resolves.toEqual(c.f.result);
    expect(c.f.signers[3].queue()[0].boundResult).toEqual(c.f.result);
  });

  it('selected actors ignore peer results until their own backend callbacks', async () => {
    const f = await fourSignerFixture({ autoBackend: false });
    const pending = await queueAll(f);
    await f.signers[0].update();
    await vi.waitFor(() => expect(f.backendCalls.sort()).toEqual([0, 1, 2]));
    const selection = f.signers[0].queue()[0].boundSelection!;
    const payload = {
      msg: digest,
      bound: {
        capability: 'bound-result-transport' as const,
        version: 1 as const,
        profileHash: f.profiles[0].profileHash,
      },
      selectionHash: selection.selectionHash,
      ...f.result,
    };
    const peerResult = await f.makeMessage(0, 'bound-result-v1', payload);
    await f.signers[1].handleMessage(peerResult, f.peers[0]);
    expect(f.signers[1].queue()[0].boundResult).toBeUndefined();
    await Promise.all(
      [0, 1, 2].map((index) =>
        f.signers[index].receiveBoundCallback(
          StatusEnum.Success,
          digest,
          f.result.signature,
          f.result.signatureRecovery,
        ),
      ),
    );
    await expect(Promise.all(pending)).resolves.toEqual(
      Array.from({ length: 4 }, () => f.result),
    );
  });

  it.each([
    'reordered-roster',
    'duplicate-peer',
    'wrong-selected-indexes',
    'foreign-selection-hash',
  ])('refuses authenticated start with %s', async (fault) => {
    const f = await fourSignerFixture({
      holdStartFor: 3,
      holdResultFor: 3,
    });
    const pending = await queueAll(f);
    await f.signers[0].update();
    await vi.waitFor(() => expect(f.backendCalls.sort()).toEqual([0, 1, 2]));
    const validStart = f.held.find((item) => item.type === 'start')!;
    const validResult = f.held.find((item) => item.type === 'bound-result-v1')!;
    const payload = structuredClone(JSON.parse(validStart.message).payload);
    if (fault === 'reordered-roster')
      [payload.guards[0], payload.guards[1]] = [
        payload.guards[1],
        payload.guards[0],
      ];
    if (fault === 'duplicate-peer')
      payload.guards[1].peerId = payload.guards[0].peerId;
    if (fault === 'wrong-selected-indexes')
      payload.selection.selectedGuards = payload.selection.selectedGuards
        .slice()
        .reverse();
    if (fault === 'foreign-selection-hash')
      payload.selection.selectionHash = '77'.repeat(32);
    const message = await f.makeMessage(
      validStart.sender,
      'start',
      payload,
      JSON.parse(validStart.message).timestamp,
    );
    await f.signers[3].handleMessage(message, f.peers[validStart.sender]);
    expect(f.signers[3].queue()[0].boundSelection).toBeUndefined();
    await deliver(f, validStart);
    await deliver(f, validResult);
    await expect(pending[3]).resolves.toEqual(f.result);
  });
});
