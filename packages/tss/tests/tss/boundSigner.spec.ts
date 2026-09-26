import { createHash } from 'node:crypto';
import secp from 'secp256k1';
import { describe, expect, it, vi } from 'vitest';

import { GuardDetection, ActiveGuard } from '@rosen-bridge/detection';
import { EdDSA } from '@rosen-bridge/encryption';

import { EcdsaSigner } from '../../lib/tss/ecdsaSigner';
import {
  BoundSignHooks,
  BoundSignProfile,
  SignCachedPayload,
  StatusEnum,
} from '../../lib/types/signer';

const digest = 'ab'.repeat(32);
const chain = 'cd'.repeat(32);
const secret = Buffer.from('01'.repeat(32), 'hex');
const key = Buffer.from(secp.publicKeyCreate(secret)).toString('hex');
const noop: BoundSignHooks = {
  authorize: async () => {},
  assertCurrent: () => {},
};

class InspectableSigner extends EcdsaSigner {
  clean = () => this.cleanup();
  expireFirstSign = () => {
    this.signs[0].addedTime = this.getDate() - this.timeout;
  };
  api = () => this.axios;
  queue = () => this.signs;
  cache = () => this.signCache;
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
  request = (guards: ActiveGuard[], index: number) =>
    this.handleRequestMessage(
      { msg: digest, guards },
      'peer',
      index,
      this.getDate(),
      false,
    );
  peerResult = (payload: SignCachedPayload) =>
    this.handleSignCachedMessage(payload, 'peer');
  approve = (guards: ActiveGuard[]) =>
    this.handleApproveMessage(
      { msg: digest, guards, initGuardIndex: 0 },
      'peer',
      0,
      this.signs[0].signs[0],
    );
  thresholdValue = (value: number) => {
    this.threshold = { value, expiry: Infinity };
  };
}

async function fixture(second = false) {
  const enc = new EdDSA(await EdDSA.randomKey());
  const pk = await enc.getPk();
  const submit = vi.fn();
  const guardKeys = [pk];
  const shares = ['1'];
  if (second) {
    guardKeys.push(await new EdDSA(await EdDSA.randomKey()).getPk());
    shares.push('2');
  }
  const detection = new GuardDetection({
    messageEnc: enc,
    guardsPublicKey: guardKeys,
    submit,
    getPeerId: async () => 'peer',
  });
  const signer = new InspectableSigner({
    messageEnc: enc,
    guardsPk: guardKeys,
    shares,
    detection,
    submitMsg: submit,
    callbackUrl: '',
    tssApiUrl: '',
    getPeerId: async () => 'peer',
    turnNoWorkSeconds: 0.001,
  });
  const get = vi
    .spyOn(signer.api(), 'get')
    .mockResolvedValue({ data: { threshold: 0 } });
  const post = vi
    .spyOn(signer.api(), 'post')
    .mockImplementation(async (url) => ({
      data: url === 'getPK' ? { publicKey: key } : {},
    }));
  const guards = [{ publicKey: pk, peerId: 'peer', index: 0 }];
  vi.spyOn(detection, 'activeGuards').mockResolvedValue(guards);
  const profile = await signer.prepareBoundProfile(chain, [1]);
  return { enc, signer, submit, get, post, profile, guardKeys, shares, guards };
}

async function queued(
  signer: InspectableSigner,
  profile: BoundSignProfile,
  hooks = noop,
) {
  const result = signer.signBoundPromised(digest, profile, hooks);
  void result.catch(() => {});
  await vi.waitFor(() => expect(signer.queue()).toHaveLength(1));
  return { result };
}

describe('bound ECDSA signing', () => {
  it('preserves the retained ASCII chain code through profile and backend dispatch', async () => {
    // Public distributed-signature fixture: payment/tests/fixtures/tss-signature.json.
    const retainedChainCode = '0123456789abcdef0123456789abcdef';
    const f = await fixture();
    f.post.mockClear();
    const profile = await f.signer.prepareBoundProfile(retainedChainCode, [0]);
    expect(profile.chainCode).toBe(retainedChainCode);
    const { result } = await queued(f.signer, profile);
    await f.signer.startSign(digest, f.guards);
    for (const [url, body] of f.post.mock.calls) {
      expect(['getPK', 'sign']).toContain(url);
      expect(body).toMatchObject({
        chainCode: retainedChainCode,
        derivationPath: [0],
      });
    }
    expect(f.post.mock.calls.some(([url]) => url === 'sign')).toBe(true);
    const signed = secp.ecdsaSign(Buffer.from(digest, 'hex'), secret);
    const signature = Buffer.from(signed.signature).toString('hex');
    const recovery = signed.recid.toString(16).padStart(2, '0');
    await f.signer.receiveBoundCallback(
      StatusEnum.Success,
      digest,
      signature,
      recovery,
    );
    await expect(result).resolves.toEqual({
      signature,
      signatureRecovery: recovery,
    });
  });

  it.each(['', '0', 'ABCDEF', 'gg', 'aa'.repeat(33)])(
    'rejects noncanonical or oversized bound chain code %j before backend access',
    async (chainCode) => {
      const f = await fixture();
      f.get.mockClear();
      f.post.mockClear();
      await expect(
        f.signer.prepareBoundProfile(chainCode, [0]),
      ).rejects.toThrow('Invalid bound signing profile');
      expect(f.get).not.toHaveBeenCalled();
      expect(f.post).not.toHaveBeenCalled();
    },
  );

  it('blocks guard order drift after the envelope index has already been captured', async () => {
    const f = await fixture(true);
    vi.spyOn(f.signer, 'getGuardTurn').mockReturnValue(0);
    const { result } = await queued(f.signer, f.profile, {
      authorize: async () => {
        await f.signer.changePks([...f.profile.guardPublicKeys].reverse());
      },
      assertCurrent: () => {},
    });
    await expect(f.signer.update()).rejects.toThrow(
      'Bound signing profile changed',
    );
    await expect(result).rejects.toBe('Bound signing profile changed');
    expect(f.submit).not.toHaveBeenCalled();
    expect(f.post.mock.calls.filter((call) => call[0] === 'sign')).toHaveLength(
      0,
    );
  });
  it('rejects a compressed encoding that is not a secp256k1 point', async () => {
    const f = await fixture();
    f.post.mockResolvedValueOnce({
      data: { publicKey: '02' + 'ff'.repeat(32) },
    });
    await expect(f.signer.prepareBoundProfile(chain, [1])).rejects.toThrow(
      'public key',
    );
  });

  it.each([false, true])(
    'retains the first verified result despite a different valid signature, earlier failure=%s',
    async (failed) => {
      const f = await fixture();
      const { result } = await queued(f.signer, f.profile);
      if (failed)
        f.post.mockImplementation(async (url) => {
          if (url === 'sign') throw Error('lost response');
          return { data: { publicKey: key } };
        });
      await f.signer.startSign(digest, f.guards);
      if (failed) await expect(result).rejects.toBe('lost response');
      const make = (data?: Buffer) => {
        const signed = secp.ecdsaSign(
          Buffer.from(digest, 'hex'),
          secret,
          data ? { data } : undefined,
        );
        return {
          signature: Buffer.from(signed.signature).toString('hex'),
          signatureRecovery: signed.recid.toString(16).padStart(2, '0'),
        };
      };
      const first = make(),
        other = make(Buffer.alloc(32, 3));
      expect(other.signature).not.toBe(first.signature);
      expect(
        await f.signer.verify(
          digest,
          other.signature,
          key,
          other.signatureRecovery,
        ),
      ).toBe(true);
      await f.signer.receiveBoundCallback(
        StatusEnum.Success,
        digest,
        first.signature,
        first.signatureRecovery,
      );
      if (!failed) await expect(result).resolves.toEqual(first);
      await f.signer.receiveBoundCallback(
        StatusEnum.Success,
        digest,
        first.signature,
        first.signatureRecovery,
      );
      await expect(
        f.signer.receiveBoundCallback(
          StatusEnum.Success,
          digest,
          other.signature,
          other.signatureRecovery,
        ),
      ).rejects.toThrow('Conflicting bound signing result');
      expect(f.signer.getBoundResult(digest, f.profile)).toEqual(first);
    },
  );
  it('schedules a third operation after two retained terminal records', async () => {
    const f = await fixture();
    const messages = ['11'.repeat(32), '22'.repeat(32), '33'.repeat(32)];
    const reject = {
      authorize: async () => {
        throw Error('revoked');
      },
      assertCurrent: () => {},
    };
    for (const message of messages)
      void f.signer
        .signBoundPromised(
          message,
          f.profile,
          message === messages[2] ? noop : reject,
        )
        .catch(() => {});
    await vi.waitFor(() => expect(f.signer.queue()).toHaveLength(3));
    for (const message of messages.slice(0, 2))
      await expect(f.signer.startSign(message, f.guards)).rejects.toThrow(
        'revoked',
      );
    await f.signer.clean();
    await f.signer.update();
    expect(
      f.submit.mock.calls.map((call) => JSON.parse(call[0]).payload.msg),
    ).toEqual([messages[2]]);
    expect(
      f.signer
        .queue()
        .slice(0, 2)
        .every((sign) => sign.boundFailed),
    ).toBe(true);
  });
  it('freezes the issued profile and copies caller path before backend awaits', async () => {
    const f = await fixture();
    let release!: () => void;
    f.get.mockImplementationOnce(async () => {
      await new Promise<void>((resolve) => {
        release = resolve;
      });
      return { data: { threshold: 0 } };
    });
    const path = [9];
    const prepared = f.signer.prepareBoundProfile(chain, path);
    path[0] = 77;
    release();
    const profile = await prepared;
    expect(profile.derivationPath).toEqual([9]);
    expect(Object.isFrozen(profile)).toBe(true);
    expect(Object.isFrozen(profile.guardPublicKeys)).toBe(true);
    expect(Object.isFrozen(profile.derivationPath)).toBe(true);
  });

  it('rejects failed or malformed fresh threshold reads despite cached threshold', async () => {
    const f = await fixture();
    f.signer.thresholdValue(1);
    f.get.mockRejectedValueOnce(Error('unavailable'));
    await expect(f.signer.prepareBoundProfile(chain, [1])).rejects.toThrow(
      'unavailable',
    );
    f.get.mockResolvedValueOnce({ data: { threshold: -1 } });
    await expect(f.signer.prepareBoundProfile(chain, [1])).rejects.toThrow(
      'threshold',
    );
  });

  it('rejects profiles copied from JSON and malformed digests', async () => {
    const f = await fixture();
    await expect(
      f.signer.signBoundPromised(
        digest,
        JSON.parse(JSON.stringify(f.profile)),
        noop,
      ),
    ).rejects.toThrow('profile');
    await expect(
      f.signer.signBoundPromised('ab', f.profile, noop),
    ).rejects.toThrow('32-byte');
  });

  it('does not reuse a same-digest legacy cache or accept overlapping profiles', async () => {
    const f = await fixture();
    f.signer.cache()[digest] = { signature: 'legacy', signatureRecovery: '00' };
    await queued(f.signer, f.profile);
    expect(f.signer.cache()[digest]).toBeUndefined();
    const other = await f.signer.prepareBoundProfile(chain, [2]);
    await expect(
      f.signer.signBoundPromised(digest, other, noop),
    ).rejects.toThrow('already signing');
  });

  it.each(['bound', 'legacy'] as const)(
    'rejects a same-digest mixed request when %s is queued first',
    async (first) => {
      const f = await fixture();
      const bound = () => f.signer.signBoundPromised(digest, f.profile, noop);
      const legacy = () => f.signer.signPromised(digest, chain, [1]);
      const original = first === 'bound' ? bound() : legacy();
      void original.catch(() => {});
      await vi.waitFor(() => expect(f.signer.queue()).toHaveLength(1));
      const callback = f.signer.queue()[0].callback;
      await expect(first === 'bound' ? legacy() : bound()).rejects.toThrow(
        'already signing',
      );
      expect(f.signer.queue()).toHaveLength(1);
      expect(f.signer.queue()[0].callback).toBe(callback);
      expect(
        f.post.mock.calls.filter((call) => call[0] === 'sign'),
      ).toHaveLength(0);
    },
  );

  it('preserves upstream timeout notification for concurrent legacy callers', async () => {
    const f = await fixture();
    const first = f.signer.signPromised(digest, chain, [1]);
    const second = f.signer.signPromised(digest, chain, [1]);
    void first.catch(() => {});
    void second.catch(() => {});
    await vi.waitFor(() => expect(f.signer.queue()).toHaveLength(1));
    f.signer.expireFirstSign();
    await f.signer.clean();
    await expect(first).rejects.toBe('Timed out');
    await expect(second).rejects.toBe('Timed out');
    expect(f.signer.queue()).toHaveLength(0);
  });

  it.each(['request', 'approve'] as const)(
    'blocks %s after revocation while envelope signing is paused',
    async (stage) => {
      const f = await fixture();
      let current = true;
      await queued(f.signer, f.profile, {
        authorize: async () => {},
        assertCurrent: () => {
          if (!current) throw Error('revoked');
        },
      });
      let release!: () => void, entered!: () => void;
      const started = new Promise<void>((resolve) => {
        entered = resolve;
      });
      const wait = new Promise<void>((resolve) => {
        release = resolve;
      });
      const real = f.enc.sign.bind(f.enc);
      vi.spyOn(f.enc, 'sign').mockImplementation(async (data) => {
        entered();
        await wait;
        return real(data);
      });
      const task =
        stage === 'request' ? f.signer.update() : f.signer.request(f.guards, 0);
      await started;
      current = false;
      release();
      await expect(task).rejects.toThrow('revoked');
      expect(f.submit).not.toHaveBeenCalled();
      expect(
        f.post.mock.calls.filter((call) => call[0] === 'sign'),
      ).toHaveLength(0);
    },
  );

  it('blocks local configuration drift during transport authorization', async () => {
    const f = await fixture();
    await queued(f.signer, f.profile, {
      authorize: async () => {
        queueMicrotask(() => {
          f.shares[0] = 'other';
        });
      },
      assertCurrent: () => {},
    });
    await expect(f.signer.update()).rejects.toThrow('profile changed');
    expect(f.submit).not.toHaveBeenCalled();
  });

  it('blocks start fanout when revoked during envelope signing and releases its mutex', async () => {
    const f = await fixture();
    let current = true;
    await queued(f.signer, f.profile, {
      authorize: async () => {},
      assertCurrent: () => {
        if (!current) throw Error('revoked');
      },
    });
    await f.signer.update();
    f.submit.mockClear();
    let release!: () => void, entered!: () => void;
    const started = new Promise<void>((resolve) => {
      entered = resolve;
    });
    const wait = new Promise<void>((resolve) => {
      release = resolve;
    });
    const real = f.enc.sign.bind(f.enc);
    vi.spyOn(f.enc, 'sign').mockImplementation(async (data) => {
      entered();
      await wait;
      return real(data);
    });
    const task = f.signer.approve(f.guards);
    await started;
    current = false;
    release();
    await task;
    expect(f.submit).not.toHaveBeenCalled();
    expect(f.post.mock.calls.filter((call) => call[0] === 'sign')).toHaveLength(
      0,
    );
    await f.signer.approve(f.guards);
  });

  it('checks captured threshold despite a later global threshold change', async () => {
    const f = await fixture();
    await queued(f.signer, f.profile);
    await f.signer.update();
    f.signer.thresholdValue(99);
    await f.signer.approve(f.guards);
    expect(f.submit.mock.calls.map((call) => JSON.parse(call[0]).type)).toEqual(
      ['request', 'start'],
    );
    expect(f.post.mock.calls.filter((call) => call[0] === 'sign')).toHaveLength(
      1,
    );
  });

  it('does not dispatch the same bound operation twice across concurrent backend gates', async () => {
    const f = await fixture();
    const { result } = await queued(f.signer, f.profile);
    const results = await Promise.allSettled([
      f.signer.startSign(digest, f.guards),
      f.signer.startSign(digest, f.guards),
    ]);
    expect(
      results.filter((result) => result.status === 'rejected'),
    ).toHaveLength(1);
    expect(f.post.mock.calls.filter((call) => call[0] === 'sign')).toHaveLength(
      1,
    );
    expect(f.signer.queue()[0].boundFailed).toBeUndefined();
    const signed = secp.ecdsaSign(Buffer.from(digest, 'hex'), secret);
    const signature = Buffer.from(signed.signature).toString('hex');
    const signatureRecovery = signed.recid.toString(16).padStart(2, '0');
    await f.signer.receiveBoundCallback(
      StatusEnum.Success,
      digest,
      signature,
      signatureRecovery,
    );
    await expect(result).resolves.toEqual({ signature, signatureRecovery });
  });

  it('blocks backend dispatch on fresh profile mismatch and after authorization revocation', async () => {
    const f = await fixture();
    let current = true;
    await queued(f.signer, f.profile, {
      authorize: async () => {
        queueMicrotask(() => {
          current = false;
        });
      },
      assertCurrent: () => {
        if (!current) throw Error('revoked');
      },
    });
    await expect(f.signer.startSign(digest, f.guards)).rejects.toThrow(
      'revoked',
    );
    expect(f.post.mock.calls.filter((call) => call[0] === 'sign')).toHaveLength(
      0,
    );
  });

  it.each(['threshold', 'publicKey', 'unavailable'] as const)(
    'rejects fresh backend %s drift before dispatch',
    async (field) => {
      const f = await fixture(true);
      await queued(f.signer, f.profile);
      if (field === 'threshold')
        f.get.mockResolvedValueOnce({ data: { threshold: 1 } });
      else if (field === 'unavailable')
        f.get.mockRejectedValueOnce(Error('unavailable'));
      else
        f.post.mockResolvedValueOnce({
          data: {
            publicKey: Buffer.from(
              secp.publicKeyCreate(Buffer.from('02'.repeat(32), 'hex')),
            ).toString('hex'),
          },
        });
      await expect(f.signer.startSign(digest, f.guards)).rejects.toThrow(
        field === 'unavailable' ? 'unavailable' : 'profile changed',
      );
      expect(
        f.post.mock.calls.filter((call) => call[0] === 'sign'),
      ).toHaveLength(0);
    },
  );

  it('posts captured path/share mapping and verifies the captured key after revocation', async () => {
    const f = await fixture();
    let current = true;
    const hooks = {
      authorize: async () => {},
      assertCurrent: () => {
        if (!current) throw Error('revoked');
      },
    };
    const { result } = await queued(f.signer, f.profile, hooks);
    hooks.authorize = async () => {
      throw Error('caller mutated hook');
    };
    await f.signer.startSign(digest, f.guards);
    expect(
      f.post.mock.calls.find((call) => call[0] === 'sign')?.[1],
    ).toMatchObject({
      chainCode: chain,
      derivationPath: [1],
      peers: [{ shareID: '1', p2pID: 'peer' }],
    });
    current = false;
    const signed = secp.ecdsaSign(Buffer.from(digest, 'hex'), secret);
    const signature = Buffer.from(signed.signature).toString('hex');
    const recovery = signed.recid.toString(16).padStart(2, '0');
    f.post.mockRejectedValue(Error('backend no longer available'));
    await f.signer.receiveBoundCallback(
      StatusEnum.Success,
      digest,
      signature,
      recovery,
    );
    await expect(result).resolves.toEqual({
      signature,
      signatureRecovery: recovery,
    });
    expect(f.signer.cache()[digest]).toBeUndefined();
  });

  it('declines a valid same-key legacy peer cache result and still signs through the bound backend path', async () => {
    const f = await fixture();
    const { result } = await queued(f.signer, f.profile);
    const signed = secp.ecdsaSign(Buffer.from(digest, 'hex'), secret);
    f.post.mockClear();
    await f.signer.peerResult({
      msg: digest,
      signature: Buffer.from(signed.signature).toString('hex'),
      signatureRecovery: signed.recid.toString(16).padStart(2, '0'),
    });
    expect(f.signer.queue()).toHaveLength(1);
    expect(f.post).not.toHaveBeenCalled();
    expect(f.signer.queue()[0].boundSettled).toBeUndefined();
    expect(f.signer.getBoundResult(digest, f.profile)).toBeUndefined();
    await f.signer.startSign(digest, f.guards);
    const signature = Buffer.from(signed.signature).toString('hex');
    const recovery = signed.recid.toString(16).padStart(2, '0');
    await f.signer.receiveBoundCallback(
      StatusEnum.Success,
      digest,
      signature,
      recovery,
    );
    await expect(result).resolves.toEqual({
      signature,
      signatureRecovery: recovery,
    });
  });

  it('hashes the exact ordered profile fields and changes hash for a different path', async () => {
    const f = await fixture();
    const { profileHash, ...fields } = f.profile;
    expect(profileHash).toBe(
      createHash('sha256').update(JSON.stringify(fields)).digest('hex'),
    );
    expect(fields).toMatchObject({
      schema: 1,
      curve: 'secp256k1',
      crypto: 'ecdsa',
      rawThreshold: 0,
      effectiveThreshold: 1,
    });
    expect(
      (await f.signer.prepareBoundProfile(chain, [2])).profileHash,
    ).not.toBe(profileHash);
  });

  it('does not settle or retain a backend signature made by another key', async () => {
    const f = await fixture();
    await queued(f.signer, f.profile);
    await f.signer.startSign(digest, f.guards);
    const signed = secp.ecdsaSign(
      Buffer.from(digest, 'hex'),
      Buffer.from('02'.repeat(32), 'hex'),
    );
    f.post.mockClear();
    await f.signer.receiveBoundCallback(
      StatusEnum.Success,
      digest,
      Buffer.from(signed.signature).toString('hex'),
      signed.recid.toString(16).padStart(2, '0'),
    );
    expect(f.signer.getBoundResult(digest, f.profile)).toBeUndefined();
    expect(f.signer.queue()[0].boundSettled).toBeUndefined();
    expect(f.post).not.toHaveBeenCalled();
  });

  it('rejects the bound caller once and retains failed custody through cleanup and update', async () => {
    const f = await fixture();
    let rejectCount = 0;
    const { result } = await queued(f.signer, f.profile, {
      authorize: async () => {
        throw Error('revoked');
      },
      assertCurrent: () => {},
    });
    void result.catch(() => {
      rejectCount++;
    });
    await expect(f.signer.update()).rejects.toThrow('revoked');
    await expect(result).rejects.toBe('revoked');
    f.signer.expireFirstSign();
    await f.signer.clean();
    await f.signer.update();
    await expect(
      f.signer.signBoundPromised(digest, f.profile, noop),
    ).rejects.toThrow('already signing');
    expect(f.signer.queue()[0]).toMatchObject({
      posted: true,
      boundFailed: true,
      boundSettled: true,
    });
    expect(rejectCount).toBe(1);
    expect(f.submit).not.toHaveBeenCalled();
    expect(f.post.mock.calls.filter((call) => call[0] === 'sign')).toHaveLength(
      0,
    );
  });

  it('retains and verifies a late backend result after an uncertain network error without resettling the caller', async () => {
    const f = await fixture();
    const { result } = await queued(f.signer, f.profile);
    let rejections = 0;
    void result.catch(() => {
      rejections++;
    });
    f.post.mockImplementation(async (url) => {
      if (url === 'sign') throw Error('lost response');
      return { data: { publicKey: key } };
    });
    await f.signer.startSign(digest, f.guards);
    await expect(result).rejects.toBe('lost response');
    expect(f.signer.queue()[0]).toMatchObject({
      boundDispatchAttempted: true,
      boundBackendAttempted: true,
      boundFailed: true,
    });
    const signed = secp.ecdsaSign(Buffer.from(digest, 'hex'), secret);
    const signature = Buffer.from(signed.signature).toString('hex');
    const signatureRecovery = signed.recid.toString(16).padStart(2, '0');
    await f.signer.receiveBoundCallback(
      StatusEnum.Success,
      digest,
      signature,
      signatureRecovery,
    );
    expect(f.signer.getBoundResult(digest, f.profile)).toEqual({
      signature,
      signatureRecovery,
    });
    expect(rejections).toBe(1);
    expect(f.signer.cache()[digest]).toBeUndefined();
    await f.signer.clean();
    await f.signer.update();
    expect(f.post.mock.calls.filter((call) => call[0] === 'sign')).toHaveLength(
      1,
    );
  });

  it('rejects a retired dispatch callback after the same digest is queued again', async () => {
    const f = await fixture();
    const first = await queued(f.signer, f.profile);
    await f.signer.startSign(digest, f.guards);
    const callbackIds = () =>
      f.post.mock.calls
        .filter(([url]) => url === 'sign')
        .map(([, body]) =>
          new URL(
            (body as { callBackUrl: string }).callBackUrl,
            'http://localhost',
          ).searchParams.get('boundOperationId'),
        );
    const firstId = callbackIds()[0]!;
    expect(firstId).toBe(f.signer.queue()[0].boundCallbackId);
    f.signer.queue()[0].addedTime = 0;
    await f.signer.clean();
    await expect(first.result).rejects.toBe('Bound signing timed out');
    expect(f.signer.queue()).toHaveLength(0);

    const second = await queued(f.signer, f.profile);
    await f.signer.startSign(digest, f.guards);
    const secondId = callbackIds()[1]!;
    expect(secondId).not.toBe(firstId);
    const signed = secp.ecdsaSign(Buffer.from(digest, 'hex'), secret);
    const signature = Buffer.from(signed.signature).toString('hex');
    const recovery = signed.recid.toString(16).padStart(2, '0');
    await expect(
      f.signer.handleSignData(StatusEnum.Success, digest, signature, recovery),
    ).rejects.toThrow('Invalid callback operation');
    await expect(
      f.signer.handleSignData(
        StatusEnum.Success,
        digest,
        signature,
        recovery,
        undefined,
        firstId,
      ),
    ).rejects.toThrow('Invalid callback operation');
    expect(f.signer.queue()[0].boundResult).toBeUndefined();
    await f.signer.handleSignData(
      StatusEnum.Success,
      digest,
      signature,
      recovery,
      undefined,
      secondId,
    );
    await expect(second.result).resolves.toEqual({
      signature,
      signatureRecovery: recovery,
    });
  });

  it('does not remove a new legacy sign when an old bound callback finishes verification', async () => {
    const f = await fixture();
    const first = await queued(f.signer, f.profile);
    await f.signer.startSign(digest, f.guards);
    const signed = secp.ecdsaSign(Buffer.from(digest, 'hex'), secret);
    const signature = Buffer.from(signed.signature).toString('hex');
    const recovery = signed.recid.toString(16).padStart(2, '0');
    const originalVerify = f.signer.verify.bind(f.signer);
    let entered!: () => void;
    let release!: () => void;
    const started = new Promise<void>((resolve) => {
      entered = resolve;
    });
    const wait = new Promise<void>((resolve) => {
      release = resolve;
    });
    vi.spyOn(f.signer, 'verify').mockImplementation(async (...args) => {
      entered();
      await wait;
      return originalVerify(...args);
    });

    const late = f.signer.receiveBoundCallback(
      StatusEnum.Success,
      digest,
      signature,
      recovery,
    );
    await started;
    f.signer.queue()[0].addedTime = 0;
    await f.signer.clean();
    await expect(first.result).rejects.toBe('Bound signing timed out');
    const legacy = f.signer.signPromised(digest, chain, [1]);
    void legacy.catch(() => {});
    await vi.waitFor(() => expect(f.signer.queue()).toHaveLength(1));
    const nextSign = f.signer.queue()[0];
    expect(nextSign.bound).toBeUndefined();

    release();
    await late;
    expect(f.signer.queue()).toEqual([nextSign]);
    nextSign.callback(false, 'test complete');
    await expect(legacy).rejects.toBe('test complete');
  });
});
