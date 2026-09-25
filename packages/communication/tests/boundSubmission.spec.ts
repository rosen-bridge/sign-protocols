import { describe, expect, it, vi } from 'vitest';

import { DummyLogger } from '@rosen-bridge/abstract-logger';
import { EdDSA } from '@rosen-bridge/encryption';

import { Communicator } from '../lib/communicator';

class BoundCommunicator extends Communicator {
  protected readonly protocolVersion = '1.0.0';
  processMessage = vi.fn();
  constructor(
    enc: EdDSA,
    submit: (message: string, peers: string[]) => unknown,
    pk: string,
  ) {
    super(new DummyLogger(), enc, submit, [pk]);
  }
  send = (
    payload: object,
    peers: string[],
    gate: { authorize: () => Promise<void>; assertCurrent: () => void },
  ) => this.sendMessage('request', payload, peers, 100, gate);
}

describe('bound final submission', () => {
  it('checks currentness after authorization promise resumes and never submits revoked work', async () => {
    const enc = new EdDSA(await EdDSA.randomKey());
    const submit = vi.fn();
    const comm = new BoundCommunicator(enc, submit, await enc.getPk());
    let current = true;
    const authorize = async () => {
      queueMicrotask(() => {
        current = false;
      });
    };
    await expect(
      comm.send({ msg: 'digest' }, ['peer'], {
        authorize,
        assertCurrent: () => {
          if (!current) throw Error('revoked');
        },
      }),
    ).rejects.toThrow('revoked');
    expect(submit).not.toHaveBeenCalled();
  });

  it('copies payload and peers before signing awaits', async () => {
    const enc = new EdDSA(await EdDSA.randomKey());
    const submit = vi.fn();
    const comm = new BoundCommunicator(enc, submit, await enc.getPk());
    const original = enc.sign.bind(enc);
    let release!: () => void;
    const wait = new Promise<void>((resolve) => {
      release = resolve;
    });
    let entered!: () => void;
    const started = new Promise<void>((resolve) => {
      entered = resolve;
    });
    vi.spyOn(enc, 'sign').mockImplementation(async (data) => {
      entered();
      await wait;
      return original(data);
    });
    const payload = { msg: 'original' };
    const peers = ['original-peer'];
    const task = comm.send(payload, peers, {
      authorize: async () => {},
      assertCurrent: () => {},
    });
    await started;
    payload.msg = 'mutated';
    peers[0] = 'mutated-peer';
    release();
    await task;
    expect(JSON.parse(submit.mock.calls[0][0]).payload).toEqual({
      msg: 'original',
    });
    expect(submit.mock.calls[0][1]).toEqual(['original-peer']);
  });
});
