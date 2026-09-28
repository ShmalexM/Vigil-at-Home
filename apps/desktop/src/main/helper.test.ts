import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { SensorEvent } from '@vigil/core';
import type { HelperClient } from '@vigil/helper/client';
import { describe, expect, it } from 'vitest';
import { HelperLink } from './helper.js';

function fakeClient(answer: (cmd: { kind: string }) => unknown) {
  const listeners: ((e: SensorEvent) => void)[] = [];
  const calls: string[] = [];
  const client = {
    onEvent: (fn: (e: SensorEvent) => void) => (listeners.push(fn), () => {}),
    subscribe: async () => {
      calls.push('events.subscribe');
    },
    call: async (cmd: { kind: string }) => {
      calls.push(cmd.kind);
      return answer(cmd);
    },
    close: () => calls.push('close'),
  };
  return {
    client: client as unknown as HelperClient,
    calls,
    emit: (e: SensorEvent) => listeners.forEach((f) => f(e)),
  };
}

const socket = () => {
  const p = join(mkdtempSync(join(tmpdir(), 'vh-')), 'helper.sock');
  writeFileSync(p, '');
  return p;
};

describe('HelperLink', () => {
  it('simulates actions while the helper is not installed', async () => {
    const link = new HelperLink('/nonexistent/vigil-helper.sock');
    await link.tryConnect();
    link.stop();
    expect(link.state).toBe('not_installed');
    expect(link.simulated).toBe(true);
    expect(await link.execute({ kind: 'process.suspend', pid: 1234 })).toHaveProperty('at');
    expect(link.dryRun.log).toHaveLength(1);
  });

  it('connects, subscribes, forwards events and runs actions through the helper', async () => {
    const fake = fakeClient((cmd) =>
      cmd.kind === 'file.quarantine'
        ? { actionId: 'j1', summary: 'quarantined', undoable: true, quarantineId: 'q1' }
        : { actionId: 'j2', summary: 'ok', undoable: true },
    );
    const link = new HelperLink(socket(), async () => fake.client);
    const events: SensorEvent[] = [];
    link.on('event', (e) => events.push(e));
    await link.tryConnect();
    expect(link.state).toBe('connected');
    expect(link.simulated).toBe(false);
    expect(fake.calls).toEqual(['events.subscribe']);

    fake.emit({
      id: 'e1',
      ts: 1,
      source: 'santa',
      kind: 'process.exec',
      process: { pid: 1, path: '/bin/ls' },
    });
    expect(events.map((e) => e.id)).toEqual(['e1']);

    const r = await link.execute({ kind: 'file.quarantine', path: '/tmp/x' });
    expect(r.quarantineId).toBe('q1');
    expect(link.dryRun.log).toHaveLength(0);
    link.stop();
  });

  it('reports a failed action as an error, not a throw', async () => {
    const fake = fakeClient(() => {
      throw new Error('boom');
    });
    const link = new HelperLink(socket(), async () => fake.client);
    await link.tryConnect();
    const r = await link.execute({ kind: 'process.kill', pid: 5 });
    expect(r.error).toBe('boom');
    link.stop();
  });

  it('marks the helper not running when its socket refuses connections', async () => {
    const link = new HelperLink(socket(), async () => {
      throw new Error('ECONNREFUSED');
    });
    await link.tryConnect();
    link.stop();
    expect(link.state).toBe('not_running');
  });
});
