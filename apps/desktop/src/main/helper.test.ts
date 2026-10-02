import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { SensorEvent } from '@vigil/core';
import type { HelperRan } from '@vigil/helper';
import type { HelperClient } from '@vigil/helper/client';
import { describe, expect, it } from 'vitest';
import { HelperLink } from './helper.js';

function fakeClient(answer: (cmd: { kind: string }) => unknown) {
  const listeners: ((e: SensorEvent, ran: HelperRan[]) => void)[] = [];
  const calls: string[] = [];
  const sent: { kind: string }[] = [];
  const client = {
    onEvent: (fn: (e: SensorEvent, ran: HelperRan[]) => void) => (listeners.push(fn), () => {}),
    subscribe: async () => {
      calls.push('events.subscribe');
    },
    call: async (cmd: { kind: string }) => {
      calls.push(cmd.kind);
      sent.push(cmd);
      return answer(cmd);
    },
    close: () => calls.push('close'),
  };
  return {
    client: client as unknown as HelperClient,
    calls,
    sent,
    emit: (e: SensorEvent, ran: HelperRan[] = []) => listeners.forEach((f) => f(e, ran)),
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
    // A helper restart replays its buffer; each event is handled once.
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
    // Reconnecting asks only for what came after the last event.
    const subscribed: (string | undefined)[] = [];
    (fake.client as unknown as { subscribe: (s?: string) => Promise<void> }).subscribe = async (
      since,
    ) => {
      subscribed.push(since);
    };
    await link.reconnect();
    expect(subscribed).toEqual(['e1']);
    link.stop();
  });

  it('does not run again what the helper’s own rules already ran', async () => {
    const fake = fakeClient(() => ({ actionId: 'j', summary: 'ok', undoable: false }));
    const link = new HelperLink(socket(), async () => fake.client);
    await link.tryConnect();
    const kill = { kind: 'process.kill' as const, pid: 4242, path: '/tmp/payload' };
    fake.emit(
      {
        id: 'e9',
        ts: 1,
        source: 'santa',
        kind: 'process.exec',
        process: { pid: 4242, path: '/tmp/payload' },
      },
      [
        {
          ruleId: 'known-bad-hash',
          at: 1,
          action: kill,
          outcome: { actionId: 'h1', summary: 'stopped', undoable: false },
        },
        {
          ruleId: 'known-bad-hash',
          at: 2,
          action: { kind: 'network.block', address: '203.0.113.9' },
          error: 'pf is off',
        },
      ],
    );
    // The helper's own finish time, so time-to-block stays honest.
    expect(await link.execute(kill)).toEqual({ at: 1 });
    expect(await link.execute({ kind: 'network.block', address: '203.0.113.9' })).toMatchObject({
      error: 'pf is off',
    });
    expect(fake.calls).toEqual(['events.subscribe']);
    // Only once: a later identical action goes to the helper.
    await link.execute(kill);
    expect(fake.calls).toEqual(['events.subscribe', 'process.kill']);
    link.stop();
  });

  it('sends the helper its rules, then only the lists it asks for, in parts', async () => {
    const fake = fakeClient((cmd) =>
      cmd.kind === 'detection.sync' ? { needLists: ['big'], preexec: null } : { complete: true },
    );
    const link = new HelperLink(socket(), async () => fake.client);
    await link.tryConnect();
    const big = Array.from({ length: 2500 }, (_, i) => `h${i}`);
    const out = await link.syncRules({
      rules: [],
      exceptions: [],
      selfPaths: ['/x'],
      lists: { big, small: ['a'] },
    });
    expect(out?.needLists).toEqual(['big']);
    const parts = fake.sent.filter((c) => c.kind === 'detection.list.set') as unknown as {
      part: number;
      parts: number;
      entries: string[];
    }[];
    expect(parts.map((p) => [p.part, p.parts, p.entries.length])).toEqual([
      [0, 3, 1000],
      [1, 3, 1000],
      [2, 3, 500],
    ]);
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
