import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { SensorEvent } from '@vigil/core';
import type { HelperRan } from '@vigil/helper';
import type { HelperClient } from '@vigil/helper/client';
import { describe, expect, it } from 'vitest';
import { HelperLink, RELEASE_TIMEOUT_MS } from './helper.js';

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

  it('sends rules and their lists as one sync, then list-only changes on their own', async () => {
    const fake = fakeClient((cmd) =>
      cmd.kind === 'detection.sync'
        ? { applied: true, needLists: [], preexec: 'pending' }
        : { complete: true },
    );
    const link = new HelperLink(socket(), async () => fake.client);
    await link.tryConnect();
    const big = Array.from({ length: 2500 }, (_, i) => `h${i}`);
    const set = {
      rules: [],
      appRules: [],
      exceptions: [],
      selfPaths: ['/x'],
      lists: { big, small: ['a'] },
    };
    const out = await link.syncRules(set, { syncId: 'abc' });
    expect(out).toMatchObject({ applied: true });
    // One command: the rules and every list's contents, so they go in together.
    const syncs = fake.sent.filter((c) => c.kind === 'detection.sync') as unknown as {
      syncId: string;
      entries: Record<string, string[]>;
    }[];
    expect(syncs).toHaveLength(1);
    expect(syncs[0]!.syncId).toBe('abc');
    expect(Object.keys(syncs[0]!.entries).sort()).toEqual(['big', 'small']);
    expect(syncs[0]!.entries['big']).toHaveLength(2500);
    expect(fake.sent.filter((c) => c.kind === 'detection.list.set')).toEqual([]);

    // Only a list changed (a feed refresh): it goes on its own, in parts.
    await link.syncRules({ ...set, lists: { big: [...big, 'h-new'], small: ['a'] } });
    const parts = fake.sent.filter((c) => c.kind === 'detection.list.set') as unknown as {
      list: string;
      part: number;
      parts: number;
      entries: string[];
    }[];
    expect(parts.map((p) => [p.list, p.part, p.parts, p.entries.length])).toEqual([
      ['big', 0, 3, 1000],
      ['big', 1, 3, 1000],
      ['big', 2, 3, 501],
    ]);
    expect(fake.sent.filter((c) => c.kind === 'detection.sync')).toHaveLength(1);
    link.stop();
  });

  it('gives each sync a deadline no later than when the app stops waiting', async () => {
    const fake = fakeClient((cmd) =>
      cmd.kind === 'detection.sync' ? { applied: true, needLists: [], preexec: null } : {},
    );
    const link = new HelperLink(socket(), async () => fake.client);
    await link.tryConnect();
    const before = Date.now();
    await link.syncRules(
      { rules: [], appRules: [], exceptions: [], selfPaths: [], lists: {} },
      { syncId: 'd1' },
    );
    const after = Date.now();
    const [sync] = fake.sent.filter((c) => c.kind === 'detection.sync') as unknown as {
      notAfter: number;
    }[];
    // The helper refuses it past this point, so a late password can't apply
    // a change the app already counted as cancelled.
    expect(sync!.notAfter).toBeGreaterThan(before);
    expect(sync!.notAfter).toBeLessThan(after + RELEASE_TIMEOUT_MS);
    link.stop();
  });

  it('sends the sync again with the lists the helper says it lacks', async () => {
    let first = true;
    const fake = fakeClient((cmd) => {
      if (cmd.kind !== 'detection.sync') return { complete: true };
      const carried = Object.keys((cmd as { entries?: object }).entries ?? {});
      if (first) {
        first = false;
        // The helper says it still lacks a list and changes nothing.
        return { applied: false, needLists: ['small'], preexec: null };
      }
      expect(carried).toContain('small');
      return { applied: true, needLists: [], preexec: null };
    });
    const link = new HelperLink(socket(), async () => fake.client);
    await link.tryConnect();
    const out = await link.syncRules({
      rules: [],
      appRules: [],
      exceptions: [],
      selfPaths: [],
      lists: { small: ['a'] },
    });
    expect(out).toMatchObject({ applied: true });
    expect(fake.sent.filter((c) => c.kind === 'detection.sync')).toHaveLength(2);
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
