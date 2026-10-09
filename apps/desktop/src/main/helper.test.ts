import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { SensorEvent } from '@vigil/core';
import type { HelperRan } from '@vigil/helper';
import { HelperCallError, type HelperClient } from '@vigil/helper/client';
import { describe, expect, it, vi } from 'vitest';
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
    // Recorded as real, so older rows without the field can read as unknown.
    expect(r.simulated).toBe(false);
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

  it('marks a quarantine refused for an installer-owned item, for the app to word', async () => {
    const fake = fakeClient((cmd) => {
      if (cmd.kind === 'file.quarantine')
        throw new HelperCallError('belongs to root', 'installer-owned');
      if (cmd.kind === 'persistence.disable')
        throw new HelperCallError(
          'no',
          (cmd as { path?: string }).path?.includes('/a/')
            ? 'startup-folder-linked'
            : 'not-your-item',
        );
      throw new HelperCallError('no', 'refused');
    });
    const link = new HelperLink(socket(), async () => fake.client);
    await link.tryConnect();
    const r = await link.execute({ kind: 'file.quarantine', path: '/Applications/X.app' });
    expect(r).toMatchObject({
      errorCode: 'installer-owned',
      error: expect.stringMatching(/^Not done/),
    });
    // Startup items in a linked folder, or another user's: their own codes.
    const linked = '/home/a/.config/autostart/x.desktop';
    expect(await link.execute({ kind: 'persistence.disable', path: linked })).toMatchObject({
      errorCode: 'startup-folder-linked',
    });
    const theirs = '/home/b/.config/autostart/y.desktop';
    expect(await link.execute({ kind: 'persistence.disable', path: theirs })).toMatchObject({
      errorCode: 'not-your-item',
    });
    // Other refusals carry no code.
    const other = await link.execute({ kind: 'process.suspend', pid: 5 });
    expect(other.errorCode).toBeUndefined();
    expect(other.error).toBe('Not done: no');
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
        {
          ruleId: 'known-bad-hash',
          at: 3,
          action: { kind: 'file.quarantine', path: '/tmp/payload' },
          error: 'Not moved in time',
          errorCode: 'move-stalled',
        },
      ],
    );
    // A move the helper stopped waiting on keeps its code, for the app's own line.
    expect(await link.execute({ kind: 'file.quarantine', path: '/tmp/payload' })).toEqual({
      at: 3,
      error: 'Not moved in time',
      errorCode: 'move-stalled',
    });
    // The helper's own finish time, so time-to-block stays honest.
    expect(await link.execute(kill)).toEqual({ at: 1, simulated: false });
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
    // Vigil's own programs go in a self grant of their own.
    expect(syncs[0]).not.toHaveProperty('selfPaths');
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
  it('reconnects at once after a dropped connection, without showing the helper as stopped', async () => {
    let n = 0;
    const link = new HelperLink(socket(), async () => {
      n++;
      return fakeClient(() => {
        throw new Error('connection reset');
      }).client;
    });
    const states: string[] = [];
    link.on('state', (s) => states.push(s));
    await link.tryConnect();
    await link.execute({ kind: 'process.kill', pid: 5 });
    await vi.waitFor(() => expect(n).toBe(2));
    await vi.waitFor(() => expect(states).toEqual(['connected', 'connected']));
    expect(link.state).toBe('connected');
    link.stop();
  });

  it('shows the helper as not running only when the reconnect fails too', async () => {
    let up = true;
    const link = new HelperLink(socket(), async () => {
      if (!up) throw new Error('ECONNREFUSED');
      return fakeClient(() => {
        throw new Error('connection reset');
      }).client;
    });
    await link.tryConnect();
    up = false;
    await link.execute({ kind: 'process.kill', pid: 5 });
    await vi.waitFor(() => expect(link.state).toBe('not_running'));
    link.stop();
  });

  it('treats a helper that connects but never answers as not running', async () => {
    vi.useFakeTimers();
    try {
      const fake = fakeClient(() => ({}));
      const hung = { ...fake.client, subscribe: () => new Promise<void>(() => {}) };
      const link = new HelperLink(socket(), async () => hung as unknown as HelperClient);
      const done = link.tryConnect();
      await vi.advanceTimersByTimeAsync(6000);
      await done;
      expect(link.state).toBe('not_running');
      expect(link.simulated).toBe(true);
      link.stop();
    } finally {
      vi.useRealTimers();
    }
  });
  it('does not loop on a helper that subscribes but never answers a query', async () => {
    vi.useFakeTimers();
    try {
      let connects = 0;
      const link = new HelperLink(socket(), async () => {
        connects++;
        // Subscribes at once; helper.status (pfctl, nft) hangs.
        return fakeClient(() => new Promise(() => {})).client;
      });
      const states: string[] = [];
      // As the app does: each new connection is health-checked at once.
      link.on('state', (st) => {
        states.push(st);
        if (st === 'connected') void link.query('helper.status').catch(() => {});
      });
      await link.tryConnect();
      await vi.advanceTimersByTimeAsync(5 * 60_000);
      expect(states).toContain('not_running');
      // Backoff: a handful of tries in five minutes, not one every 5 s.
      expect(connects).toBeLessThanOrEqual(6);
      link.stop();
    } finally {
      vi.useRealTimers();
    }
  });

  it('shows a crash-looping helper as not running, though each reconnect works', async () => {
    vi.useFakeTimers();
    try {
      let connects = 0;
      const link = new HelperLink(socket(), async () => {
        connects++;
        // Restarted by launchd or systemd, then gone again by the next check.
        return fakeClient(() => {
          throw new Error('connection closed');
        }).client;
      });
      const states: string[] = [];
      link.on('state', (st) => states.push(st));
      await link.tryConnect();
      // The health check pings once a minute.
      await link.ping();
      await vi.advanceTimersByTimeAsync(10);
      expect(link.state).toBe('connected');
      await vi.advanceTimersByTimeAsync(60_000);
      await link.ping();
      expect(link.state).toBe('not_running');
      expect(states).toContain('not_running');
      expect(connects).toBe(2);
      link.stop();
    } finally {
      vi.useRealTimers();
    }
  });
});
