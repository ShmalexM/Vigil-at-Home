import { DatabaseSync } from 'node:sqlite';
import type { Action, Alert, EventOfKind, SensorEvent } from '@vigil/core';
import { DetectionRule, sqliteStores, VIGIL_PROVIDER } from '@vigil/detection';
import { describe, expect, it } from 'vitest';
import { AlertService, repeatKey } from './alerts.js';
import { Store } from './db/store.js';
import { Detector } from './detection.js';
import { DryRunExecutor } from './executor.js';
import {
  AGENT_REPEAT_WINDOW_MS,
  commandExclusion,
  commandRegex,
  liveChecker,
  normalize,
  OLD_AGENT_ALERT_MS,
  patternOf,
} from './quiet.js';
import { VigilCore } from './service.js';
import { makeExec, makeRule, memoryStore } from './testing.js';

const DAY = 24 * 60 * 60_000;
const HOUR = 60 * 60_000;
/** Noon local time, so a few hours either way stay on the same day. */
const NOON = new Date(2026, 9, 10, 12, 0, 0).getTime();

let n = 0;

/** A valid agent session id (16 hex characters) for a short test name. */
function sess(name: string): string {
  return Buffer.from(name).toString('hex').padStart(16, '0').slice(-16);
}

/** One run of a shell command by an AI agent. */
function agentRun(
  args: string[],
  pid = 4000 + ++n,
  session = 'a',
  agent = 'claude-code',
): EventOfKind<'process.exec'> {
  n++;
  return {
    id: `q-${n}`,
    ts: NOON + n,
    source: 'test',
    kind: 'process.exec',
    process: {
      pid,
      path: '/bin/sh',
      args,
      signing: 'apple',
      agent: { id: agent as 'claude-code', session: sess(session), depth: 1 },
    },
  };
}

/**
 * Claude Code running the same command again: only its shell snapshot's
 * name (a timestamp and a random suffix) and a mktemp folder change.
 */
const sameCommand = (i: number) => [
  'sh',
  '-c',
  `source /Users/a/.claude/shell-snapshots/snapshot-zsh-${1760000000000 + i}-r${i}x.sh && make test OUT=/var/folders/xy/abc/T/tmp.Q${i}w9ZpXk/out.log`,
];

function connect(remoteAddress: string, remotePort: number): EventOfKind<'network.connection'> {
  n++;
  return {
    id: `c-${n}`,
    ts: NOON + n,
    source: 'test',
    kind: 'network.connection',
    direction: 'outbound',
    protocol: 'tcp',
    remoteAddress,
    remotePort,
    process: {
      pid: 6000 + n,
      path: '/usr/bin/curl',
      signing: 'apple',
      agent: { id: 'claude-code', session: sess('a'), depth: 1 },
    },
  };
}

function santaBlock(path = '/bin/sh', sha256 = 'b'.repeat(64)): SensorEvent {
  n++;
  return {
    id: `s-${n}`,
    ts: NOON + n,
    source: 'test',
    kind: 'santa.decision',
    target: 'execution',
    decision: 'block',
    reason: 'BLOCK_BINARY',
    process: { pid: 7000 + n, path, sha256 },
  };
}

/** Liveness from a list of [pid, startTime] that still run. */
function running(...procs: Array<[number, number?]>) {
  return async () => (pid: number, startTime?: number) =>
    procs.some(
      ([p, t]) => p === pid && (t === undefined || startTime === undefined || t === startTime),
    );
}

function alertsSetup(start = NOON) {
  let now = start;
  const store = memoryStore();
  const svc = new AlertService(store, new DryRunExecutor(), () => now);
  svc.liveness = running();
  const popups: Alert[] = [];
  svc.on('popup', (a) => popups.push(a));
  return { store, svc, popups, tick: (ms: number) => (now += ms), at: () => now };
}

const guard = makeRule({ id: 'agent-guard', mode: 'alert', severity: 'high', fidelity: 'high' });
/** An agent rule that only notices (medium, badge): what bulk closes may take. */
const noticing = makeRule({
  id: 'agent-noticed',
  mode: 'alert',
  severity: 'medium',
  fidelity: 'low',
});

describe('normalizing what an agent did', () => {
  it('makes only random per-run text alike', () => {
    expect(
      normalize(
        'cat /private/var/folders/xy/abc123/T/tmp.Xyz9ab/out.json 8f14e45fceea167a5a36dedd4bea2543 1760000000',
      ),
    ).toBe('cat /private/var/folders/xy/abc123/T/tmp.<random>/out.json <id> <time>');
    expect(normalize('. snapshot-zsh-1697-abc.sh')).toBe('. snapshot-<id>.sh');
    // Ports, pids, addresses and file names stay.
    expect(normalize('curl http://45.33.2.1:4444/x && kill -0 4242')).toBe(
      'curl http://45.33.2.1:4444/x && kill -0 4242',
    );
    expect(patternOf(agentRun(sameCommand(1)))).toBe(patternOf(agentRun(sameCommand(2))));
  });

  it('keeps different scripts, addresses and ports apart', () => {
    const p = (args: string[]) => patternOf(agentRun(args));
    expect(p(['bash', '/tmp/build.sh'])).not.toBe(p(['bash', '/tmp/evil.sh']));
    expect(p(['curl', 'http://127.0.0.1:8080/x'])).not.toBe(p(['curl', 'http://45.33.2.1:4444/x']));
    expect(p(['curl', 'http://127.0.0.1:8080/x'])).not.toBe(p(['curl', 'http://127.0.0.1:4444/x']));
    expect(patternOf(connect('127.0.0.1', 8080))).not.toBe(patternOf(connect('45.33.2.1', 8080)));
    expect(patternOf(connect('127.0.0.1', 8080))).not.toBe(patternOf(connect('127.0.0.1', 4444)));
  });

  it('turns a command into an anchored regex where only random text may differ', () => {
    const base = 'node /Users/a/proj/vitest.mjs --out';
    const regex = commandRegex(`${base} /tmp/tmp.Ab12Cd/x.json --since 1760000000 --port 6001`)!;
    const m = (s: string) => new RegExp(regex).test(`${base} ${s}`);
    expect(m('/tmp/tmp.Zz99Yy/x.json --since 1760009999 --port 6001')).toBe(true);
    expect(m('/tmp/evil.sh --since 1760000000 --port 6001')).toBe(false);
    expect(m('/tmp/tmp.Ab12Cd/x.json --since 1760000000 --port 4444')).toBe(false);
    expect(m('/tmp/tmp.Ab12Cd/x.json --since 1760000000 --port 6001 && curl x')).toBe(false);
    // Too long for a rule's regex: no exception.
    expect(commandRegex(`sh -c ${'echo hello && '.repeat(30)}true`)).toBeUndefined();
  });

  it('scopes an exception to the binary and never offers one for an agent’s command', () => {
    expect(commandExclusion(agentRun(['python3', '-m', 'http.server', '8000']))).toBeUndefined();
    const own = makeExec('/usr/local/bin/tool', 5);
    own.process.args = ['tool', 'serve', '--port', '8000'];
    expect(commandExclusion(own)).toBeUndefined(); // no hash, no signature: nothing to pin
    own.process.sha256 = 'd'.repeat(64);
    expect(commandExclusion(own)).toEqual({
      all: [
        { field: 'process.sha256', op: 'eq', value: 'd'.repeat(64) },
        { field: 'process.commandLine', op: 'regex', value: '^tool serve --port 8000$' },
      ],
    });
  });
});

describe('folding an agent’s repeats', () => {
  it('folds the same agent command across pids, snapshots, temp names and sessions', async () => {
    const { store, svc, popups, tick } = alertsSetup();
    const first = await svc.raise({
      rule: guard,
      events: [agentRun(sameCommand(0), 11, 'one')],
      actions: [],
    });
    for (let i = 1; i <= 5; i++) {
      tick(HOUR); // well past the exact fold's 15 minutes
      await svc.raise({
        rule: guard,
        events: [agentRun(sameCommand(i), 20 + i, `s${i}`)],
        actions: [],
      });
    }
    const open = store.listAlerts({ status: 'open' });
    expect(open).toHaveLength(1);
    expect(open[0]!.id).toBe(first.id);
    expect(open[0]!.repeats?.count).toBe(6);
    expect(popups).toHaveLength(1);
  });

  it('never folds different scripts or addresses, and a new high payload notifies again', async () => {
    const { store, svc, popups } = alertsSetup();
    const raise = (args: string[], pid: number) =>
      svc.raise({
        rule: guard,
        events: [agentRun(args, pid)],
        actions: [{ kind: 'process.suspend', pid }],
      });
    await raise(['bash', '/tmp/build.sh'], 31);
    await raise(['bash', '/tmp/evil.sh'], 32);
    await raise(['curl', 'http://127.0.0.1:8080/x'], 33);
    await raise(['curl', 'http://45.33.2.1:4444/x'], 34);
    expect(store.listAlerts({ status: 'open' })).toHaveLength(4);
    expect(popups).toHaveLength(4);
  });

  it('keeps other agents, other binaries, other rules and other network peers apart', async () => {
    const { store, svc } = alertsSetup();
    const raise = (e: SensorEvent, rule = guard) => svc.raise({ rule, events: [e], actions: [] });
    await raise(agentRun(['git', 'status']));
    await raise(agentRun(['git', 'status'], 1, 'a', 'codex'));
    const other = agentRun(['git', 'status']);
    other.process.sha256 = 'e'.repeat(64);
    await raise(other);
    await raise(agentRun(['git', 'status']), { ...guard, id: 'agent-other' });
    await raise(connect('127.0.0.1', 8080));
    await raise(connect('127.0.0.1', 4444));
    await raise(connect('45.33.2.1', 8080));
    expect(store.listAlerts({ status: 'open' })).toHaveLength(7);
  });

  it('starts a new row a day after the first detection, however often repeats come', async () => {
    const { store, svc, tick } = alertsSetup();
    const make = () =>
      svc.raise({ rule: guard, events: [agentRun(['make', 'test'])], actions: [] });
    const a = await make();
    for (let i = 0; i < 23; i++) {
      tick(HOUR);
      await make();
    }
    expect(store.listAlerts({ status: 'open' })).toHaveLength(1);
    expect(AGENT_REPEAT_WINDOW_MS).toBe(DAY);
    tick(HOUR + 1);
    const b = await make();
    expect(b.id).not.toBe(a.id);
    expect(store.listAlerts({ status: 'open' })).toHaveLength(2);
    // An answered row takes no more repeats either.
    await svc.decide(b.id, { verdict: 'expected', release: false });
    const c = await make();
    expect([a.id, b.id]).not.toContain(c.id);
  });

  it('keeps the suggestion for a process that still runs, and adds the newest', async () => {
    const { store, svc, popups } = alertsSetup();
    const suspend = (pid: number): Action => ({
      kind: 'process.suspend',
      pid,
      startTime: pid * 10,
    });
    const raise = (pid: number) =>
      svc.raise({
        rule: guard,
        events: [agentRun(['rm', '-rf', 'build'], pid)],
        actions: [suspend(pid)],
      });
    svc.liveness = running([101, 1010]);
    const a = await raise(101);
    expect((await raise(202)).id).toBe(a.id);
    const pending = () =>
      store
        .listProposals({ alertId: a.id, status: 'pending' })
        .map((p) => (p.action as { pid: number }).pid)
        .sort();
    expect(pending()).toEqual([101, 202]);
    // 101 exits: the next repeat expires its suggestion; 202's stays while it runs.
    svc.liveness = running([202, 2020]);
    await raise(303);
    expect(pending()).toEqual([202, 303]);
    expect(popups).toHaveLength(1);
  });

  it('never folds into a row the user acted on, or a block rule’s detections', async () => {
    const { store, svc } = alertsSetup();
    const suspend: Action = { kind: 'process.suspend', pid: 5 };
    const a = await svc.raise({
      rule: guard,
      events: [agentRun(['rm', '-rf', 'x'], 5)],
      actions: [suspend],
    });
    svc.rejectProposal(store.listProposals({ alertId: a.id })[0]!.id);
    await svc.raise({ rule: guard, events: [agentRun(['rm', '-rf', 'x'], 6)], actions: [] });
    const block = makeRule({ id: 'agent-block', mode: 'block' });
    expect(repeatKey({ rule: block, events: [agentRun(['a', 'b'])], actions: [suspend] })).toBe(
      undefined,
    );
    expect(store.listAlerts({ status: 'open' })).toHaveLength(2);
  });
});

describe('Santa blocking a launch', () => {
  const santa = makeRule({
    id: 'santa-blocked-launch',
    mode: 'alert',
    severity: 'high',
    fidelity: 'high',
    eventKinds: ['santa.decision'],
  });

  it('raises one alert per program per day and pops up only the first time', async () => {
    const { store, svc, popups, tick } = alertsSetup();
    for (let i = 0; i < 4; i++) {
      await svc.raise({ rule: santa, events: [santaBlock()], actions: [] });
      tick(30 * 60_000);
    }
    expect(store.listAlerts()).toHaveLength(1);
    expect(store.listAlerts()[0]!.repeats?.count).toBe(4);
    expect(popups).toHaveLength(1);

    // Answered: later blocks that day still fold into it, quietly.
    const first = store.listAlerts()[0]!;
    await svc.decide(first.id, { verdict: 'expected', release: false });
    await svc.raise({ rule: santa, events: [santaBlock()], actions: [] });
    expect(store.listAlerts()).toHaveLength(1);
    expect(store.getAlert(first.id)!.status).toBe('resolved');

    // The next day: a new alert, but no popup for a program already shown once.
    tick(DAY);
    const next = await svc.raise({ rule: santa, events: [santaBlock()], actions: [] });
    expect(store.listAlerts()).toHaveLength(2);
    expect(next.notify).toBe('badge');
    expect(popups).toHaveLength(1);

    // Another program pops up as usual.
    await svc.raise({ rule: santa, events: [santaBlock('/tmp/x', 'c'.repeat(64))], actions: [] });
    expect(popups).toHaveLength(2);
  });
});

describe('expiring suggestions for processes that are gone', () => {
  const raise = (svc: AlertService, pid: number, startTime?: number) =>
    svc.raise({
      rule: makeRule({ id: `r-${pid}`, mode: 'alert' }),
      events: [makeExec(`/tmp/p${pid}`, pid)],
      actions: [{ kind: 'process.suspend', pid, ...(startTime ? { startTime } : {}) }],
    });

  it('expires only when the pid and start time no longer run, however old', async () => {
    const { store, svc, tick } = alertsSetup();
    const gone = await raise(svc, 11, 1000);
    const live = await raise(svc, 22, 2000);
    const reused = await raise(svc, 33, 3000);
    // 22 runs as itself; 33's pid now belongs to a process that started later.
    svc.liveness = running([22, 2000], [33, 9999]);
    expect(await svc.expireProcessProposals()).toBe(2);
    expect(store.listProposals({ alertId: gone.id })[0]).toMatchObject({ status: 'expired' });
    expect(store.listProposals({ alertId: reused.id })[0]).toMatchObject({ status: 'expired' });
    expect(store.hasPendingProposal(live.id)).toBe(true);
    // The alert itself is untouched: still open, undecided.
    expect(store.getAlert(gone.id)).toMatchObject({ status: 'open' });
    expect(store.getAlert(gone.id)!.decision).toBeUndefined();

    // A live process keeps its suggestion for days.
    tick(3 * DAY);
    expect(await svc.expireProcessProposals()).toBe(0);
    expect(store.hasPendingProposal(live.id)).toBe(true);
  });

  it('leaves suggestions that are not about a process', async () => {
    const { store, svc } = alertsSetup();
    const a = await svc.raise({
      rule: makeRule({ id: 'net', mode: 'alert' }),
      events: [makeExec('/tmp/n', 3)],
      actions: [{ kind: 'network.block', address: '203.0.113.9' }],
    });
    expect(await svc.expireProcessProposals()).toBe(0);
    expect(store.hasPendingProposal(a.id)).toBe(true);
  });

  it('reads this machine’s processes by pid and start time', async () => {
    const alive = await liveChecker([process.pid]);
    expect(alive(process.pid)).toBe(true);
    expect((await liveChecker([999_999]))(999_999)).toBe(false);
    // A pid ps refuses makes it list nothing; the others still count as running.
    expect((await liveChecker([process.pid, 999_999]))(process.pid)).toBe(true);
    // Same pid, a start time far from this process's: a different process.
    expect(alive(process.pid, 1)).toBe(false);
    const started = Date.now() - process.uptime() * 1000;
    expect(alive(process.pid, started)).toBe(true);
  });
});

function coreSetup(start = NOON) {
  let now = start;
  const store = memoryStore();
  const core = new VigilCore(store, new DryRunExecutor(), true, () => now);
  core.alerts.liveness = running();
  return { store, core, tick: (ms: number) => (now += ms), at: () => now };
}

describe('closing in bulk', () => {
  it('closes every safe alert of one rule, as expected, and leaves the rest', async () => {
    const { store, core, at } = coreSetup();
    const noisy = makeRule({ id: 'noisy', mode: 'alert', severity: 'medium', fidelity: 'low' });
    const raise = (path: string, pid: number, rule = noisy) =>
      core.alerts.raise({ rule, events: [makeExec(path, pid)], actions: [] });
    const ids: string[] = [];
    for (let i = 0; i < 4; i++) ids.push((await raise(`/tmp/n${i}`, i + 1)).id);
    // High, critical and anything held stay: they need a decision.
    const high = await raise('/tmp/high', 40, { ...noisy, severity: 'high' });
    const critical = await raise('/tmp/crit', 41, { ...noisy, severity: 'critical' });
    const held = await core.alerts.raise({
      rule: makeRule({ id: 'noisy', mode: 'block', severity: 'medium', fidelity: 'low' }),
      events: [makeExec('/tmp/held', 50)],
      actions: [{ kind: 'process.suspend', pid: 50 }],
    });
    const other = await raise('/tmp/o', 9, { ...noisy, id: 'other' });
    expect(core.bulkClosable('noisy')).toMatchObject({ rule: 4 });
    expect(await core.closeRuleAlerts('noisy', at())).toBe(4);
    for (const id of ids) {
      expect(store.getAlert(id)!.decision).toMatchObject({ verdict: 'expected', remember: false });
      expect(store.getAlert(id)!.decision!.note).toBeTruthy();
    }
    expect(store.getAlert(high.id)!.status).toBe('open');
    expect(store.getAlert(critical.id)!.status).toBe('open');
    expect(store.getAlert(held.id)).toMatchObject({ status: 'open', containment: 'active' });
    expect(store.getAlert(other.id)).toMatchObject({ status: 'open' });
  });

  it('leaves alerts last seen after the confirm opened', async () => {
    const { store, core, at, tick } = coreSetup();
    const noisy = makeRule({ id: 'noisy', mode: 'alert', severity: 'low', fidelity: 'low' });
    await core.alerts.raise({ rule: noisy, events: [makeExec('/tmp/a', 1)], actions: [] });
    const asked = at();
    tick(1000);
    const late = await core.alerts.raise({
      rule: noisy,
      events: [makeExec('/tmp/b', 2)],
      actions: [],
    });
    expect(await core.closeRuleAlerts('noisy', asked)).toBe(1);
    expect(store.getAlert(late.id)!.status).toBe('open');
  });

  it('closes agents’ Noticed alerts last seen over a week ago, never high ones', async () => {
    const { store, core, tick, at } = coreSetup();
    const raise = (args: string[], rule = noticing) =>
      core.alerts.raise({ rule, events: [agentRun(args)], actions: [] });
    const old = await raise(['old', 'cmd']);
    const oldHigh = await raise(['old', 'high'], guard);
    const mine = await core.alerts.raise({
      rule: makeRule({ id: 'not-agent', mode: 'alert', severity: 'medium', fidelity: 'low' }),
      events: [makeExec('/tmp/me', 3)],
      actions: [],
    });
    tick(OLD_AGENT_ALERT_MS + 1000);
    const fresh = await raise(['new', 'cmd']);
    expect(core.bulkClosable()).toEqual({ rule: 0, oldAgents: 1 });
    expect(await core.closeOldAgentAlerts(at())).toBe(1);
    expect(store.getAlert(old.id)!.status).toBe('resolved');
    expect(store.getAlert(oldHigh.id)!.status).toBe('open');
    expect(store.getAlert(mine.id)!.status).toBe('open');
    expect(store.getAlert(fresh.id)!.status).toBe('open');
  });

  it('expires suggestions for exited processes first, and keeps live ones', async () => {
    const { store, core, tick, at } = coreSetup();
    const raise = (args: string[], pid: number) =>
      core.alerts.raise({
        rule: noticing,
        events: [agentRun(args, pid)],
        actions: [{ kind: 'process.suspend', pid }],
      });
    const gone = await raise(['rm', 'x'], 77);
    const live = await raise(['rm', 'y'], 78);
    core.alerts.liveness = running([78]);
    tick(OLD_AGENT_ALERT_MS + 1000);
    expect(await core.closeOldAgentAlerts(at())).toBe(1);
    expect(store.getAlert(gone.id)!.status).toBe('resolved');
    expect(store.getAlert(live.id)!.status).toBe('open');
  });
});

describe('ageing out quiet alerts', () => {
  it('moves untouched low and silent Noticed alerts to History after the setting’s days', async () => {
    const { store, core, tick } = coreSetup();
    expect(core.ageOutDays()).toBe(7);
    const low = await core.alerts.raise({
      rule: makeRule({ id: 'low', mode: 'alert', severity: 'low', fidelity: 'low' }),
      events: [makeExec('/tmp/l', 1)],
      actions: [],
    });
    const silent = await core.alerts.raise({
      rule: makeRule({ id: 'listen', mode: 'alert', severity: 'medium', fidelity: 'low' }),
      events: [makeExec('/tmp/s', 2)],
      actions: [],
      notify: 'silent',
    });
    const badge = await core.alerts.raise({
      rule: makeRule({ id: 'mid', mode: 'alert', severity: 'medium', fidelity: 'low' }),
      events: [makeExec('/tmp/m', 3)],
      actions: [],
    });
    const high = await core.alerts.raise({
      rule: makeRule({ id: 'high', mode: 'alert', severity: 'high', fidelity: 'low' }),
      events: [makeExec('/tmp/h', 4)],
      actions: [],
    });
    tick(6 * DAY);
    expect(await core.ageOut()).toBe(0);
    tick(DAY + 1);
    expect(await core.ageOut()).toBe(2);
    expect(store.getAlert(low.id)!.decision?.note).toMatch(/7 days/);
    expect(store.getAlert(silent.id)!.status).toBe('resolved');
    expect(store.getAlert(badge.id)!.status).toBe('open'); // medium and not silent
    expect(store.getAlert(high.id)!.status).toBe('open'); // needs a decision
  });

  it('never ages out when set to 0', async () => {
    const { store, core, tick } = coreSetup();
    core.setAgeOutDays(0);
    const low = await core.alerts.raise({
      rule: makeRule({ id: 'low', mode: 'alert', severity: 'low', fidelity: 'low' }),
      events: [makeExec('/tmp/l', 1)],
      actions: [],
    });
    tick(365 * DAY);
    expect(await core.ageOut()).toBe(0);
    expect(store.getAlert(low.id)!.status).toBe('open');
  });
});

describe('"Don’t show this again" after repeated "That was me"', () => {
  const rule = DetectionRule.parse({
    id: 'tool-run',
    version: 1,
    name: 'Tool ran',
    description: '',
    origin: 'user',
    mode: 'alert',
    severity: 'medium',
    fidelity: 'high',
    eventKinds: ['process.exec'],
    condition: { field: 'process.path', op: 'eq', value: '/usr/local/bin/tool' },
    reasons: ['tool ran'],
    tags: [],
    createdAt: 1,
    updatedAt: 1,
  });
  const SHA = 'd'.repeat(64);

  function setup() {
    const db = new DatabaseSync(':memory:');
    sqliteStores(db).rules.save(rule, 1);
    const store = new Store(db);
    const core = new VigilCore(store, new DryRunExecutor(), true);
    core.detector = new Detector(db, store, core.alerts, (e, o) => core.ingest(e, o), {
      installedAt: 1,
      selfPaths: ['/Applications/Vigil at Home.app'],
      platform: 'darwin',
      feeds: { fetch: async () => Promise.reject(new Error('offline in tests')) },
    });
    return { core, store, detector: core.detector };
  }

  /** The tool run again: only its mktemp folder and timestamp change. */
  function run(o: { port?: number; sha256?: string; extra?: string[] } = {}): SensorEvent {
    n++;
    return {
      id: `t-${n}`,
      // Hours apart, past the engine's own one-alert-an-hour-per-program dedupe.
      ts: Date.now() + n * 2 * HOUR,
      source: 'test',
      kind: 'process.exec',
      process: {
        pid: 9000 + n,
        path: '/usr/local/bin/tool',
        sha256: o.sha256 ?? SHA,
        args: [
          'tool',
          'serve',
          '--root',
          `/tmp/tmp.R${n}x7Qa/site`,
          '--since',
          String(1760000000 + n),
          '--port',
          String(o.port ?? 5000),
          ...(o.extra ?? []),
        ],
        signing: 'unsigned',
      },
    };
  }

  const newest = (store: Store) => store.listAlerts({ status: 'open' })[0]!;
  const waiting = (d: Detector) =>
    d.pipeline.list().filter((p) => p.status === 'awaiting_review' && p.kind === 'tuning');

  it('suggests an exception for that binary and command on the third answer', async () => {
    const { core, store, detector } = setup();
    for (let i = 0; i < 2; i++) {
      await core.handleEvent(run());
      await core.decide(newest(store).id, { verdict: 'expected', release: false });
    }
    expect(waiting(detector)).toHaveLength(0);
    await core.handleEvent(run());
    await core.decide(newest(store).id, { verdict: 'expected', release: false });
    const [p] = waiting(detector);
    expect(p).toMatchObject({ provider: VIGIL_PROVIDER, rule: { id: 'tool-run' } });
    expect(p!.rationale).toMatch(/Don't show this again/);
    expect(p!.rule.exclusions.at(-1)).toEqual({
      all: [
        { field: 'process.sha256', op: 'eq', value: SHA },
        {
          field: 'process.commandLine',
          op: 'regex',
          value: expect.stringMatching(/--port 5000\$$/),
        },
      ],
    });
    // A fourth answer doesn't queue a second one.
    await core.handleEvent(run());
    await core.decide(newest(store).id, { verdict: 'expected', release: false });
    expect(waiting(detector)).toHaveLength(1);

    // Nothing changes until the user approves it; then only the same run is quiet.
    await core.handleEvent(run());
    expect(store.countAlerts('open')).toBe(1);
    await core.decide(newest(store).id, { verdict: 'benign', release: false });
    await detector.acceptProposal(p!.id);
    await core.handleEvent(run());
    expect(store.countAlerts('open')).toBe(0);
    await core.handleEvent(run({ port: 4444 }));
    expect(store.countAlerts('open')).toBe(1);
    await core.handleEvent(run({ sha256: 'f'.repeat(64) }));
    expect(store.countAlerts('open')).toBe(2);
    await core.handleEvent(run({ extra: ['--exec', 'curl'] }));
    expect(store.countAlerts('open')).toBe(3);
  });

  it('doesn’t count bulk closes, other commands or "Looks fine"', async () => {
    const { core, store, detector } = setup();
    await core.handleEvent(run());
    await core.decide(newest(store).id, { verdict: 'benign', release: false });
    await core.handleEvent(run({ extra: ['--verbose'] }));
    await core.decide(newest(store).id, { verdict: 'expected', release: false });
    await core.handleEvent(run());
    await core.clearNoticed([newest(store).id]);
    await core.handleEvent(run());
    await core.decide(newest(store).id, { verdict: 'expected', release: false });
    expect(waiting(detector)).toHaveLength(0);
  });
});
