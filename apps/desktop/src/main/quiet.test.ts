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
  normalize,
  OLD_AGENT_ALERT_MS,
  patternOf,
  PROCESS_PROPOSAL_TTL_MS,
} from './quiet.js';
import { VigilCore } from './service.js';
import { makeExec, makeRule, memoryStore } from './testing.js';

const DAY = 24 * 60 * 60_000;
/** Noon local time, so a few hours either way stay on the same day. */
const NOON = new Date(2026, 9, 10, 12, 0, 0).getTime();

let n = 0;
/** One run of a shell command by an AI agent. */
function agentRun(args: string[], pid = 4000 + ++n, session = 'a'): EventOfKind<'process.exec'> {
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
      agent: { id: 'claude-code', session: sess(session), depth: 1 },
    },
  };
}

/** A valid agent session id (16 hex characters) for a short test name. */
function sess(name: string): string {
  return Buffer.from(name).toString('hex').padStart(16, '0').slice(-16);
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

function alertsSetup(start = NOON) {
  let now = start;
  const store = memoryStore();
  const svc = new AlertService(store, new DryRunExecutor(), () => now);
  const popups: Alert[] = [];
  svc.on('popup', (a) => popups.push(a));
  return { store, svc, popups, tick: (ms: number) => (now += ms), at: () => now };
}

const guard = makeRule({ id: 'agent-guard', mode: 'alert', severity: 'high', fidelity: 'high' });
const snapshot = (pid: number, dir: string) => [
  'sh',
  '-c',
  `source /Users/a/.claude/shell-snapshots/snapshot-zsh-${pid}-abc123.sh && cd ${dir} && kill -0 ${pid}`,
];

describe('normalizing what an agent did', () => {
  it('makes temp paths, numbers, ids and snapshot names alike', () => {
    expect(
      normalize(
        'cat /private/var/folders/xy/abc123/T/tmp.Xyz/out.json 8f14e45fceea167a5a36dedd4bea2543 4242',
      ),
    ).toBe('cat <tmp> <id> #');
    expect(normalize('ls /tmp/claude-501/run-77/x')).toBe('ls <tmp>');
    expect(normalize('. snapshot-zsh-1697-abc.sh')).toBe('. snapshot-<id>');
    expect(patternOf(agentRun(snapshot(11, '/tmp/a')))).toBe(
      patternOf(agentRun(snapshot(99, '/tmp/b'))),
    );
    expect(patternOf(agentRun(['git', 'status']))).not.toBe(patternOf(agentRun(['git', 'push'])));
  });

  it('turns a command into an anchored regex that matches its reruns and nothing more', () => {
    const regex = commandRegex(
      'node /Users/a/proj/vitest.mjs run --port 51234 --out /tmp/run-1/x.json',
    )!;
    const m = (s: string) => new RegExp(regex).test(s);
    expect(m('node /Users/a/proj/vitest.mjs run --port 6001 --out /tmp/run-77/x.json')).toBe(true);
    expect(m('node /Users/a/proj/vitest.mjs run --port 6001 --out /tmp/a;curl evil')).toBe(false);
    expect(m('node /Users/a/proj/vitest.mjs run --port 6001 --out /tmp/x && curl evil')).toBe(
      false,
    );
    expect(m('node /Users/a/proj/vitest.mjs run --port 1 --out /tmp/x.json curl')).toBe(false);
    expect(m('node /Users/a/proj/vitest.mjs run --port x1 --out /tmp/x.json')).toBe(false);
    // Too long for a rule's regex: no exception.
    expect(commandRegex(`sh -c ${'echo hello && '.repeat(30)}true`)).toBeUndefined();
    const ex = commandExclusion(agentRun(['python3', '-m', 'http.server', '8000']));
    expect(ex).toEqual({
      all: [
        { field: 'process.path', op: 'eq', value: '/bin/sh' },
        { field: 'process.commandLine', op: 'regex', value: '^python3 -m http\\.server [0-9]+$' },
      ],
    });
  });
});

describe('folding an agent’s repeats', () => {
  it('folds the same agent command across pids, temp dirs and sessions into one row', async () => {
    const { store, svc, popups, tick } = alertsSetup();
    const first = await svc.raise({
      rule: guard,
      events: [agentRun(snapshot(11, '/tmp/a'), 11, 'one')],
      actions: [],
    });
    for (let i = 0; i < 5; i++) {
      tick(60 * 60_000); // hours apart: well past the exact fold's 15 minutes
      await svc.raise({
        rule: guard,
        events: [agentRun(snapshot(20 + i, `/tmp/x${i}`), 20 + i, `s${i}`)],
        actions: [],
      });
    }
    const open = store.listAlerts({ status: 'open' });
    expect(open).toHaveLength(1);
    expect(open[0]!.id).toBe(first.id);
    expect(open[0]!.repeats?.count).toBe(6);
    expect(open[0]!.eventIds).toHaveLength(6);
    expect(popups).toHaveLength(1);
  });

  it('keeps other commands, other agents and other rules apart', async () => {
    const { store, svc } = alertsSetup();
    await svc.raise({ rule: guard, events: [agentRun(['git', 'status'])], actions: [] });
    await svc.raise({ rule: guard, events: [agentRun(['git', 'push'])], actions: [] });
    const other = agentRun(['git', 'status']);
    other.process.agent = { id: 'codex', session: sess('c'), depth: 1 };
    await svc.raise({ rule: guard, events: [other], actions: [] });
    await svc.raise({
      rule: { ...guard, id: 'agent-other' },
      events: [agentRun(['git', 'status'])],
      actions: [],
    });
    expect(store.listAlerts({ status: 'open' })).toHaveLength(4);
  });

  it('starts a new row a day after the last repeat, or once the row was answered', async () => {
    const { store, svc, tick } = alertsSetup();
    const a = await svc.raise({ rule: guard, events: [agentRun(['make', 'test'])], actions: [] });
    tick(AGENT_REPEAT_WINDOW_MS - 1);
    await svc.raise({ rule: guard, events: [agentRun(['make', 'test'])], actions: [] });
    expect(store.listAlerts({ status: 'open' })).toHaveLength(1);
    tick(AGENT_REPEAT_WINDOW_MS + 1);
    await svc.raise({ rule: guard, events: [agentRun(['make', 'test'])], actions: [] });
    expect(store.listAlerts({ status: 'open' })).toHaveLength(2);
    await svc.decide(a.id, { verdict: 'expected', release: false });
    const b = store.listAlerts({ status: 'open' })[0]!;
    await svc.decide(b.id, { verdict: 'expected', release: false });
    await svc.raise({ rule: guard, events: [agentRun(['make', 'test'])], actions: [] });
    expect(store.listAlerts({ status: 'open' })).toHaveLength(1);
  });

  it('replaces the rule’s suggestion with one for the newest process', async () => {
    const { store, svc, popups } = alertsSetup();
    const suspend = (pid: number): Action => ({ kind: 'process.suspend', pid });
    const a = await svc.raise({
      rule: guard,
      events: [agentRun(['rm', '-rf', 'build'], 101)],
      actions: [suspend(101)],
    });
    const again = await svc.raise({
      rule: guard,
      events: [agentRun(['rm', '-rf', 'build'], 202)],
      actions: [suspend(202)],
    });
    expect(again.id).toBe(a.id);
    expect(again.repeats?.count).toBe(2);
    const ps = store.listProposals({ alertId: a.id });
    expect(ps.filter((p) => p.status === 'pending').map((p) => p.action)).toEqual([suspend(202)]);
    expect(ps.filter((p) => p.status === 'expired')).toHaveLength(1);
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
  it('expires a pending process suggestion once the pid exits or it is hours old', async () => {
    const { store, svc, tick } = alertsSetup();
    const raise = (pid: number, path: string) =>
      svc.raise({
        rule: makeRule({ id: `r-${pid}`, mode: 'alert' }),
        events: [makeExec(path, pid)],
        actions: [{ kind: 'process.suspend', pid }],
      });
    const gone = await raise(11, '/tmp/gone');
    const running = await raise(22, '/tmp/running');
    const alive = (pid: number) => pid === 22;
    expect(svc.expireProcessProposals(alive, PROCESS_PROPOSAL_TTL_MS)).toBe(1);
    expect(store.hasPendingProposal(gone.id)).toBe(false);
    expect(store.listProposals({ alertId: gone.id })[0]).toMatchObject({ status: 'expired' });
    expect(store.hasPendingProposal(running.id)).toBe(true);
    // The alert itself is untouched: still open, undecided.
    expect(store.getAlert(gone.id)).toMatchObject({ status: 'open' });
    expect(store.getAlert(gone.id)!.decision).toBeUndefined();

    tick(PROCESS_PROPOSAL_TTL_MS + 1);
    expect(svc.expireProcessProposals(alive, PROCESS_PROPOSAL_TTL_MS)).toBe(1);
    expect(store.hasPendingProposal(running.id)).toBe(false);
  });

  it('leaves suggestions that are not about a process', async () => {
    const { store, svc } = alertsSetup();
    const a = await svc.raise({
      rule: makeRule({ id: 'net', mode: 'alert' }),
      events: [makeExec('/tmp/n', 3)],
      actions: [{ kind: 'network.block', address: '203.0.113.9' }],
    });
    expect(svc.expireProcessProposals(() => false, 0)).toBe(0);
    expect(store.hasPendingProposal(a.id)).toBe(true);
  });
});

function coreSetup(start = NOON) {
  let now = start;
  const store = memoryStore();
  const core = new VigilCore(store, new DryRunExecutor(), true, () => now);
  core.pidAlive = () => false;
  return { store, core, tick: (ms: number) => (now += ms), at: () => now };
}

describe('closing in bulk', () => {
  it('closes every safe alert of one rule, as expected, and leaves the rest', async () => {
    const { store, core, at } = coreSetup();
    const noisy = makeRule({ id: 'noisy', mode: 'alert', severity: 'high' });
    const ids: string[] = [];
    for (let i = 0; i < 4; i++) {
      ids.push(
        (
          await core.alerts.raise({
            rule: noisy,
            events: [makeExec(`/tmp/n${i}`, i + 1)],
            actions: [],
          })
        ).id,
      );
    }
    // One held something, one had an action taken: those stay.
    const block = makeRule({ id: 'noisy', mode: 'block', severity: 'high' });
    const held = await core.alerts.raise({
      rule: block,
      events: [makeExec('/tmp/held', 50)],
      actions: [{ kind: 'process.suspend', pid: 50 }],
    });
    const other = await core.alerts.raise({
      rule: makeRule({ id: 'other', mode: 'alert' }),
      events: [makeExec('/tmp/o', 9)],
      actions: [],
    });
    expect(core.bulkClosable('noisy')).toMatchObject({ rule: 4 });
    expect(await core.closeRuleAlerts('noisy', at())).toBe(4);
    for (const id of ids) {
      expect(store.getAlert(id)!.decision).toMatchObject({ verdict: 'expected', remember: false });
      expect(store.getAlert(id)!.decision!.note).toBeTruthy();
    }
    expect(store.getAlert(held.id)).toMatchObject({ status: 'open', containment: 'active' });
    expect(store.getAlert(other.id)).toMatchObject({ status: 'open' });
  });

  it('leaves alerts last seen after the confirm opened', async () => {
    const { store, core, at, tick } = coreSetup();
    const noisy = makeRule({ id: 'noisy', mode: 'alert' });
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

  it('closes agents’ alerts last seen over a week ago, and nothing else', async () => {
    const { store, core, tick, at } = coreSetup();
    const old = await core.alerts.raise({
      rule: guard,
      events: [agentRun(['old', 'cmd'])],
      actions: [],
    });
    const mine = await core.alerts.raise({
      rule: makeRule({ id: 'not-agent', mode: 'alert' }),
      events: [makeExec('/tmp/me', 3)],
      actions: [],
    });
    tick(OLD_AGENT_ALERT_MS + 1000);
    const fresh = await core.alerts.raise({
      rule: guard,
      events: [agentRun(['new', 'cmd'])],
      actions: [],
    });
    expect(core.bulkClosable()).toEqual({ rule: 0, oldAgents: 1 });
    expect(await core.closeOldAgentAlerts(at())).toBe(1);
    expect(store.getAlert(old.id)!.status).toBe('resolved');
    expect(store.getAlert(mine.id)!.status).toBe('open');
    expect(store.getAlert(fresh.id)!.status).toBe('open');
  });

  it('expires suggestions for exited processes first, so they don’t keep an alert open', async () => {
    const { store, core, tick, at } = coreSetup();
    const a = await core.alerts.raise({
      rule: guard,
      events: [agentRun(['rm', 'x'], 77)],
      actions: [{ kind: 'process.suspend', pid: 77 }],
    });
    tick(OLD_AGENT_ALERT_MS + 1000);
    expect(await core.closeOldAgentAlerts(at())).toBe(1);
    expect(store.getAlert(a.id)!.status).toBe('resolved');
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

  function run(port: number, extra: string[] = []): SensorEvent {
    n++;
    return {
      id: `t-${n}`,
      // Hours apart, past the engine's own one-alert-an-hour-per-program dedupe.
      ts: Date.now() + n * 2 * 60 * 60_000,
      source: 'test',
      kind: 'process.exec',
      process: {
        pid: 9000 + n,
        path: '/usr/local/bin/tool',
        args: ['tool', 'serve', '--root', `/tmp/build-${n}`, '--port', String(port), ...extra],
        signing: 'unsigned',
      },
    };
  }

  const newest = (store: Store) => store.listAlerts({ status: 'open' })[0]!;
  const waiting = (d: Detector) =>
    d.pipeline.list().filter((p) => p.status === 'awaiting_review' && p.kind === 'tuning');

  it('suggests a scoped exception on the third answer; approving it quiets reruns only', async () => {
    const { core, store, detector } = setup();
    for (let i = 0; i < 2; i++) {
      await core.handleEvent(run(5000 + i));
      await core.decide(newest(store).id, { verdict: 'expected', release: false });
    }
    expect(waiting(detector)).toHaveLength(0);
    await core.handleEvent(run(5002));
    await core.decide(newest(store).id, { verdict: 'expected', release: false });
    const [p] = waiting(detector);
    expect(p).toMatchObject({ provider: VIGIL_PROVIDER, rule: { id: 'tool-run' } });
    expect(p!.rationale).toMatch(/Don't show this again/);
    expect(p!.rule.exclusions.at(-1)).toEqual({
      all: [
        { field: 'process.path', op: 'eq', value: '/usr/local/bin/tool' },
        {
          field: 'process.commandLine',
          op: 'regex',
          value: expect.stringMatching(/^\^tool serve --root .*--port \[0-9\]\+\$$/),
        },
      ],
    });
    // A fourth answer doesn't queue a second one.
    await core.handleEvent(run(5003));
    await core.decide(newest(store).id, { verdict: 'expected', release: false });
    expect(waiting(detector)).toHaveLength(1);

    // Nothing changes until the user approves it.
    await core.handleEvent(run(5004));
    expect(store.countAlerts('open')).toBe(1);
    await core.decide(newest(store).id, { verdict: 'benign', release: false });
    await detector.acceptProposal(p!.id);
    await core.handleEvent(run(6001));
    expect(store.countAlerts('open')).toBe(0);
    await core.handleEvent(run(6002, ['--exec', 'curl']));
    expect(store.countAlerts('open')).toBe(1);
  });

  it('doesn’t count bulk closes, other commands or "Looks fine"', async () => {
    const { core, store, detector } = setup();
    await core.handleEvent(run(1));
    await core.decide(newest(store).id, { verdict: 'benign', release: false });
    await core.handleEvent(run(2, ['--verbose']));
    await core.decide(newest(store).id, { verdict: 'expected', release: false });
    await core.handleEvent(run(3));
    await core.clearNoticed([newest(store).id]);
    await core.handleEvent(run(4));
    await core.decide(newest(store).id, { verdict: 'expected', release: false });
    expect(waiting(detector)).toHaveLength(0);
  });
});
