import { DatabaseSync } from 'node:sqlite';
import type { SensorEvent } from '@vigil/core';
import { describe, expect, it } from 'vitest';
import { Store } from './db/store.js';
import { Detector } from './detection.js';
import { DryRunExecutor } from './executor.js';
import { VigilCore } from './service.js';

const BAD = 'a'.repeat(64);

function setup() {
  const db = new DatabaseSync(':memory:');
  const store = new Store(db);
  const executor = new DryRunExecutor();
  const core = new VigilCore(store, executor, true);
  const fetches: string[] = [];
  core.detector = new Detector(db, store, core.alerts, (e, o) => core.ingest(e, o), {
    installedAt: 1,
    selfPaths: ['/Applications/Vigil at Home.app'],
    feeds: {
      fetch: async (url: string) => {
        fetches.push(url);
        throw new Error('offline in tests');
      },
    },
  });
  const popups: string[] = [];
  core.alerts.on('popup', (a) => popups.push(a.id));
  return { core, store, executor, popups, fetches };
}

let n = 0;
function exec(path: string, sha256?: string): SensorEvent {
  n++;
  return {
    id: `ev-${n}`,
    ts: Date.now() + n,
    source: 'test',
    kind: 'process.exec',
    process: {
      pid: 5000 + n,
      path,
      ...(sha256 ? { sha256 } : {}),
      signing: 'unsigned',
      parentPath: '/bin/zsh',
    },
  };
}

describe('Detector', () => {
  it('stores ordinary events with how many rules checked them', async () => {
    const { core, store, popups } = setup();
    await core.handleEvent(exec('/usr/bin/git'));
    core.events.flush(); // events are written in batches
    const [view] = store.listEventViews();
    expect(view?.outcome?.checked).toBeGreaterThan(0);
    expect(view?.outcome?.matches).toEqual([]);
    expect(popups).toEqual([]);
  });

  it('blocks known malware inline, pops up, and shows the match in the feed', async () => {
    const { core, store, executor, popups } = setup();
    core.detector!.stores.lists.add('known_bad_sha256', BAD, { source: 'test', updatedAt: 1 });
    await core.handleEvent(exec('/Users/you/Downloads/evil', BAD));
    core.events.flush();

    const [view] = store.listEventViews({ matchedOnly: true });
    expect(view?.outcome?.matches).toEqual([
      { ruleId: 'known-bad-hash', ruleName: 'Known malware started', mode: 'block' },
    ]);
    expect(popups).toHaveLength(1);
    const alert = store.getAlert(popups[0]!);
    expect(alert?.containment).toBe('active');
    expect(executor.log.map((a) => a.kind)).toContain('process.kill');
  });

  it('learns from the verdict: malicious adds the program to the blocked list', async () => {
    const { core, popups, executor } = setup();
    core.detector!.stores.lists.add('known_bad_sha256', BAD, { source: 'test', updatedAt: 1 });
    await core.handleEvent(exec('/Users/you/Downloads/evil', BAD));
    await core.decide(popups[0]!, { verdict: 'malicious', release: false });
    expect(core.detector!.stores.lists.has('user_blocked_sha256', BAD)).toBe(true);
    expect(executor.log.filter((a) => a.kind === 'santa.rule.set').length).toBeGreaterThan(0);
  });

  it('lists the engine rules and lets the user change their mode', async () => {
    const { core } = setup();
    const rules = core.rules();
    expect(rules.find((r) => r.rule.id === 'known-bad-hash')?.rule.mode).toBe('block');
    core.detector!.syncHelper = async () => 'applied';
    expect(await core.setRuleMode('known-bad-hash', 'alert')).toMatchObject({
      rule: { id: 'known-bad-hash', mode: 'alert' },
      helper: 'applied',
    });
    expect(core.rules().find((r) => r.rule.id === 'known-bad-hash')?.rule.mode).toBe('alert');
  });

  it('the Rules screen hears that a cancelled password left the rule blocking', async () => {
    const { core } = setup();
    core.detector!.syncHelper = async () => 'declined';
    expect(await core.setRuleMode('known-bad-hash', 'alert')).toMatchObject({
      rule: { mode: 'block' },
      helper: 'declined',
    });
    core.detector!.syncHelper = async () => 'unavailable';
    expect(await core.setRuleMode('known-bad-hash', 'alert')).toMatchObject({
      rule: { mode: 'alert' },
      helper: 'unavailable',
    });
  });

  it('hands the helper the rules it can block with, and what they need', async () => {
    const { core, popups } = setup();
    core.detector!.stores.lists.add('known_bad_sha256', BAD, { source: 'test', updatedAt: 1 });
    await core.handleEvent(exec('/Users/you/Downloads/evil', BAD));
    await core.decide(popups[0]!, {
      verdict: 'benign',
      release: true,
      remember: true,
      scope: 'this_binary',
    });
    const set = core.detector!.helperRules();
    expect(set.rules.map((r) => r.id)).toContain('known-bad-hash');
    expect(set.rules.every((r) => r.mode === 'block')).toBe(true);
    expect(set.lists['known_bad_sha256']).toEqual([BAD]);
    expect(set.selfPaths).toEqual(['/Applications/Vigil at Home.app']);
    // The user's "this is fine" reaches the helper, so it stops blocking it too.
    expect(set.exceptions.length).toBeGreaterThan(0);
    await core.setRuleMode('known-bad-hash', 'alert');
    expect(core.detector!.helperRules().rules.map((r) => r.id)).not.toContain('known-bad-hash');
  });

  it('undoes a change in the app too when the user cancels the helper’s password', async () => {
    const { core, popups } = setup();
    const d = core.detector!;
    d.syncHelper = async () => 'declined';
    expect(await d.setMode('known-bad-hash', 'alert')).toBe('declined');
    expect(core.rules().find((r) => r.rule.id === 'known-bad-hash')?.rule.mode).toBe('block');

    d.stores.lists.add('known_bad_sha256', BAD, { source: 'test', updatedAt: 1 });
    await core.handleEvent(exec('/Users/you/Downloads/evil', BAD));
    await core.decide(popups[0]!, {
      verdict: 'benign',
      release: true,
      remember: true,
      scope: 'this_binary',
    });
    expect(d.stores.exceptions.all()).toEqual([]);
    expect(d.helperRules().exceptions).toEqual([]);

    d.syncHelper = async () => 'applied';
    expect(await d.setMode('known-bad-hash', 'alert')).toBe('applied');
    expect(core.rules().find((r) => r.rule.id === 'known-bad-hash')?.rule.mode).toBe('alert');
  });

  it('asks once when a release also remembers an exception', async () => {
    const { core, popups, executor } = setup();
    const d = core.detector!;
    const order: string[] = [];
    let send = () => {};
    const run = executor.execute.bind(executor);
    executor.execute = async (a) => (order.push(a.kind), run(a));
    Object.assign(executor, {
      approveHeld: async () => {
        order.push('password');
        send();
      },
    });
    d.syncHelper = (opts) => {
      if (!opts?.hold) return Promise.resolve('applied');
      order.push('rule change held');
      opts.onHeld?.();
      return new Promise((resolve) => {
        send = () => (order.push('rule change sent'), resolve('applied'));
      });
    };
    d.stores.lists.add('known_bad_sha256', BAD, { source: 'test', updatedAt: 1 });
    await core.handleEvent(exec('/Users/you/Downloads/evil', BAD));
    order.length = 0;
    await core.decide(popups[0]!, {
      verdict: 'benign',
      release: true,
      remember: true,
      scope: 'this_binary',
    });
    // The rule change waits for the release's dialog, then goes with that one password.
    expect(order[0]).toBe('rule change held');
    expect(order.slice(-2)).toEqual(['password', 'rule change sent']);
    expect(order.filter((o) => o === 'password')).toHaveLength(1);
    expect(d.stores.exceptions.all()).toHaveLength(1);
  });

  it('remembers nothing and asks no more when the release is cancelled', async () => {
    const { core, popups, executor, store } = setup();
    const d = core.detector!;
    const order: string[] = [];
    let refuse = () => {};
    Object.assign(executor, {
      approveHeld: async () => void order.push('password'),
      dropHeld: () => (order.push('dropped'), refuse()),
    });
    d.syncHelper = (opts) => {
      if (!opts?.hold) return Promise.resolve('applied');
      opts.onHeld?.();
      return new Promise((resolve) => (refuse = () => resolve('declined')));
    };
    d.stores.lists.add('known_bad_sha256', BAD, { source: 'test', updatedAt: 1 });
    await core.handleEvent(exec('/Users/you/Downloads/evil', BAD));
    // The user cancels the release's password dialog.
    executor.execute = async () => {
      throw new Error('not approved');
    };
    const alert = await core.decide(popups[0]!, {
      verdict: 'benign',
      release: true,
      remember: true,
      scope: 'this_binary',
    });
    expect(order).toEqual(['dropped']);
    expect(alert.decision).toBeUndefined();
    expect(store.getAlert(popups[0]!)?.decision).toBeUndefined();
    expect(d.stores.exceptions.all()).toHaveLength(0);
  });

  it('refreshes threat feeds on the scheduler and survives being offline', async () => {
    const { core, fetches } = setup();
    core.start();
    await new Promise((r) => setTimeout(r, 20));
    core.stop();
    expect(fetches.length).toBeGreaterThan(0);
  });
});
