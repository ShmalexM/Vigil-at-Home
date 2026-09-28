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

  it('lists the engine rules and lets the user change their mode', () => {
    const { core } = setup();
    const rules = core.rules();
    expect(rules.find((r) => r.rule.id === 'known-bad-hash')?.rule.mode).toBe('block');
    core.setRuleMode('known-bad-hash', 'alert');
    expect(core.rules().find((r) => r.rule.id === 'known-bad-hash')?.rule.mode).toBe('alert');
  });

  it('refreshes threat feeds on the scheduler and survives being offline', async () => {
    const { core, fetches } = setup();
    core.start();
    await new Promise((r) => setTimeout(r, 20));
    core.stop();
    expect(fetches.length).toBeGreaterThan(0);
  });
});
