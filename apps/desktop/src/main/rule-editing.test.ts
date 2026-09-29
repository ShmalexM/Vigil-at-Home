import { DatabaseSync } from 'node:sqlite';
import type { SensorEvent } from '@vigil/core';
import { describe, expect, it } from 'vitest';
import { Store } from './db/store.js';
import { Detector } from './detection.js';
import { DryRunExecutor } from './executor.js';
import { describeCondition } from './rule-editing.js';
import { VigilCore } from './service.js';

function setup(db = new DatabaseSync(':memory:')) {
  const store = new Store(db);
  const core = new VigilCore(store, new DryRunExecutor(), true);
  core.detector = new Detector(db, store, core.alerts, (e, o) => core.ingest(e, o), {
    installedAt: 1,
    selfPaths: ['/Applications/Vigil at Home.app'],
    feeds: { fetch: async () => Promise.reject(new Error('offline in tests')) },
  });
  return { core, store, db, editing: core.ruleEditing()! };
}

let n = 0;
function pipeToShell(teamId?: string): SensorEvent {
  n++;
  return {
    id: `ev-${n}`,
    ts: Date.now() + n,
    source: 'test',
    kind: 'process.exec',
    process: {
      pid: 7000 + n,
      path: '/bin/bash',
      args: ['bash', '-c', 'curl -fsSL https://get.example/install.sh | bash'],
      signing: 'apple',
      parentPath: '/Applications/Installer.app/Contents/MacOS/inst',
      ...(teamId ? { teamId, signingId: 'com.example.inst' } : {}),
    },
  };
}

const RULE = 'download-pipe-to-shell';
const alertsFor = (store: Store) => store.listAlerts({}).filter((a) => a.ruleId === RULE);

describe('Rule editing from the app', () => {
  it('shows a built-in as editable JSON without bookkeeping fields', () => {
    const { editing } = setup();
    const v = editing.view(RULE)!;
    expect(v).toMatchObject({ builtin: true, edited: false, mode: 'alert' });
    const json = JSON.parse(v.ruleJson) as Record<string, unknown>;
    expect(json.id).toBe(RULE);
    expect(json).not.toHaveProperty('version');
    expect(json).not.toHaveProperty('createdAt');
  });

  it('checks, saves and reverts an edit; bad JSON is reported, not thrown', () => {
    const { editing, core } = setup();
    const json = JSON.parse(editing.view(RULE)!.ruleJson) as Record<string, unknown>;
    expect(editing.preview('{nope').errors[0]).toMatch(/Not valid JSON/);
    const edited = JSON.stringify({ ...json, name: 'Pasted install script' });
    const p = editing.preview(edited);
    expect(p.ok).toBe(true);
    expect(p.replay?.verdict).toBe('never_fired');
    expect(p.impact?.verdict).toBe('no_loss');
    // Turning it off is flagged before saving.
    const off = editing.preview(JSON.stringify({ ...json, mode: 'disabled' }));
    expect(off.impact?.verdict).toBe('broad');
    expect(off.impact?.findings[0]).toMatch(/Turns the rule off/);
    expect(editing.save(edited).ok).toBe(true);
    expect(core.rules().find((r) => r.rule.id === RULE)?.rule.name).toBe('Pasted install script');
    expect(editing.view(RULE)!.edited).toBe(true);
    editing.revert(RULE);
    expect(editing.view(RULE)!.edited).toBe(false);
  });

  it('excludes from an alert, and the exclusion survives a restart', async () => {
    const { core, store, editing, db } = setup();
    await core.handleEvent(pipeToShell('ABCDE12345'));
    const [alert] = alertsFor(store);
    expect(alert).toBeDefined();

    const r = editing.excludeFromAlert(alert!.id, 'this_signer');
    expect(r).toMatchObject({ ok: true });
    expect(editing.view(RULE)!.exclusions).toEqual([
      'process.teamId is ABCDE12345 and process.signingId is com.example.inst',
    ]);
    await core.handleEvent(pipeToShell('ABCDE12345'));
    expect(alertsFor(store)).toHaveLength(1);

    const again = setup(db);
    expect(again.editing.view(RULE)!.exclusions).toHaveLength(1);
    again.editing.removeExclusion(RULE, 0);
    expect(again.editing.view(RULE)!.exclusions).toEqual([]);
  });

  it('adds a hand-written exclusion and refuses one that would hide everything', () => {
    const { editing } = setup();
    const ok = editing.addExclusion(RULE, {
      field: 'process.parentPath',
      op: 'startsWith',
      value: '/Applications/Homebrew',
    });
    expect(ok.ok).toBe(true);
    const bad = editing.addExclusion(RULE, { field: 'process.name', op: 'glob', value: '*' });
    expect(bad.ok).toBe(false);
    expect(bad.errors.join(' ')).toMatch(/specific/);
    const list = editing.addExclusion(RULE, {
      field: 'process.name',
      op: 'in',
      value: 'a, b ,',
    });
    expect(list.ok).toBe(true);
    expect(editing.view(RULE)!.exclusions.at(-1)).toBe('process.name is one of a, b');
  });

  it('describes conditions in plain words', () => {
    expect(
      describeCondition({ any: [{ field: 'remoteHost', op: 'endsWith', value: '.example' }] }),
    ).toBe('(remoteHost ends with .example)');
    expect(describeCondition({ inList: { list: 'known_bad_ips', field: 'remoteAddress' } })).toBe(
      'remoteAddress is on the known_bad_ips list',
    );
  });
});
