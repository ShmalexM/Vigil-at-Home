import { DatabaseSync } from 'node:sqlite';
import type { SensorEvent } from '@vigil/core';
import { afterAll, describe, expect, it } from 'vitest';
import { PASSWORD_CANCELLED } from '../shared/helper-outcome.js';
import { Store } from './db/store.js';
import { Detector } from './detection.js';
import { DryRunExecutor } from './executor.js';
import { describeCondition } from './rule-editing.js';
import { VigilCore } from './service.js';
import { helperPolicy } from './testing.js';

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

  it('checks, saves and reverts an edit; bad JSON is reported, not thrown', async () => {
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
    expect((await editing.save(edited)).ok).toBe(true);
    expect(core.rules().find((r) => r.rule.id === RULE)?.rule.name).toBe('Pasted install script');
    expect(editing.view(RULE)!.edited).toBe(true);
    await editing.revert(RULE);
    expect(editing.view(RULE)!.edited).toBe(false);
  });

  it('excludes from an alert, and the exclusion survives a restart', async () => {
    const { core, store, editing, db } = setup();
    await core.handleEvent(pipeToShell('ABCDE12345'));
    const [alert] = alertsFor(store);
    expect(alert).toBeDefined();

    const r = await editing.excludeFromAlert(alert!.id, 'this_signer');
    expect(r).toMatchObject({ ok: true });
    expect(editing.view(RULE)!.exclusions).toEqual([
      'process.teamId is ABCDE12345 and process.signingId is com.example.inst',
    ]);
    await core.handleEvent(pipeToShell('ABCDE12345'));
    expect(alertsFor(store)).toHaveLength(1);

    const again = setup(db);
    expect(again.editing.view(RULE)!.exclusions).toHaveLength(1);
    await again.editing.removeExclusion(RULE, 0);
    expect(again.editing.view(RULE)!.exclusions).toEqual([]);
  });

  it('adds a hand-written exclusion and refuses one that would hide everything', async () => {
    const { editing } = setup();
    const ok = await editing.addExclusion(RULE, {
      field: 'process.parentPath',
      op: 'startsWith',
      value: '/Applications/Homebrew',
    });
    expect(ok.ok).toBe(true);
    const bad = await editing.addExclusion(RULE, { field: 'process.name', op: 'glob', value: '*' });
    expect(bad.ok).toBe(false);
    expect(bad.errors.join(' ')).toMatch(/specific/);
    const list = await editing.addExclusion(RULE, {
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

describe('rule edits that weaken a blocking rule wait for the helper', () => {
  const cleanups: (() => void)[] = [];
  afterAll(() => cleanups.forEach((f) => f()));
  const TEMP = 'exec-from-shared-temp';

  async function blocking(id: string) {
    const t = setup();
    const policy = helperPolicy(t.core.detector!);
    cleanups.push(policy.done);
    expect((await t.core.setRuleMode(id, 'block')).helper).toBe('applied');
    const rule = () => t.core.rules().find((r) => r.rule.id === id)!.rule;
    return { ...t, ...policy, rule };
  }

  let pid = 9000;
  const fromTemp = (): SensorEvent => ({
    id: `tmp-${++pid}`,
    ts: Date.now() + pid,
    source: 'test',
    kind: 'process.exec',
    process: {
      pid,
      path: `/tmp/payload-${pid}`,
      signing: 'unsigned',
      sha256: pid.toString(16).padStart(64, '0'),
    },
  });
  const notChanged = { ok: false, errors: [PASSWORD_CANCELLED], helper: 'declined' };

  it('leaves an app-only blocking rule as it was when the password is cancelled', async () => {
    const { core, store, editing, helper, asked, rule } = await blocking(TEMP);
    // The helper never runs this rule (it needs the "first seen" baseline), yet it asks.
    expect(core.detector!.helperRules().rules.map((r) => r.id)).not.toContain(TEMP);
    await core.handleEvent(fromTemp());
    const alert = store.listAlerts({}).find((a) => a.ruleId === TEMP);
    expect(alert).toBeDefined();
    const before = JSON.stringify(core.detector!.engine.getRule(TEMP));
    helper.approve = false;

    const add = await editing.addExclusion(TEMP, {
      field: 'process.sha256',
      op: 'eq',
      value: '1'.repeat(64),
    });
    expect(add).toMatchObject(notChanged);
    const stop = await editing.excludeFromAlert(alert!.id, 'this_binary');
    expect(stop).toMatchObject(notChanged);
    const json = JSON.parse(editing.view(TEMP)!.ruleJson) as Record<string, unknown>;
    expect(await editing.save(JSON.stringify({ ...json, mode: 'shadow' }))).toMatchObject(
      notChanged,
    );
    const mode = await core.setRuleMode(TEMP, 'shadow');
    expect(mode.helper).toBe('declined');
    expect(mode.rule.mode).toBe('block');

    expect(asked).toHaveLength(4);
    expect(asked[0]).toEqual(['change what “New program started from a temporary folder” blocks']);
    expect(rule().mode).toBe('block');
    expect(JSON.stringify(core.detector!.engine.getRule(TEMP))).toBe(before);
    expect(editing.view(TEMP)!.exclusions).toEqual([]);
    expect(core.detector!.stores.rules.list().map((r) => r.id)).not.toContain(TEMP);
    // It still blocks.
    await core.handleEvent(fromTemp());
    expect(store.listAlerts({}).filter((a) => a.ruleId === TEMP)).toHaveLength(2);
  });

  it('makes the change once the password is given', async () => {
    const { core, store, editing, asked, rule } = await blocking(TEMP);
    const add = await editing.addExclusion(TEMP, {
      field: 'process.sha256',
      op: 'eq',
      value: '1'.repeat(64),
    });
    expect(add).toMatchObject({ ok: true, helper: 'applied' });
    expect(editing.view(TEMP)!.exclusions).toHaveLength(1);
    await core.handleEvent(fromTemp());
    const alert = store.listAlerts({}).find((a) => a.ruleId === TEMP)!;
    expect(await editing.excludeFromAlert(alert.id, 'this_binary')).toMatchObject({ ok: true });
    expect(editing.view(TEMP)!.exclusions).toHaveLength(2);
    expect((await core.setRuleMode(TEMP, 'shadow')).helper).toBe('applied');
    expect(rule().mode).toBe('shadow');
    expect(asked).toHaveLength(3);
  });

  it('leaves a helper-run blocking rule as it was when the password is cancelled', async () => {
    const { core, editing, helper, asked, rule } = await blocking('known-bad-hash');
    expect(core.detector!.helperRules().rules.map((r) => r.id)).toContain('known-bad-hash');
    helper.approve = false;
    const add = await editing.addExclusion('known-bad-hash', {
      field: 'process.path',
      op: 'eq',
      value: '/Applications/Thing.app/Contents/MacOS/thing',
    });
    expect(add).toMatchObject(notChanged);
    expect(editing.view('known-bad-hash')!.exclusions).toEqual([]);
    expect((await core.setRuleMode('known-bad-hash', 'alert')).helper).toBe('declined');
    expect(rule().mode).toBe('block');
    expect(asked.flat().join(' ')).toMatch(/Known malware started/);
  });

  it('says why when the helper refuses, and changes nothing', async () => {
    const { core, editing, helper, rule } = await blocking(TEMP);
    helper.refuse = 'list known_bad_sha256 would drop 9000 entries; at most 5000';
    const json = JSON.parse(editing.view(TEMP)!.ruleJson) as Record<string, unknown>;
    expect(await editing.save(JSON.stringify({ ...json, mode: 'alert' }))).toMatchObject({
      ok: false,
      helper: 'failed',
      errors: ['Not changed: list known_bad_sha256 would drop 9000 entries; at most 5000'],
    });
    const mode = await core.setRuleMode(TEMP, 'alert');
    expect(mode).toMatchObject({ helper: 'failed', helperReason: helper.refuse });
    expect(rule().mode).toBe('block');
  });

  it('keeps a blocking rule of your own when deleting it is cancelled', async () => {
    const t = setup();
    const { helper, done } = helperPolicy(t.core.detector!);
    cleanups.push(done);
    const mine = {
      id: 'my-block',
      name: 'My block',
      description: 'Mine.',
      eventKinds: ['process.exec'],
      severity: 'high',
      mode: 'block',
      condition: { field: 'process.sha256', op: 'eq', value: '4'.repeat(64) },
      response: [{ kind: 'process.kill', pid: '{{process.pid}}' }],
      reasons: ['{{process.name}} is mine to block'],
    };
    const saved = await t.editing.save(JSON.stringify(mine));
    expect(saved).toMatchObject({ ok: true, helper: 'applied' });
    expect(t.core.detector!.hasRule('my-block')).toBe(true);
    helper.approve = false;
    expect(await t.editing.delete('my-block')).toMatchObject(notChanged);
    expect(t.core.detector!.hasRule('my-block')).toBe(true);
    helper.approve = true;
    expect(await t.editing.delete('my-block')).toMatchObject({ ok: true, helper: 'applied' });
    expect(t.core.detector!.hasRule('my-block')).toBe(false);
  });
});
