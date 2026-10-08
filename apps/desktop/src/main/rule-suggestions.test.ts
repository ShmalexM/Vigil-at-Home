import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import type { SensorEvent } from '@vigil/core';
import { INDICATOR_RULE, type AnalyzeRunner } from '@vigil/detection';
import { listDigest } from '@vigil/detection/fastpath';
import { FastPath, type DetectionSync } from '@vigil/helper';
import { afterAll, describe, expect, it } from 'vitest';
import { Store } from './db/store.js';
import { Detector } from './detection.js';
import { DryRunExecutor } from './executor.js';
import { RuleSuggestions } from './rule-suggestions.js';
import { VigilCore } from './service.js';

const pasteRule = {
  id: 'paste-site',
  name: 'Paste site',
  description: 'A program talked to a paste site.',
  eventKinds: ['network.connection'],
  severity: 'medium',
  mode: 'alert',
  condition: { field: 'remoteHost', op: 'in', value: ['pastebin.com', 'paste.ee'] },
  reasons: ['{{process.name}} talked to {{remoteHost}}'],
};

function setup(answer: unknown, db = new DatabaseSync(':memory:')) {
  const store = new Store(db);
  const core = new VigilCore(store, new DryRunExecutor(), true);
  const detector = new Detector(db, store, core.alerts, (e, o) => core.ingest(e, o), {
    installedAt: 1,
    selfPaths: ['/Applications/Vigil at Home.app'],
    feeds: { fetch: async () => Promise.reject(new Error('offline in tests')) },
  });
  core.detector = detector;
  const seen: unknown[] = [];
  const runner: AnalyzeRunner = {
    async run(req) {
      const tool = req.tools?.find((t) => t.name === 'get_telemetry_summary');
      seen.push(await tool?.run({ sinceHours: 24 }));
      return { ok: true, value: req.output.parse(answer), provider: 'claude' };
    },
  };
  detector.attachReviewer(() => runner);
  const ui = new RuleSuggestions(
    detector,
    () => true,
    (id) => store.getAlertDetection(id),
  );
  return { core, store, db, detector, seen, ui };
}

let n = 0;
function connect(host: string, path = '/Users/alex/Library/.cache/upd'): SensorEvent {
  n++;
  return {
    id: `ev-${n}`,
    ts: Date.now() - 1000 + n,
    source: 'test',
    kind: 'network.connection',
    direction: 'outbound',
    protocol: 'tcp',
    remoteAddress: `104.20.1.${n % 250}`,
    remoteHost: host,
    process: { pid: 500 + n, path, signing: path.startsWith('/Users') ? 'adhoc' : 'developer_id' },
  } as SensorEvent;
}

const answer = {
  newRules: [{ ruleJson: JSON.stringify(pasteRule), rationale: 'Paste sites.', evidence: [] }],
  tunings: [],
  retirements: [],
  summary: 'One new rule for paste sites.',
};

describe('AI rule suggestions in the app', () => {
  it('a review queues a checked suggestion; accepting turns it on in alert mode', async () => {
    const { core, detector, ui } = setup(answer);
    for (let i = 0; i < 3; i++) await core.handleEvent(connect('paste.ee'));
    core.events.flush();
    expect(await detector.reviewRules({ force: true })).toMatchObject({ ran: true, queued: 1 });

    const v = ui.view();
    expect(v.review).toMatchObject({
      available: true,
      lastSummary: 'One new rule for paste sites.',
    });
    expect(v.pending).toHaveLength(1);
    const s = v.pending[0]!;
    expect(s).toMatchObject({ kind: 'new_rule', ruleId: 'ai-paste-site', provider: 'claude' });
    expect(s.condition).toBe('remoteHost is one of pastebin.com, paste.ee');
    expect(s.replay?.hits).toBe(3);
    expect(s.impact?.verdict).toBe('no_loss');
    expect(JSON.parse(s.ruleJson!)).not.toHaveProperty('version');

    // Nothing is live until the user accepts.
    expect(detector.hasRule('ai-paste-site')).toBe(false);
    expect(await ui.accept(s.id)).toBe('unavailable');
    expect(detector.rules().find((r) => r.rule.id === 'ai-paste-site')?.mode).toBe('alert');
    expect(ui.view().pending).toHaveLength(0);
    expect(ui.view().recent[0]).toMatchObject({ status: 'approved', ruleName: 'Paste site' });
  });

  it('accepted rules and review state survive a restart', async () => {
    const db = new DatabaseSync(':memory:');
    const first = setup(answer, db);
    await first.detector.reviewRules({ force: true });
    await first.ui.accept(first.ui.view().pending[0]!.id);
    const again = setup(answer, db);
    expect(again.detector.hasRule('ai-paste-site')).toBe(true);
    expect(again.ui.view().review.lastOkAt).toBeDefined();
    // The next scheduled review waits a day.
    expect(await again.detector.reviewRules()).toMatchObject({ ran: false });
  });

  it('accepting leaves everything as it was if the helper’s password is cancelled', async () => {
    const { detector, ui } = setup(answer);
    await detector.reviewRules({ force: true });
    const id = ui.view().pending[0]!.id;
    detector.syncHelper = async () => 'declined';
    expect(await ui.accept(id, 'block')).toBe('declined');
    expect(detector.hasRule('ai-paste-site')).toBe(false);
    expect(detector.stores.rules.list().map((r) => r.id)).not.toContain('ai-paste-site');
    expect(ui.view().pending.map((p) => p.id)).toEqual([id]);
  });

  it('dismissing keeps the rule off and tells the AI next time', async () => {
    const { detector, ui, seen } = setup(answer);
    await detector.reviewRules({ force: true });
    ui.dismiss(ui.view().pending[0]!.id, 'Too broad for me');
    expect(detector.hasRule('ai-paste-site')).toBe(false);
    await detector.reviewRules({ force: true });
    expect(JSON.stringify(seen.at(-1))).toContain('Too broad for me');
  });

  it('passes classifier leads that no rule matched to the review', async () => {
    const { core, store, detector, seen } = setup({ ...answer, newRules: [] });
    const e = connect('weird.example', '/Applications/Tool.app/Contents/MacOS/tool');
    await core.handleEvent(e);
    core.events.flush();
    store.setEventLabels([
      {
        eventId: e.id,
        label: { label: 'suspicious', score: 0.8, reason: 'odd host', by: 'model', at: 1 },
      },
    ]);
    await detector.reviewRules({ force: true });
    expect(JSON.stringify(seen[0])).toContain(
      '/Applications/Tool.app/Contents/MacOS/tool -> weird.example',
    );
  });

  describe('drafted by the Lead dog in chat', () => {
    const scout = { provider: 'codex', name: 'Scout' };
    async function withAlert(sha256?: string) {
      const t = setup(answer);
      await t.detector.reviewRules({ force: true });
      await t.ui.accept(t.ui.view().pending[0]!.id);
      const e = connect('paste.ee');
      if (sha256 && 'process' in e && e.process) e.process.sha256 = sha256;
      await t.core.handleEvent(e);
      t.core.events.flush();
      const alert = t.store.listAlerts().find((a) => t.store.getAlertDetection(a.id));
      return { ...t, alertId: alert!.id };
    }

    it('waits under Suggested changes, marked as the Lead dog’s, and changes nothing until accepted', async () => {
      const { detector, ui, alertId } = await withAlert();
      const d = ui.draft(
        { kind: 'exclude', alertId, scope: 'this_path', why: 'That is my own updater.' },
        scout,
      );
      expect(d).toMatchObject({
        status: 'waiting',
        ruleId: 'ai-paste-site',
        ruleName: 'Paste site',
        change: 'Stop "Paste site" matching when process.path is /Users/alex/Library/.cache/upd',
      });
      const s = ui.view().pending.find((p) => p.id === d.proposalId)!;
      expect(s).toMatchObject({
        kind: 'tuning',
        by: 'Scout',
        provider: 'codex',
        rationale: 'That is my own updater.',
        exclusion: 'process.path is /Users/alex/Library/.cache/upd',
      });
      expect(s.impact).toBeDefined();
      expect(detector.engine.getRule('ai-paste-site')!.exclusions).toHaveLength(0);

      // Asking again finds the one already waiting instead of adding another.
      const again = ui.draft(
        { kind: 'exclude', alertId, scope: 'this_path', why: 'Still my updater.' },
        scout,
      );
      expect(again).toMatchObject({ status: 'already', proposalId: d.proposalId });
      expect(ui.view().pending).toHaveLength(1);

      await ui.accept(d.proposalId!);
      expect(detector.engine.getRule('ai-paste-site')!.exclusions).toHaveLength(1);
    });

    it('turns a rule down only to Shadow, and only once accepted', async () => {
      const { detector, ui, alertId } = await withAlert();
      const d = ui.draft({ kind: 'turn-down', alertId, why: 'Too noisy for me.' }, scout);
      expect(d).toMatchObject({ status: 'waiting', change: expect.stringMatching(/to Shadow/) });
      expect(ui.view().pending[0]).toMatchObject({
        kind: 'retire',
        retireTo: 'shadow',
        by: 'Scout',
      });
      const rule = () => detector.rules().find((r) => r.rule.id === 'ai-paste-site')!;
      expect(rule().mode).toBe('alert');
      await ui.accept(d.proposalId!);
      expect(rule().mode).toBe('shadow');
    });

    it('says why a draft was refused', async () => {
      const { ui, alertId } = await withAlert();
      expect(ui.draft({ kind: 'exclude', alertId: 'nope', why: 'x' }, scout)).toMatchObject({
        status: 'failed',
        note: expect.stringMatching(/detection rule/),
      });
      expect(ui.draft({ kind: 'exclude', ruleId: 'ai-paste-site', why: 'x' }, scout)).toMatchObject(
        { status: 'failed', note: expect.stringMatching(/needs the alert/) },
      );
      // A host exclusion on an alert about a host is fine; one the event can't support is not.
      expect(
        ui.draft({ kind: 'exclude', alertId, scope: 'this_signer', why: 'x' }, scout),
      ).toMatchObject({ status: 'failed', note: expect.stringMatching(/doesn’t say enough/) });
      expect(ui.draft({ kind: 'turn-down', ruleId: 'nope', why: 'x' }, scout)).toMatchObject({
        status: 'failed',
        note: expect.stringMatching(/no rule/),
      });
      expect(ui.view().pending).toHaveLength(0);
    });

    it('never quiets an alert about a program on the blocked list', async () => {
      const bad = 'f'.repeat(64);
      const { detector, ui, alertId } = await withAlert(bad);
      detector.engine.stores.lists.add('user_blocked_sha256', bad, {
        source: 'user',
        updatedAt: 0,
      });
      for (const req of [
        { kind: 'exclude' as const, alertId, scope: 'this_path' as const, why: 'It is mine.' },
        { kind: 'exclude' as const, alertId, why: 'It is mine.' },
        { kind: 'turn-down' as const, alertId, why: 'Too noisy for me.' },
      ]) {
        expect(ui.draft(req, scout)).toMatchObject({
          status: 'failed',
          note: expect.stringMatching(/on your blocked list/),
        });
      }
      expect(ui.view().pending).toHaveLength(0);
    });

    it('never turns down or excludes from a blocked-list or known-bad rule, even by rule id alone', async () => {
      const { detector, ui } = await withAlert();
      // On the list, but its last event was long ago: the replay has nothing to go on.
      detector.engine.stores.lists.add('known_bad_sha256', '7'.repeat(64), {
        source: 'feed',
        updatedAt: 0,
      });
      for (const ruleId of ['known-bad-hash', 'user-blocked-hash', 'known-bad-destination'])
        expect(
          ui.draft({ kind: 'turn-down', ruleId, why: 'It never fires.' }, scout),
        ).toMatchObject({ status: 'failed', note: INDICATOR_RULE });
      expect(ui.view().pending).toHaveLength(0);
      expect(detector.rules().find((r) => r.rule.id === 'known-bad-hash')!.mode).toBe('block');
    });

    it('withdraws a waiting exclusion once its program is confirmed malicious, and refuses to accept it', async () => {
      const bad = 'e'.repeat(64);
      const { detector, ui, alertId } = await withAlert(bad);
      const d = ui.draft(
        { kind: 'exclude', alertId, scope: 'this_path', why: 'That is my own updater.' },
        scout,
      );
      expect(d.status).toBe('waiting');
      await detector.learn(alertId, { at: Date.now(), verdict: 'malicious', remember: false });
      expect(ui.view().pending).toHaveLength(0);
      expect(ui.view().recent[0]).toMatchObject({ id: d.proposalId, status: 'withdrawn' });
      await expect(ui.accept(d.proposalId!)).rejects.toThrow(/withdrawn/);
      expect(detector.engine.getRule('ai-paste-site')!.exclusions).toHaveLength(0);
    });

    it('refuses at accept a turn-down queued before a feed listed what the rule caught', async () => {
      const bad = 'd'.repeat(64);
      const { detector, ui, alertId } = await withAlert(bad);
      const d = ui.draft({ kind: 'turn-down', alertId, why: 'Too noisy for me.' }, scout);
      expect(d.status).toBe('waiting');
      detector.engine.stores.lists.replace('known_bad_sha256', [bad], {
        source: 'feeds',
        updatedAt: 0,
      });
      await expect(ui.accept(d.proposalId!)).rejects.toThrow(/malicious/);
      expect(detector.rules().find((r) => r.rule.id === 'ai-paste-site')!.mode).toBe('alert');
      expect(ui.view().pending).toHaveLength(0);
    });
  });

  describe('weakening a blocking rule only the app runs', () => {
    const dirs: string[] = [];
    afterAll(() => {
      for (const d of dirs) rmSync(d, { recursive: true, force: true });
    });

    /** The helper's own policy check, with a password dialog the test answers. */
    function withHelper(detector: Detector) {
      const dir = mkdtempSync(join(tmpdir(), 'vigil-fp-'));
      dirs.push(dir);
      const fast = new FastPath({
        file: join(dir, 'rules.json'),
        run: async () => ({ ok: true }) as never,
      });
      const asked: string[][] = [];
      const helper = { approve: true };
      detector.syncHelper = async () => {
        const set = detector.helperRules();
        const cmd: DetectionSync = {
          kind: 'detection.sync',
          rules: set.rules,
          appRules: set.appRules,
          exceptions: set.exceptions,
          selfPaths: set.selfPaths,
          lists: Object.fromEntries(Object.entries(set.lists).map(([l, e]) => [l, listDigest(e)])),
        };
        const weakens = fast.loosening(cmd);
        if (weakens.length) {
          asked.push(weakens);
          if (!helper.approve) return 'declined';
        }
        fast.sync(cmd);
        return 'applied';
      };
      return { asked, helper };
    }

    it('asks for the password before Scout’s turn-down of a blocking first-seen rule goes live', async () => {
      const { detector, ui } = setup(answer);
      const { asked, helper } = withHelper(detector);
      const mode = () => detector.rules().find((r) => r.rule.id === 'exec-from-shared-temp')!.mode;
      expect(await detector.setMode('exec-from-shared-temp', 'block')).toBe('applied');
      expect(asked).toEqual([]);
      // The helper never runs it: it needs the app's "first seen" baseline.
      expect(detector.helperRules().rules.map((r) => r.id)).not.toContain('exec-from-shared-temp');

      const d = ui.draft(
        {
          kind: 'turn-down',
          ruleId: 'exec-from-shared-temp',
          why: 'It keeps firing on my builds.',
        },
        { provider: 'codex', name: 'Scout' },
      );
      expect(d.status).toBe('waiting');

      // Cancelled password: nothing changes and the suggestion still waits.
      helper.approve = false;
      expect(await ui.accept(d.proposalId!)).toBe('declined');
      expect(asked.at(-1)).toEqual([
        'stop blocking with “New program started from a temporary folder”',
      ]);
      expect(mode()).toBe('block');
      expect(ui.view().pending.map((p) => p.id)).toEqual([d.proposalId]);

      // The Rules page's own mode switch asks too.
      expect(await detector.setMode('exec-from-shared-temp', 'alert')).toBe('declined');
      expect(mode()).toBe('block');

      helper.approve = true;
      expect(await ui.accept(d.proposalId!)).toBe('applied');
      expect(mode()).toBe('shadow');
    });

    it('asks before an exclusion is added to a blocking rule only the app runs', async () => {
      const { detector, ui } = setup(answer);
      const { asked, helper } = withHelper(detector);
      expect(await detector.setMode('exec-from-shared-temp', 'block')).toBe('applied');
      const res = detector.pipeline.submitTuning(
        {
          ruleId: 'exec-from-shared-temp',
          addExclusion: { field: 'process.sha256', op: 'eq', value: '3'.repeat(64) },
          rationale: 'That is my own build output.',
        },
        'codex',
        'Scout',
      );
      expect(res.ok).toBe(true);
      helper.approve = false;
      expect(await ui.accept(res.proposalId!)).toBe('declined');
      expect(asked.at(-1)).toEqual([
        'change what “New program started from a temporary folder” blocks',
      ]);
      expect(detector.engine.getRule('exec-from-shared-temp')!.exclusions).toHaveLength(0);
      expect(ui.view().pending.map((p) => p.id)).toEqual([res.proposalId]);
    });
  });
});
