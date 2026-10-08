import { DatabaseSync } from 'node:sqlite';
import type { SensorEvent } from '@vigil/core';
import type { AnalyzeRunner } from '@vigil/detection';
import { describe, expect, it } from 'vitest';
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
    async function withAlert() {
      const t = setup(answer);
      await t.detector.reviewRules({ force: true });
      await t.ui.accept(t.ui.view().pending[0]!.id);
      await t.core.handleEvent(connect('paste.ee'));
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
  });
});
