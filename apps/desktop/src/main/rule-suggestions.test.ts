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
  return { core, store, db, detector, seen, ui: new RuleSuggestions(detector, () => true) };
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
    ui.accept(s.id);
    expect(detector.rules().find((r) => r.rule.id === 'ai-paste-site')?.mode).toBe('alert');
    expect(ui.view().pending).toHaveLength(0);
    expect(ui.view().recent[0]).toMatchObject({ status: 'approved', ruleName: 'Paste site' });
  });

  it('accepted rules and review state survive a restart', async () => {
    const db = new DatabaseSync(':memory:');
    const first = setup(answer, db);
    await first.detector.reviewRules({ force: true });
    first.ui.accept(first.ui.view().pending[0]!.id);
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
    expect(await detector.approveProposal(id, 'block')).toBe('declined');
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
});
