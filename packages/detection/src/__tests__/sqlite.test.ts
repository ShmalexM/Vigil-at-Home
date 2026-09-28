import { DatabaseSync } from 'node:sqlite';
import { describe, expect, it } from 'vitest';
import { DetectionEngine } from '../engine.js';
import { Feedback } from '../feedback.js';
import { mergeRules } from '../merge.js';
import { macosCoreRules } from '../packs/macos-core.js';
import { RulePipeline } from '../proposals/pipeline.js';
import { sqliteStores, type SqlDatabase } from '../state/sqlite.js';
import { userOrigin } from '../user.js';
import { connect, DAY, ev, proc, T0 } from './fixtures.js';

describe('SQLite stores', () => {
  it('persist baseline, lists, exceptions, modes, history, proposals and approved rules across restarts', () => {
    const db = new DatabaseSync(':memory:') as unknown as SqlDatabase;
    const me = userOrigin('test');
    const now = () => T0 + DAY;

    {
      const stores = sqliteStores(db);
      stores.lists.replace('known_bad_domains', ['evil.test'], { source: 'feed', updatedAt: T0 });
      const engine = new DetectionEngine(mergeRules(macosCoreRules, stores.rules.list()), stores);
      const pipeline = new RulePipeline(engine, stores.history, stores.proposals, {
        now,
        repository: stores.rules,
      });
      const item = ev({
        kind: 'persistence',
        change: 'added',
        mechanism: 'launch_agent',
        path: '/Users/a/Library/LaunchAgents/x.plist',
        program: '/Applications/X.app/x',
      });
      const d = engine.evaluate(item).find((x) => x.match.ruleId === 'persistence-first-seen')!;
      const fb = new Feedback(engine, undefined, now);
      fb.recordDecision(
        d,
        { at: T0, verdict: 'expected', remember: true, scope: 'this_binary' },
        me,
      );
      fb.setMode('unsigned-first-network', 'alert', me);
      const res = pipeline.submitRule(
        {
          rule: {
            id: 'paste',
            name: 'Paste site',
            eventKinds: ['network.connection'],
            severity: 'low',
            mode: 'alert',
            condition: { field: 'remoteHost', op: 'eq', value: 'paste.ee' },
            reasons: ['{{process.name}} talked to a paste site'],
          },
          rationale: 'Paste sites move stolen data.',
        },
        'claude',
      );
      pipeline.approve(res.proposalId!, me);
    }

    const stores = sqliteStores(db);
    const engine = new DetectionEngine(mergeRules(macosCoreRules, stores.rules.list()), stores);
    expect(stores.baseline.size()).toBe(1);
    expect(stores.lists.has('known_bad_domains', 'a.evil.test')).toBe(true);
    expect(stores.exceptions.all()).toHaveLength(1);
    expect(stores.exceptions.all()[0]!.match).toEqual({
      path: '/Users/a/Library/LaunchAgents/x.plist',
    });
    expect(engine.modeOf(engine.getRule('unsigned-first-network')!)).toBe('alert');
    expect(engine.getRule('ai-paste')).toMatchObject({ origin: 'ai', mode: 'alert' });
    expect([...stores.history.range(0, T0 + 10 * DAY)]).toHaveLength(1);
    expect(stores.proposals.list()[0]!.status).toBe('approved');
    expect(stores.ruleState.verdicts('persistence-first-seen', 0)).toHaveLength(1);
    expect(stores.history.prune(T0 + 10 * DAY)).toBe(1);

    const again = connect(proc({ path: '/opt/x' }), '104.20.1.1', 'paste.ee');
    expect(engine.evaluate(again).map((d) => d.match.ruleId)).toContain('ai-paste');
  });

  it('migrations are idempotent', () => {
    const db = new DatabaseSync(':memory:') as unknown as SqlDatabase;
    sqliteStores(db);
    expect(() => sqliteStores(db)).not.toThrow();
  });
});
