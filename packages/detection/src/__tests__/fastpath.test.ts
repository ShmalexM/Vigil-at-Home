import { describe, expect, it } from 'vitest';
import { DetectionEngine, macosCoreRules, memoryStores, MemoryListStore } from '../index.js';
import { fastPathRules, listDigest } from '../fastpath.js';
import type { DetectionRule } from '../types.js';

const engine = () => new DetectionEngine(macosCoreRules, memoryStores());

describe('rules the helper can run itself', () => {
  it('takes the block-mode rules and the lists they read', () => {
    const e = engine();
    const set = fastPathRules(e.listRules());
    const blocking = e.listRules().filter((r) => r.effectiveMode === 'block');
    expect(set.rules.map((r) => r.id)).toEqual(blocking.map((r) => r.id));
    expect(set.rules.every((r) => r.mode === 'block')).toBe(true);
    expect(set.lists).toContain('known_bad_sha256');
    expect(set.lists).toContain('user_blocked_sha256');
    // known-bad-domain only alerts, so its list stays in the app.
    expect(set.lists).not.toContain('known_bad_domains');
  });

  it('uses the mode the user set, not the rule’s own', () => {
    const rules = engine().listRules();
    const demoted = rules.map((r) =>
      r.id === 'known-bad-hash' ? { ...r, effectiveMode: 'alert' as const } : r,
    );
    const promoted = rules.map((r) =>
      r.id === 'known-bad-domain' ? { ...r, effectiveMode: 'block' as const } : r,
    );
    expect(fastPathRules(demoted).rules.map((r) => r.id)).not.toContain('known-bad-hash');
    const p = fastPathRules(promoted);
    expect(p.rules.find((r) => r.id === 'known-bad-domain')?.mode).toBe('block');
    expect(p.lists).toContain('known_bad_domains');
  });

  it('leaves rules that need the baseline or app-only fields to the app', () => {
    const base = engine()
      .listRules()
      .find((r) => r.id === 'known-bad-hash')!;
    const firstSeen = {
      ...base,
      id: 'new-program',
      condition: { all: [base.condition, { firstSeen: { key: ['process.path'] } }] },
    } as DetectionRule & { effectiveMode: 'block' };
    const agent = {
      ...base,
      id: 'agent-rule',
      condition: { field: 'agent.name', op: 'eq', value: 'x' },
    } as unknown as DetectionRule & { effectiveMode: 'block' };
    const inTemplate = {
      ...base,
      id: 'agent-template',
      response: [{ kind: 'process.kill', pid: '{{agent.pid}}' }],
    } as unknown as DetectionRule & { effectiveMode: 'block' };
    const ids = fastPathRules([base, firstSeen, agent, inTemplate], ['agent.']).rules.map(
      (r) => r.id,
    );
    expect(ids).toEqual(['known-bad-hash']);
  });

  it('lists come back out of the store as they went in, so digests match', () => {
    const lists = new MemoryListStore();
    lists.replace('ips', ['203.0.113.9', '198.51.100.0/24', 'EVIL.test', '# comment'], {
      source: 't',
      updatedAt: 0,
    });
    expect(lists.entries('ips').sort()).toEqual(['198.51.100.0/24', '203.0.113.9', 'evil.test']);
    expect(lists.entries('missing')).toEqual([]);
    const copy = new MemoryListStore();
    copy.replace('ips', lists.entries('ips'), { source: 't', updatedAt: 0 });
    expect(copy.has('ips', '198.51.100.7')).toBe(true);
    expect(listDigest(copy.entries('ips'))).toBe(listDigest(lists.entries('ips')));
    expect(listDigest(['b', 'a', 'a'])).toBe(listDigest(['a', 'b']));
  });
});
