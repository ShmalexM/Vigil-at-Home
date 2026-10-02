import { describe, expect, it } from 'vitest';
import {
  AGENT_FIELD_PREFIXES,
  agentPreflightRules,
  agentWatchRules,
  builtinRules,
  DetectionEngine,
  macosCoreRules,
  memoryStores,
  MemoryListStore,
} from '../index.js';
import { APP_ONLY_FIELD_PREFIXES, fastPathRules, isAppOnlyField, listDigest } from '../fastpath.js';
import { preexecRules } from '../preexec.js';
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

describe('agent rules and the helper', () => {
  type Listed = DetectionRule & { effectiveMode: 'block' };
  /** Every built-in rule, as if the user had turned each one to block. */
  const allBlocking = (): Listed[] =>
    new DetectionEngine(builtinRules, memoryStores())
      .listRules()
      .map((r) => ({ ...r, effectiveMode: 'block' as const }));
  const agentIds = new Set([...agentWatchRules, ...agentPreflightRules].map((r) => r.id));

  it('never hands the helper (or Santa) an agent-watch or pre-flight rule', () => {
    const set = fastPathRules(allBlocking());
    expect(set.rules.length).toBeGreaterThan(0);
    expect(set.rules.filter((r) => agentIds.has(r.id))).toEqual([]);
    expect(set.rules.some((r) => r.eventKinds.includes('agent.tool_request'))).toBe(false);
    // Santa's pre-launch rules come from that same set (packages/helper preexec.ts),
    // and would refuse the agent rules anyway: Santa can't see an agent.
    const pre = preexecRules(set.rules.map((rule) => ({ rule, mode: 'block' as const })));
    expect(pre.rules.flatMap((r) => r.ruleIds).filter((id) => agentIds.has(id))).toEqual([]);
    const direct = preexecRules(
      allBlocking()
        .filter((r) => agentIds.has(r.id))
        .map(({ effectiveMode: _m, ...rule }) => ({ rule, mode: 'block' as const })),
    );
    expect(direct.rules).toEqual([]);
  });

  it('keeps any rule on a tool request in the app, whatever fields it reads', () => {
    const base = allBlocking().find((r) => r.id === 'known-bad-hash')!;
    const request = {
      ...base,
      id: 'user-deny-zsh',
      eventKinds: ['agent.tool_request'],
      condition: { field: 'process.path', op: 'eq', value: '/bin/zsh' },
      response: [],
    } as Listed;
    const chained = {
      ...base,
      id: 'user-chain',
      sequence: {
        steps: [
          {
            eventKinds: ['agent.tool_request'],
            condition: { field: 'process.path', op: 'eq', value: '/bin/zsh' },
          },
        ],
        key: ['process.path'],
        windowSec: 60,
      },
    } as Listed;
    expect(fastPathRules([base, request, chained]).rules.map((r) => r.id)).toEqual([
      'known-bad-hash',
    ]);
  });

  it('runs rules on the process tree there, since the sensor hub fills it in', () => {
    const base = allBlocking().find((r) => r.id === 'known-bad-hash')!;
    const tree = (id: string, field: string) =>
      ({
        ...base,
        id,
        condition: { all: [base.condition, { field, op: 'in', value: ['Installer'] }] },
      }) as Listed;
    const ids = fastPathRules([
      tree('on-ancestors', 'process.ancestors'),
      tree('on-parent', 'process.parentName'),
      tree('on-download', 'process.downloadRoot'),
      tree('on-agent', 'process.agent.id'),
      {
        ...base,
        id: 'in-reason',
        reasons: ['{{process.agent.session}} ran it'],
      } as Listed,
    ]).rules.map((r) => r.id);
    expect(ids).toEqual(['on-ancestors', 'on-parent', 'on-download']);
  });

  it('matches app-only fields by name or what is under them, not by any prefix', () => {
    for (const f of [
      'process.agent',
      'process.agent.id',
      'process.agent.session',
      'agent',
      'agent.id',
      'agent.hookSession',
      'tool',
      'command',
      'commandBytes',
      'commandClipped',
      'filePath',
      'url',
      'mcpServer',
      'cwd',
      'toolOutsideCwd',
      'contentBytes',
      'contentSha256',
    ])
      expect([f, isAppOnlyField(f)]).toEqual([f, true]);
    for (const f of [
      'process.ancestors',
      'process.parentName',
      'process.cwd',
      'process.commandLine',
      'process.path',
      'path',
      'agentish',
      'process.agentish',
    ])
      expect([f, isAppOnlyField(f)]).toEqual([f, false]);
    // Every agent field is app-only except the tree, which the helper now has too.
    expect([...APP_ONLY_FIELD_PREFIXES, 'process.ancestors'].sort()).toEqual(
      [...AGENT_FIELD_PREFIXES].sort(),
    );
    // An entry ending in "." covers only what is under it.
    expect(isAppOnlyField('agent.name', ['agent.'])).toBe(true);
    expect(isAppOnlyField('agent', ['agent.'])).toBe(false);
  });
});
