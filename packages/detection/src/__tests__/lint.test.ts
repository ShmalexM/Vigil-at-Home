import { describe, expect, it } from 'vitest';
import { isAnchored, lintRule } from '../rules/lint.js';
import { DetectionRule } from '../types.js';
import { testRule } from './fixtures.js';

const lint = (r: Record<string, unknown> & { id: string; condition: unknown }, ai = false) =>
  lintRule(DetectionRule.parse(testRule(r)), { aiProposed: ai });

describe('anchoring', () => {
  const inList = (field: string) => ({ inList: { list: 'known_bad_sha256', field } });

  it('counts a list lookup as an anchor only on an anchor field', () => {
    expect(isAnchored(inList('process.sha256'))).toBe(true);
    expect(isAnchored(inList('remoteHost'))).toBe(true);
    expect(isAnchored(inList('process.commandLine'))).toBe(false);
    expect(isAnchored({ any: [inList('process.sha256'), inList('process.commandLine')] })).toBe(
      false,
    );
  });

  it('keeps an AI rule from killing on a list of behaviours', () => {
    const kill = [{ kind: 'process.kill', pid: '{{process.pid}}' }];
    const res = (field: string) =>
      lint({ id: 'ai-x', severity: 'high', condition: inList(field), response: kill }, true);
    expect(res('process.commandLine').errors.join(' ')).toMatch(/names a specific/);
    expect(res('process.sha256').errors).toEqual([]);
  });
});

describe('pre-flight rules', () => {
  const pre = (r: Record<string, unknown> = {}) =>
    lint({
      id: 'pre',
      eventKinds: ['agent.tool_request'],
      condition: { field: 'command', op: 'contains', value: 'rm -rf' },
      reasons: ['{{tool}} would delete a folder'],
      ...r,
    });

  it('lint clean, and a deny needs no response', () => {
    expect(pre()).toEqual({ errors: [], warnings: [] });
    expect(pre({ mode: 'block' })).toEqual({ errors: [], warnings: [] });
    expect(
      lint({
        id: 'exec',
        mode: 'block',
        condition: { field: 'process.name', op: 'eq', value: 'x' },
      }).warnings,
    ).toEqual(['the rule is in block mode but has no response, so it only alerts']);
  });

  it('check only tool requests', () => {
    expect(pre({ eventKinds: ['agent.tool_request', 'process.exec'] }).errors).toContain(
      'pre-flight rules check only agent.tool_request',
    );
  });

  it('cannot run actions', () => {
    expect(
      pre({ response: [{ kind: 'process.suspend', pid: '{{process.pid}}' }] }).errors,
    ).toContain('pre-flight rules decide ask or deny; they cannot run actions');
  });

  it('cannot count, learn or add Santa rules', () => {
    expect(pre({ threshold: { count: 3, windowSec: 60 } }).errors.join(' ')).toMatch(
      /cannot use a threshold/,
    );
    const learns = /cannot use firstSeen/;
    expect(
      pre({
        condition: {
          all: [{ field: 'tool', op: 'eq', value: 'Bash' }, { firstSeen: { key: ['command'] } }],
        },
      }).errors.join(' '),
    ).toMatch(learns);
    expect(
      pre({ exclusions: [{ not: { firstSeen: { key: ['filePath'] } } }] }).errors.join(' '),
    ).toMatch(learns);
    expect(pre({ santa: { ruleType: 'binary', from: 'contentSha256' } }).errors).toContain(
      'pre-flight rules cannot add Santa rules',
    );
  });

  it('know the tool request fields', () => {
    const fields = [
      'tool',
      'command',
      'commandBytes',
      'filePath',
      'url',
      'mcpServer',
      'cwd',
      'contentBytes',
      'contentSha256',
      'toolOutsideCwd',
      'agent.host',
      'agent.id',
      'agent.session',
      'agent.hookSession',
      'process.agent.id',
      'process.agent.depth',
      'process.ancestors',
    ];
    for (const field of fields)
      expect(pre({ condition: { field, op: 'exists' } }).errors).toEqual([]);
  });
});
