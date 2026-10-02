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

  it('cannot chain requests, and no chain can step on one', () => {
    const step = (eventKinds: string[], field: string) => ({
      steps: [{ eventKinds, condition: { field, op: 'contains', value: '.ssh/id_' } }],
      key: ['agent.session'],
      windowSec: 600,
    });
    // A check never moves a chain on, so these could never fire.
    expect(pre({ sequence: step(['agent.tool_request'], 'command') }).errors).toEqual([
      'a sequence step cannot be an agent.tool_request; checking a request moves no chain',
      'pre-flight rules decide each request on its own; they cannot use a sequence',
    ]);
    expect(pre({ sequence: step(['file'], 'path') }).errors).toContain(
      'pre-flight rules decide each request on its own; they cannot use a sequence',
    );
    const onLaunch = lint({
      id: 'exec-after-request',
      condition: { field: 'process.name', op: 'eq', value: 'curl' },
      sequence: { ...step(['agent.tool_request'], 'command'), key: ['process.agent.session'] },
    });
    expect(onLaunch.errors).toEqual([
      'a sequence step cannot be an agent.tool_request; checking a request moves no chain',
    ]);
    // Chains of launches and file reads are fine.
    expect(
      lint({
        id: 'exec-after-read',
        condition: { field: 'process.name', op: 'eq', value: 'curl' },
        sequence: { ...step(['file'], 'path'), key: ['process.agent.session'] },
      }).errors,
    ).toEqual([]);
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
      'commandClipped',
      // A Bash request carries the shell it would start.
      'process.name',
      'process.commandLine',
    ];
    for (const field of fields)
      expect(pre({ condition: { field, op: 'exists' } })).toEqual({ errors: [], warnings: [] });
  });

  it('warn about process fields a tool request never carries', () => {
    const r = pre({ condition: { field: 'process.agent.id', op: 'eq', value: 'codex' } });
    expect(r.errors).toEqual([]);
    expect(r.warnings).toEqual([
      'process.agent.id is never set on a tool request; use agent.id or agent.session (agent.host for the app)',
    ]);
    for (const field of ['process.ancestors', 'process.parentName', 'process.agent.depth'])
      expect(pre({ condition: { field, op: 'exists' } }).warnings.join(' ')).toMatch(
        /never set on a tool request/,
      );
    expect(
      pre({
        exclusions: [{ inList: { list: 'my_list', field: 'process.parentName' } }],
        reasons: ['{{process.agent.session}} asked'],
      }).warnings,
    ).toHaveLength(2);
    // The same test on a launch is fine: the tracker tags those.
    expect(
      lint({
        id: 'exec',
        condition: { field: 'process.agent.id', op: 'eq', value: 'codex' },
      }).warnings.join(' '),
    ).not.toMatch(/never set on a tool request/);
  });
});
