import { describe, expect, it } from 'vitest';
import type { Action } from './index.js';
import {
  Alert,
  Rule,
  SensorEvent,
  authorizeAction,
  canChangeMode,
  canPropose,
  compareSeverity,
  isRelease,
  newId,
  undoOf,
} from './index.js';

describe('newId', () => {
  it('sorts by creation order', () => {
    const ids = [newId(1000), newId(1000), newId(1001), newId(2_000_000_000_000)];
    expect([...ids].sort()).toEqual(ids);
    expect(new Set(ids).size).toBe(ids.length);
  });
});

describe('SensorEvent', () => {
  it('parses a process exec and rejects an unknown kind', () => {
    const ev = SensorEvent.parse({
      id: 'e1',
      ts: 1,
      source: 'osquery',
      kind: 'process.exec',
      process: { pid: 42, path: '/usr/bin/curl', args: ['curl', 'x'], signing: 'apple' },
    });
    expect(ev.kind).toBe('process.exec');
    expect(SensorEvent.safeParse({ id: 'e', ts: 1, source: 'osquery', kind: 'nope' }).success).toBe(
      false,
    );
  });
});

describe('action policy', () => {
  const suspend: Action = { kind: 'process.suspend', pid: 7 };
  const resume: Action = { kind: 'process.resume', pid: 7 };
  const allow: Action = {
    kind: 'santa.rule.set',
    ruleType: 'teamid',
    identifier: 'X',
    policy: 'allow',
  };
  const block: Action = { ...allow, policy: 'block' };

  it('classifies release actions', () => {
    expect(isRelease(suspend)).toBe(false);
    expect(isRelease(resume)).toBe(true);
    expect(isRelease(allow)).toBe(true);
    expect(isRelease(block)).toBe(false);
  });

  it('lets rules contain but never release', () => {
    expect(authorizeAction('rule', suspend).ok).toBe(true);
    expect(authorizeAction('rule', resume).ok).toBe(false);
    expect(authorizeAction('rule', allow).ok).toBe(false);
  });

  it('never lets the AI execute, and lets it propose containment only', () => {
    expect(authorizeAction('ai', suspend).ok).toBe(false);
    expect(canPropose('ai', block).ok).toBe(true);
    expect(canPropose('ai', allow).ok).toBe(false);
    expect(canPropose('ai', resume).ok).toBe(false);
  });

  it('lets the user do anything', () => {
    for (const a of [suspend, resume, allow, block])
      expect(authorizeAction('user', a).ok).toBe(true);
  });

  it('computes undo', () => {
    expect(undoOf(suspend)).toEqual(resume);
    expect(undoOf({ kind: 'file.quarantine', path: '/tmp/x' })).toBeUndefined();
    expect(
      undoOf({ kind: 'file.quarantine', path: '/tmp/x' }, { at: 1, quarantineId: 'q1' }),
    ).toEqual({ kind: 'file.restore', quarantineId: 'q1' });
    expect(undoOf(block)).toEqual({
      kind: 'santa.rule.remove',
      ruleType: 'teamid',
      identifier: 'X',
    });
    expect(undoOf({ kind: 'process.kill', pid: 1 })).toBeUndefined();
  });
});

describe('rules', () => {
  const rule = {
    id: 'persistence.unsigned-launch-agent',
    version: 1,
    name: 'Unsigned launch agent',
    description: 'A launch agent that runs an unsigned program was added.',
    origin: 'builtin',
    mode: 'block',
    severity: 'high',
    fidelity: 'high',
    eventKinds: ['persistence'],
    condition: {
      all: [
        { field: 'mechanism', op: 'eq', value: 'launch_agent' },
        {
          not: {
            field: 'process.signing',
            op: 'in',
            value: ['apple', 'developer_id', 'app_store'],
          },
        },
      ],
    },
    response: [{ kind: 'persistence.disable', path: '{{path}}' }],
    createdAt: 1,
    updatedAt: 1,
  };

  it('parses nested conditions and response templates', () => {
    const parsed = Rule.parse(rule);
    expect(parsed.tags).toEqual([]);
    expect(parsed.response[0]?.kind).toBe('persistence.disable');
  });

  it('rejects a response with an unknown action kind', () => {
    expect(Rule.safeParse({ ...rule, response: [{ kind: 'rm -rf' }] }).success).toBe(false);
  });

  it('only lets the user make a rule louder', () => {
    expect(canChangeMode('ai', null, 'shadow')).toBe(true);
    expect(canChangeMode('ai', null, 'alert')).toBe(false);
    expect(canChangeMode('ai', 'shadow', 'block')).toBe(false);
    expect(canChangeMode('rule', 'block', 'shadow')).toBe(true);
    expect(canChangeMode('user', 'shadow', 'block')).toBe(true);
  });
});

describe('alerts', () => {
  it('defaults lists and orders severities', () => {
    const alert = Alert.parse({
      id: 'a1',
      createdAt: 1,
      updatedAt: 1,
      ruleId: 'r',
      ruleVersion: 1,
      title: 't',
      summary: 's',
      severity: 'high',
      fidelity: 'high',
      notify: 'popup',
      status: 'open',
      containment: 'active',
      eventIds: ['e1'],
    });
    expect(alert.actionIds).toEqual([]);
    expect(compareSeverity('critical', 'low')).toBeGreaterThan(0);
  });
});

describe('additions for detection and sensors', () => {
  it('parses the new event kinds', () => {
    for (const ev of [
      { kind: 'network.listen', protocol: 'tcp', localPort: 4444 },
      { kind: 'browser.extension', change: 'added', browser: 'chrome', extensionId: 'abc' },
      { kind: 'system.alert', subtype: 'xprotect_detected', details: { malware: 'MACOS.ADLOAD' } },
    ]) {
      expect(SensorEvent.safeParse({ id: 'e', ts: 1, source: 'santa', ...ev }).success).toBe(true);
    }
  });

  it('parses firstSeen, inList, exclusions and dedupe on rules', () => {
    const r = Rule.parse({
      id: 'x',
      version: 1,
      name: 'n',
      description: 'd',
      origin: 'builtin',
      mode: 'shadow',
      severity: 'low',
      fidelity: 'low',
      eventKinds: ['process.exec'],
      condition: {
        all: [
          { firstSeen: { key: ['process.sha256'] } },
          { not: { inList: { list: 'known_bad_sha256', field: 'process.sha256' } } },
          { field: 'process.teamId', op: 'notIn', value: ['EQHXZ8M8AV'] },
        ],
      },
      exclusions: [{ field: 'process.path', op: 'startsWith', value: '/Applications/' }],
      dedupe: { key: ['process.sha256'], windowSec: 3600 },
      createdAt: 1,
      updatedAt: 1,
    });
    expect(r.reasons).toEqual([]);
    expect(r.exclusions).toHaveLength(1);
  });

  it('keeps the expected path through undo', () => {
    expect(undoOf({ kind: 'process.suspend', pid: 9, path: '/tmp/x' })).toEqual({
      kind: 'process.resume',
      pid: 9,
      path: '/tmp/x',
    });
  });
});
