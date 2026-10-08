import { describe, expect, it } from 'vitest';
import { macosCoreRules } from '@vigil/detection';
import { needsApproval, parseRequest, type HelperCommand } from './protocol.js';

const req = (command: unknown, extra: object = {}) =>
  parseRequest(JSON.stringify({ id: 'r1', command, ...extra }));

describe('request validation', () => {
  it('accepts the helper rule set and list parts without asking for approval', () => {
    const rule = macosCoreRules.find((r) => r.id === 'fake-password-prompt')!;
    const sync = {
      kind: 'detection.sync',
      rules: [rule],
      exceptions: [{ id: 'x', ruleId: '*', match: { 'process.path': '/a' }, createdAt: 1 }],
      selfPaths: ['/Applications/Vigil at Home.app'],
      lists: { known_bad_sha256: 'a'.repeat(64) },
    };
    const parsed = req(sync);
    expect('command' in parsed && parsed.command.kind).toBe('detection.sync');
    if ('command' in parsed) expect(needsApproval(parsed.command)).toBe(false);
    expect(req({ ...sync, extra: 1 })).toHaveProperty('error');
    expect(req({ ...sync, rules: [{ id: 'x' }] })).toHaveProperty('error');
    expect(req({ ...sync, lists: { 'Bad Name': 'a'.repeat(64) } })).toHaveProperty('error');
    const part = {
      kind: 'detection.list.set',
      list: 'known_bad_sha256',
      digest: 'a'.repeat(64),
      part: 0,
      parts: 1,
      entries: ['x'],
    };
    expect(req(part)).toHaveProperty('command');
    expect(req({ ...part, entries: Array(1001).fill('x') })).toHaveProperty('error');
  });

  it('accepts the core actions and the helper queries', () => {
    for (const command of [
      { kind: 'process.suspend', pid: 123, path: '/tmp/x' },
      { kind: 'process.resume', pid: 123 },
      { kind: 'process.kill', pid: 123, startTime: 1790000000000 },
      { kind: 'network.block', address: '203.0.113.9' },
      { kind: 'network.unblock', address: '203.0.113.0/24' },
      { kind: 'file.quarantine', path: '/Users/a/Downloads/x' },
      { kind: 'file.restore', quarantineId: 'a'.repeat(24) },
      { kind: 'persistence.disable', path: '/Library/LaunchDaemons/x.plist' },
      { kind: 'persistence.enable', path: '/Library/LaunchDaemons/x.plist' },
      {
        kind: 'santa.rule.set',
        ruleType: 'binary',
        identifier: 'a'.repeat(64),
        policy: 'silent_block',
        message: 'm',
      },
      { kind: 'santa.rule.remove', ruleType: 'teamid', identifier: 'ABCDE12345' },
      { kind: 'helper.status' },
      { kind: 'helper.journal', limit: 10 },
      { kind: 'santa.profile' },
      { kind: 'events.subscribe' },
      { kind: 'santa.client.reissue' },
    ]) {
      expect(req(command)).toEqual({ id: 'r1', command });
    }
  });

  it('rejects anything else', () => {
    expect(req({ kind: 'exec', cmd: 'rm -rf /' })).toHaveProperty('error');
    expect(req({ kind: 'toString' })).toHaveProperty('error');
    expect(req({ kind: 'helper.status', extra: 1 })).toHaveProperty('error');
    expect(req({ kind: 'santa.client.reissue', password: 'x' })).toHaveProperty('error');
    expect(req({ kind: 'process.kill', pid: 1, path: '/x', force: true })).toMatchObject({
      error: 'unknown field force',
    });
    expect(req({ kind: 'process.kill', pid: -3, path: '/x' })).toHaveProperty('error');
    expect(req({ kind: 'process.kill', pid: 1.5, path: '/x' })).toHaveProperty('error');
    expect(
      req({ kind: 'santa.rule.set', ruleType: 'path', identifier: 'x', policy: 'block' }),
    ).toHaveProperty('error');
    expect(
      req({ kind: 'santa.rule.set', ruleType: 'binary', identifier: 'x', policy: 'nuke' }),
    ).toHaveProperty('error');
    expect(req({ kind: 'helper.status' }, { approval: 'nothex' })).toHaveProperty('error');
    expect(req({ kind: 'helper.status' }, { sudo: true })).toHaveProperty('error');
    expect(parseRequest('not json')).toMatchObject({ error: 'invalid JSON' });
    expect(parseRequest('[]')).toHaveProperty('error');
    expect(parseRequest(JSON.stringify({ command: { kind: 'helper.status' } }))).toHaveProperty(
      'error',
    );
    expect(req({ kind: 'bogus' })).toMatchObject({ id: 'r1' });
  });

  it('asks for approval exactly for core release actions', () => {
    const yes: HelperCommand[] = [
      { kind: 'process.resume', pid: 5 },
      { kind: 'network.unblock', address: '203.0.113.9' },
      { kind: 'file.restore', quarantineId: 'a'.repeat(24) },
      { kind: 'persistence.enable', path: '/x' },
      { kind: 'santa.rule.remove', ruleType: 'teamid', identifier: 'ABCDE12345' },
      { kind: 'santa.rule.set', ruleType: 'teamid', identifier: 'ABCDE12345', policy: 'allow' },
    ];
    const no: HelperCommand[] = [
      { kind: 'process.suspend', pid: 5, path: '/x' },
      { kind: 'process.kill', pid: 5, path: '/x' },
      { kind: 'network.block', address: '203.0.113.9' },
      { kind: 'file.quarantine', path: '/x' },
      { kind: 'persistence.disable', path: '/x' },
      { kind: 'santa.rule.set', ruleType: 'teamid', identifier: 'ABCDE12345', policy: 'block' },
      { kind: 'helper.status' },
    ];
    for (const c of yes) expect(needsApproval(c)).toBe(true);
    for (const c of no) expect(needsApproval(c)).toBe(false);
  });
});
