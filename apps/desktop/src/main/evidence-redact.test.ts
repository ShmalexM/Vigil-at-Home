import { describe, expect, it } from 'vitest';
import { redactEvidence } from './evidence-redact.js';

const names = { username: 'al', hostname: 'pc.local' };

describe('redactEvidence', () => {
  it('hides the arg after a secret flag', () => {
    expect(redactEvidence(['tool', '--token', 'secret123456', 'run'], {})).toEqual([
      'tool',
      '--token',
      '<redacted>',
      'run',
    ]);
    for (const flag of ['--password', '--passwd', '--api-key', '--access-token', '--KEY']) {
      expect(redactEvidence(['x', flag, 'secret123456'], {})).toEqual(['x', flag, '<redacted>']);
    }
  });

  it('hides a secret flag value inside one string, after a space or =', () => {
    const out = JSON.stringify(
      redactEvidence(
        {
          cmd: 'mysql --password secret123456 -h db',
          other: 'curl --auth=abcdef --apikey "two words"',
        },
        {},
      ),
    );
    expect(out).not.toContain('secret123456');
    expect(out).not.toContain('abcdef');
    expect(out).not.toContain('two words');
    expect(out).toContain('--password <redacted> -h db');
  });

  it('keeps the values of ordinary flags', () => {
    expect(redactEvidence(['git', '--keyboard', 'us', '--author', 'me'], {})).toEqual([
      'git',
      '--keyboard',
      'us',
      '--author',
      'me',
    ]);
    expect(redactEvidence(['tool', '--token', '--verbose'], {})).toEqual([
      'tool',
      '--token',
      '--verbose',
    ]);
  });

  it("hides this computer's short user and host names as whole tokens", () => {
    const out = redactEvidence(
      { args: ['ssh', 'al@pc', 'al'], host: 'pc.local', who: 'AL', path: '/Users/al/x' },
      names,
    );
    expect(out).toEqual({
      args: ['ssh', '<user>@<host>', '<user>'],
      host: '<host>',
      who: '<user>',
      path: '/Users/<user>/x',
    });
  });

  it('leaves longer words that only contain those names', () => {
    expect(redactEvidence(['always', 'pcap', 'my-pc', 'alpha'], names)).toEqual([
      'always',
      'pcap',
      'my-pc',
      'alpha',
    ]);
  });

  it('hides a host name given without .local in its .local form too', () => {
    expect(redactEvidence('on pc.local and pc', { hostname: 'pc' })).toBe('on <host> and <host>');
  });
});
