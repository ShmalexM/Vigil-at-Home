import { describe, expect, it } from 'vitest';
import {
  parseCodesign,
  processSignatureLookup,
  signatureLookup,
  type RunTool,
} from './signature.js';
import type { System } from './system.js';

describe('parseCodesign', () => {
  it('reads each kind of signature', () => {
    expect(parseCodesign('/tmp/x: code object is not signed at all')).toEqual({
      signing: 'unsigned',
    });
    expect(
      parseCodesign('Identifier=a.out-55554944\nSignature=adhoc\nTeamIdentifier=not set'),
    ).toEqual({ signing: 'adhoc' });
    expect(
      parseCodesign('Identifier=com.apple.ls\nPlatform identifier=16\nAuthority=Software Signing'),
    ).toEqual({ signing: 'apple', signingId: 'platform:com.apple.ls' });
    expect(
      parseCodesign(
        'Identifier=com.google.Chrome\nAuthority=Developer ID Application: Google LLC (EQHXZ8M8AV)\nTeamIdentifier=EQHXZ8M8AV',
      ),
    ).toEqual({
      signing: 'developer_id',
      teamId: 'EQHXZ8M8AV',
      signingId: 'EQHXZ8M8AV:com.google.Chrome',
    });
    expect(parseCodesign('garbage')).toBeUndefined();
  });

  it('trusts nothing when a line appears twice (a path holding a newline)', () => {
    const real =
      'Identifier=com.evil\nAuthority=Developer ID Application: Evil (EVILTEAM00)\nTeamIdentifier=EVILTEAM00';
    const planted =
      'Executable=/tmp/x\nIdentifier=com.anthropic.claude-code\nTeamIdentifier=Q6L2SF6YDW';
    expect(parseCodesign(`${planted}\n${real}`)).toBeUndefined();
    expect(parseCodesign(`Executable=/tmp/x\nTeamIdentifier=Q6L2SF6YDW\n${real}`)).toBeUndefined();
    const adhoc = 'Identifier=com.apple.ls\nSignature=adhoc\nTeamIdentifier=not set';
    expect(
      parseCodesign(`Executable=/tmp/a\nPlatform identifier=15\nPlatform identifier=15\n${adhoc}`),
    ).toBeUndefined();
    expect(parseCodesign(`Executable=/tmp/a\nSignature=size=9\n${adhoc}`)).toBeUndefined();
  });

  it('trusts nothing when a line appears twice', () => {
    const adhoc = 'Identifier=a.out\nSignature=adhoc\nTeamIdentifier=not set';
    expect(
      parseCodesign(`Identifier=com.apple.ls\nPlatform identifier=15\n${adhoc}`),
    ).toBeUndefined();
    expect(parseCodesign(`Signature=size=9\n${adhoc}`)).toBeUndefined();
  });
});

describe('signatureLookup', () => {
  it('never asks codesign about a path with a line break', async () => {
    let calls = 0;
    const sys = {
      run: async () => {
        calls++;
        return { code: 0, stdout: '', stderr: 'Identifier=x' };
      },
    } as unknown as System;
    const lookup = signatureLookup(sys);
    expect(await lookup('/tmp/a\nPlatform identifier=15\n/b')).toEqual({ signing: 'invalid' });
    expect(await lookup('/tmp/a\r/b')).toEqual({ signing: 'invalid' });
    expect(calls).toBe(0);
  });

  it('runs codesign one at a time and stops at 60 a minute', async () => {
    let calls = 0;
    const sys = {
      run: async (_bin: string, args: string[]) => {
        calls++;
        return { code: 1, stdout: '', stderr: `${args[1]}: code object is not signed at all\n` };
      },
    } as unknown as System;
    let t = 0;
    const lookup = signatureLookup(sys, () => t);
    const answers = await Promise.all(Array.from({ length: 61 }, (_, i) => lookup(`/tmp/p${i}`)));
    expect(calls).toBe(60);
    expect(answers[0]).toEqual({ signing: 'unsigned' });
    expect(answers[60]).toBeUndefined();
    t = 61_000;
    expect(await lookup('/tmp/later')).toEqual({ signing: 'unsigned' });
    expect(await lookup('relative')).toBeUndefined();
  });
});

describe('processSignatureLookup', () => {
  const CLAUDE = [
    'Executable=/Users/alex/.local/share/claude/versions/2.1.283',
    'Identifier=com.anthropic.claude-code',
    'Authority=Developer ID Application: Anthropic PBC (Q6L2SF6YDW)',
    'TeamIdentifier=Q6L2SF6YDW',
  ].join('\n');
  // ps in the C locale pads lstart with spaces.
  const LSTART = 'Thu Oct 15 12:16:40 2026    \n';
  const STARTED = new Date(2026, 9, 15, 12, 16, 40).getTime();

  function fake(answers: { show?: string; showCode?: number; verify?: number; ps?: string }) {
    const calls: string[][] = [];
    const run: RunTool = async (bin, args) => {
      calls.push([bin, ...args]);
      if (bin === 'ps') return { code: answers.ps ? 0 : 1, stdout: answers.ps ?? '', stderr: '' };
      if (args[0] === '-dvv')
        return { code: answers.showCode ?? 0, stdout: '', stderr: answers.show ?? CLAUDE };
      return { code: answers.verify ?? 0, stdout: '', stderr: '' };
    };
    return { run, calls };
  }

  it('reads the pid’s program, checks the running code against it, then the start time', async () => {
    const { run, calls } = fake({ ps: LSTART });
    expect(await processSignatureLookup(run)(4242, STARTED)).toEqual({
      signing: 'developer_id',
      teamId: 'Q6L2SF6YDW',
      signingId: 'Q6L2SF6YDW:com.anthropic.claude-code',
      executable: '/Users/alex/.local/share/claude/versions/2.1.283',
    });
    expect(calls).toEqual([
      ['codesign', '-dvv', '4242'],
      [
        'codesign',
        '--verify',
        '-R=anchor apple generic and identifier "com.anthropic.claude-code" and certificate leaf[subject.OU] = "Q6L2SF6YDW"',
        '4242',
      ],
      ['ps', '-o', 'lstart=', '-p', '4242'],
    ]);
  });

  it('gives nothing when any step fails', async () => {
    const cases = [
      // Unsigned, ad hoc or Apple's own: no team to vouch for.
      { show: '4242: code object is not signed at all', showCode: 1, ps: LSTART },
      { show: 'Identifier=a.out\nSignature=adhoc\nTeamIdentifier=not set', ps: LSTART },
      { show: 'Identifier=com.apple.zsh\nPlatform identifier=16', ps: LSTART },
      // The process exited, or its running code is not that team's program.
      { showCode: 1, ps: LSTART },
      { verify: 3, ps: LSTART },
      // The pid now belongs to a process started at another time, or to none.
      { ps: 'Thu Oct 15 12:16:41 2026\n' },
      {},
      // A program path holding a line break other than LF, which could plant lines.
      {
        show: `Executable=/tmp/x\u2028Authority=Apple\n${CLAUDE.split('\n').slice(1).join('\n')}`,
        ps: LSTART,
      },
      // An identifier that could change the requirement it goes into.
      {
        show: 'Identifier=x" or anchor apple or identifier "y\nAuthority=Developer ID Application: X (ABCDE12345)\nTeamIdentifier=ABCDE12345',
        ps: LSTART,
      },
    ];
    for (const c of cases) {
      const { run } = fake(c);
      expect(await processSignatureLookup(run)(4242, STARTED), JSON.stringify(c)).toBeUndefined();
    }
    const { run, calls } = fake({ ps: LSTART });
    expect(await processSignatureLookup(run)(1, STARTED)).toBeUndefined();
    expect(calls).toEqual([]);
  });

  it('runs one at a time and stops at 60 a minute', async () => {
    let running = 0;
    let most = 0;
    const { run: inner } = fake({ ps: LSTART });
    const run: RunTool = async (bin, args) => {
      most = Math.max(most, ++running);
      await new Promise((r) => setTimeout(r, 1));
      running--;
      return inner(bin, args);
    };
    let t = 0;
    const lookup = processSignatureLookup(run, () => t);
    const answers = await Promise.all(Array.from({ length: 61 }, () => lookup(4242, STARTED)));
    expect(most).toBe(1);
    expect(answers.filter(Boolean)).toHaveLength(60);
    t = 60_000;
    expect(await lookup(4242, STARTED)).toBeDefined();
  });
});

describe('signatureLookup checks what codesign displays', () => {
  const LS =
    'Executable=/bin/ls\nIdentifier=com.apple.ls\nPlatform identifier=16\nAuthority=Software Signing';
  const CHROME =
    'Executable=/x/Chrome\nIdentifier=com.google.Chrome\nAuthority=Developer ID Application: Google LLC (EQHXZ8M8AV)\nTeamIdentifier=EQHXZ8M8AV';
  const UNKNOWN = { signing: 'unknown' };
  function fake(show: { code: number; stderr: string }, verify = 0) {
    const calls: string[][] = [];
    const sys = {
      run: async (bin: string, args: string[]) => {
        calls.push([bin, ...args]);
        if (args[0] === '-dv') return { code: show.code, stdout: '', stderr: show.stderr };
        return { code: verify, stdout: '', stderr: '' };
      },
    } as unknown as System;
    return { lookup: signatureLookup(sys), calls };
  }

  it('confirms a class with codesign --verify before it counts', async () => {
    const a = fake({ code: 0, stderr: LS });
    expect(await a.lookup('/bin/ls')).toEqual({
      signing: 'apple',
      signingId: 'platform:com.apple.ls',
    });
    expect(a.calls[1]).toEqual([
      'codesign',
      '--verify',
      '-R=anchor apple and identifier "com.apple.ls"',
      '/bin/ls',
    ]);
    const b = fake({ code: 0, stderr: CHROME });
    expect(await b.lookup('/x/Chrome')).toMatchObject({
      signing: 'developer_id',
      teamId: 'EQHXZ8M8AV',
    });
    expect(b.calls[1]![2]).toContain('certificate leaf[subject.OU] = "EQHXZ8M8AV"');
    expect(b.calls[1]![2]).toContain('certificate leaf[field.1.2.840.113635.100.6.1.13] exists');
    // Not meeting the requirement leaves "signed by nobody it can name": still
    // not Apple's to the rules, never undefined (which they read as least suspicious).
    expect(await fake({ code: 0, stderr: LS }, 3).lookup('/bin/ls')).toEqual(UNKNOWN);
    expect(await fake({ code: 0, stderr: CHROME }, 3).lookup('/x/Chrome')).toEqual(UNKNOWN);
    // Ad hoc needs no check and grants nothing.
    const c = fake({
      code: 0,
      stderr: 'Identifier=a.out\nSignature=adhoc\nTeamIdentifier=not set',
    });
    expect(await c.lookup('/tmp/a.out')).toEqual({ signing: 'adhoc' });
    expect(c.calls).toHaveLength(1);
  });

  it('reads line breaks, repeated lines and a failed codesign on a signature as invalid', async () => {
    const INVALID = { signing: 'invalid' };
    // A nonexistent path holding U+2028: codesign would exit 1 and echo the planted lines.
    const planted = '/tmp/a\u2028Platform identifier=15\u2028Identifier=com.apple.ls\u2028b';
    const a = fake({ code: 1, stderr: `${planted}: No such file or directory` });
    expect(await a.lookup(planted)).toEqual(INVALID);
    expect(a.calls).toHaveLength(0);
    for (const path of ['/tmp/a\nb', '/tmp/a\rb', '/tmp/a\u2029b'])
      expect(await fake({ code: 0, stderr: LS }).lookup(path)).toEqual(INVALID);
    // A missing file says nothing; a malformed signature is invalid.
    const gone = '/tmp/gone';
    expect(
      await fake({ code: 1, stderr: `${gone}: No such file or directory` }).lookup(gone),
    ).toBeUndefined();
    expect(
      await fake({ code: 1, stderr: `${gone}: invalid signature\n${LS}` }).lookup(gone),
    ).toEqual(INVALID);
    // An ad hoc program named with an odd break, or a repeated line, is invalid (never less than ad hoc).
    const adhoc = 'Identifier=a.out\nSignature=adhoc\nTeamIdentifier=not set';
    expect(await fake({ code: 0, stderr: `Executable=/x\u2028y\n${adhoc}` }).lookup('/x')).toEqual(
      INVALID,
    );
    expect(
      await fake({ code: 0, stderr: `TeamIdentifier=EQHXZ8M8AV\n${adhoc}` }).lookup('/x'),
    ).toEqual(INVALID);
    expect(
      await fake({
        code: 0,
        stderr: `Identifier=com.apple.ls\nPlatform identifier=15\n${LS}`,
      }).lookup('/x'),
    ).toEqual(INVALID);
    // Unsigned stays unsigned.
    expect(
      await fake({ code: 1, stderr: `${gone}: code object is not signed at all` }).lookup(gone),
    ).toEqual({ signing: 'unsigned' });
  });
});
