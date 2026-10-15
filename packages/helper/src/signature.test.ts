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
});

describe('signatureLookup', () => {
  it('runs codesign one at a time and stops at 60 a minute', async () => {
    let calls = 0;
    const sys = {
      run: async () => {
        calls++;
        return { code: 1, stdout: '', stderr: 'code object is not signed at all' };
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
