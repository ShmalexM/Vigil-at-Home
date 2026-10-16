import { describe, expect, it } from 'vitest';
import { parseCodesign, signatureLookup } from './signature.js';
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

  it('trusts nothing when a line appears twice', () => {
    const adhoc = 'Identifier=a.out\nSignature=adhoc\nTeamIdentifier=not set';
    expect(
      parseCodesign(`Identifier=com.apple.ls\nPlatform identifier=15\n${adhoc}`),
    ).toBeUndefined();
    expect(parseCodesign(`Signature=size=9\n${adhoc}`)).toBeUndefined();
  });
});

describe('signatureLookup', () => {
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
