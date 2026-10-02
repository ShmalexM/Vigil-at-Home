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
