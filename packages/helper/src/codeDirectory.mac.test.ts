// Real-Mac check that the CDHash and identifier the helper reads from a
// program's own bytes (codeDirectory.ts) are the ones codesign reports, for
// programs that ship with macOS. Runs only on macOS (`pnpm --filter
// @vigil/helper test:mac`); needs no root.

import { describe, expect, it } from 'vitest';
import { execFileSync } from 'node:child_process';
import { parseCodesignIdentity } from './appPin.js';
import { readCodeIdentity } from './codeDirectory.js';
import { openRegularFile } from './openedFile.js';

describe.skipIf(process.platform !== 'darwin')('reading code signatures on a real Mac', () => {
  for (const program of ['/usr/bin/true', '/bin/ls', '/usr/bin/codesign']) {
    it(`agrees with codesign for ${program}`, () => {
      // codesign -d writes to stderr.
      const out = execFileSync('/bin/sh', [
        '-c',
        '/usr/bin/codesign -d -vvv "$1" 2>&1',
        '-',
        program,
      ]);
      const want = parseCodesignIdentity(out.toString());
      expect(want).toBeDefined();
      const f = openRegularFile(program, { nofollow: true });
      expect(f).toBeDefined();
      try {
        const got = readCodeIdentity((pos, len) => f!.read(pos, len));
        expect(got?.cdhash).toBe(want?.cdhash);
        expect(got?.identifier).toBe(want?.identifier);
      } finally {
        f!.close();
      }
    });
  }
});
