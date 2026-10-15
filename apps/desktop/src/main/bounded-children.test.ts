import { readdirSync, readFileSync } from 'node:fs';
import { join, relative } from 'node:path';
import { describe, expect, it } from 'vitest';

const ROOT = join(__dirname, '..', '..', '..', '..');

/**
 * The only places allowed to start a program directly. Everything else goes
 * through execFileWithin, which always answers by its time limit, so no
 * background job can wait forever on a program that hangs.
 */
const ALLOWED = new Set([
  // execFileWithin itself.
  'packages/ai/src/execWithin.ts',
  // The Codex server: every request has a time limit and close() kills it.
  'packages/ai/src/providers/jsonRpcStdio.ts',
  // Opens a terminal window for the user: detached and never waited on.
  'apps/desktop/src/main/onboarding/terminal.ts',
]);

function sources(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((e) => {
    const path = join(dir, e.name);
    if (e.isDirectory()) return e.name === 'fixtures' ? [] : sources(path);
    return /\.(ts|mts|js|mjs)$/.test(e.name) && !/\.test\./.test(e.name) ? [path] : [];
  });
}

describe('starting programs', () => {
  it('happens only through execFileWithin in the AI package and the main process', () => {
    const files = [
      ...sources(join(ROOT, 'packages/ai/src')),
      ...sources(join(ROOT, 'apps/desktop/src/main')),
    ];
    expect(files.length).toBeGreaterThan(50);
    const direct = files
      .filter((f) => /['"](node:)?child_process['"]/.test(readFileSync(f, 'utf8')))
      .map((f) => relative(ROOT, f));
    expect(direct.filter((f) => !ALLOWED.has(f))).toEqual([]);
    // Each exception still exists, so this list cannot go stale.
    for (const f of ALLOWED) expect(direct).toContain(f);
  });
});
