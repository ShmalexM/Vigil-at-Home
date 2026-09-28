// Real-Mac check that FileTailer's file watch sees lines another process
// writes, and follows a newsyslog-style rotation, without the fallback poll.
// Runs only on macOS with VIGIL_MAC_INTEGRATION=1 (`pnpm --filter @vigil/sensors test:mac`).

import { describe, expect, it } from 'vitest';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { FileTailer } from './tail.js';

const enabled = process.platform === 'darwin' && process.env.VIGIL_MAC_INTEGRATION === '1';

async function until(check: () => boolean, ms = 10_000): Promise<boolean> {
  const end = Date.now() + ms;
  while (!check() && Date.now() < end) await new Promise((r) => setTimeout(r, 20));
  return check();
}

describe.skipIf(!enabled)('FileTailer on a real Mac', () => {
  it('sees appends and rotation by another process through the watch alone', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'vigil-tail-mac-'));
    const path = join(dir, 'santa.log');
    writeFileSync(path, '');
    const lines: string[] = [];
    const t = new FileTailer({ path, intervalMs: 60_000, onLine: (l) => lines.push(l) });
    await t.start();
    const sh = (cmd: string) => execFileSync('/bin/sh', ['-c', cmd], { env: { F: path } });
    try {
      // FSEvents drops changes made before its stream is running.
      for (let i = 0; i < 50 && !lines.some((l) => l.startsWith('warmup')); i++) {
        sh(`echo warmup ${i} >> "$F"`);
        await until(() => lines.some((l) => l.startsWith('warmup')), 200);
      }
      expect(lines.some((l) => l.startsWith('warmup'))).toBe(true);
      sh('echo one >> "$F"');
      expect(await until(() => lines.includes('one'))).toBe(true);
      sh('mv "$F" "$F.0" && echo two > "$F"');
      expect(await until(() => lines.includes('two'))).toBe(true);
      sh('echo three >> "$F"');
      expect(await until(() => lines.includes('three'))).toBe(true);
    } finally {
      await t.stop();
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
