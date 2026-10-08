import { EventEmitter } from 'node:events';
import { appendFileSync, mkdtempSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';

// A folder watch that starts fine and then never reports anything, as when
// the stream behind it stops without an error.
vi.mock('node:fs', async (importOriginal) => {
  const real = await importOriginal<typeof import('node:fs')>();
  return { ...real, watch: () => Object.assign(new EventEmitter(), { close() {} }) };
});

const { FileTailer } = await import('./tail.js');

const dirs: string[] = [];
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

const until = async (check: () => boolean, ms = 2_000) => {
  const end = Date.now() + ms;
  while (!check() && Date.now() < end) await new Promise((r) => setTimeout(r, 10));
  return check();
};

describe('FileTailer with a watch that went quiet', () => {
  it('keeps the fast poll, so a line written just before rotation is not lost', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'vigil-tail-dead-'));
    dirs.push(dir);
    const path = join(dir, 'santa.log');
    writeFileSync(path, 'old\n');
    const lines: string[] = [];
    const t = new FileTailer({
      path,
      intervalMs: 50,
      watchedIntervalMs: 60_000,
      onLine: (l) => lines.push(l),
    });
    await t.start();
    try {
      appendFileSync(path, 'missed\n');
      expect(await until(() => lines.includes('missed'))).toBe(true);
      renameSync(path, path + '.0');
      writeFileSync(path, 'replacement\n');
      expect(await until(() => lines.includes('replacement'))).toBe(true);
      expect(lines).toEqual(['missed', 'replacement']);
    } finally {
      await t.stop();
    }
  });
});
