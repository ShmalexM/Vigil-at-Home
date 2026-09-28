import { afterEach, describe, expect, it } from 'vitest';
import { appendFileSync, mkdtempSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { FileTailer } from './tail.js';

const dirs: string[] = [];
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

function setup() {
  const dir = mkdtempSync(join(tmpdir(), 'vigil-tail-'));
  dirs.push(dir);
  const path = join(dir, 'santa.log');
  const lines: string[] = [];
  return {
    path,
    lines,
    tailer: (from: 'start' | 'end' = 'end') =>
      new FileTailer({ path, from, onLine: (l) => lines.push(l) }),
  };
}

describe('FileTailer', () => {
  it('starts at the end, handles partial lines, rotation and truncation', async () => {
    const { path, lines, tailer } = setup();
    writeFileSync(path, 'old\n');
    const t = tailer();
    await t.start();
    await t.stop(); // stop the timer; drive poll() by hand
    appendFileSync(path, 'one\ntw');
    await t.poll();
    expect(lines).toEqual(['one']);
    appendFileSync(path, 'o\n');
    await t.poll();
    expect(lines).toEqual(['one', 'two']);

    renameSync(path, path + '.0');
    writeFileSync(path, 'three\n');
    await t.poll();
    expect(lines).toEqual(['one', 'two', 'three']);

    writeFileSync(path, 'x\n'); // truncated in place (same inode, smaller)
    await t.poll();
    expect(lines.at(-1)).toBe('x');
  });

  it('does not split multi-byte characters across reads', async () => {
    const { path, lines, tailer } = setup();
    writeFileSync(path, '');
    const t = tailer('start');
    await t.start();
    await t.stop();
    const s = 'é'.repeat(200_000) + '\n'; // 400 KB, crosses the 256 KB chunk boundary
    appendFileSync(path, s);
    await t.poll();
    expect(lines[0]).toBe(s.trimEnd());
  });

  it('resumes from a saved position', async () => {
    const { path, lines } = setup();
    writeFileSync(path, 'a\nb\n');
    const first = new FileTailer({ path, from: 'start', onLine: () => {} });
    await first.start();
    await first.stop();
    await first.poll();
    const saved = first.position!;
    appendFileSync(path, 'c\n');
    const second = new FileTailer({ path, from: saved, onLine: (l) => lines.push(l) });
    await second.start();
    await second.stop();
    await second.poll();
    expect(lines).toEqual(['c']);
  });

  describe('while running', () => {
    const until = async (check: () => boolean, ms = 10_000) => {
      const end = Date.now() + ms;
      while (!check() && Date.now() < end) await new Promise((r) => setTimeout(r, 20));
      return check();
    };
    /** Append warm-up lines until one arrives through the watch. */
    const watchReady = async (path: string, lines: string[]) => {
      for (let i = 0; i < 50 && !lines.some((l) => l.startsWith('warmup')); i++) {
        appendFileSync(path, `warmup ${i}\n`);
        await until(() => lines.some((l) => l.startsWith('warmup')), 200);
      }
      return lines.some((l) => l.startsWith('warmup'));
    };

    it('picks up appends and rotation through the file watch, without waiting for the poll', async () => {
      const { path, lines } = setup();
      writeFileSync(path, '');
      // A fallback poll this slow never fires during the test.
      const t = new FileTailer({ path, intervalMs: 60_000, onLine: (l) => lines.push(l) });
      await t.start();
      try {
        // FSEvents starts its stream asynchronously and drops changes made
        // before it is running, so wait until the watch delivers something.
        expect(await watchReady(path, lines)).toBe(true);
        appendFileSync(path, 'one\n');
        expect(await until(() => lines.includes('one'))).toBe(true);
        renameSync(path, path + '.0');
        writeFileSync(path, 'two\n');
        expect(await until(() => lines.includes('two'))).toBe(true);
        appendFileSync(path, 'three\n');
        expect(await until(() => lines.includes('three'))).toBe(true);
      } finally {
        await t.stop();
      }
    }, 60_000);

    it('finds a file that appears later through the fallback poll', async () => {
      const { path, lines } = setup();
      const t = new FileTailer({ path, intervalMs: 50, onLine: (l) => lines.push(l) });
      await t.start();
      try {
        writeFileSync(path, 'first\n');
        expect(await until(() => lines.includes('first'))).toBe(true);
        appendFileSync(path, 'second\n');
        expect(await until(() => lines.includes('second'))).toBe(true);
      } finally {
        await t.stop();
      }
    });

    it('still works with the watch turned off', async () => {
      const { path, lines } = setup();
      writeFileSync(path, '');
      const t = new FileTailer({
        path,
        watch: false,
        intervalMs: 50,
        onLine: (l) => lines.push(l),
      });
      await t.start();
      try {
        appendFileSync(path, 'polled\n');
        expect(await until(() => lines.includes('polled'))).toBe(true);
      } finally {
        await t.stop();
      }
    });
  });
});
