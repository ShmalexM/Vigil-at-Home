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
});
