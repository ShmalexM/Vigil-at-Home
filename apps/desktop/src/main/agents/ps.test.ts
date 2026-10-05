import { mkdirSync, mkdtempSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { processTableReader, readLinuxProcessTable } from './ps.js';

function fakeProc(): string {
  const proc = mkdtempSync(join(tmpdir(), 'proc-'));
  writeFileSync(join(proc, 'stat'), 'cpu  1 2 3\nbtime 1700000000\nprocesses 9\n');
  const add = (pid: number, stat: string, cmdline?: string, exe?: string) => {
    const dir = join(proc, String(pid));
    mkdirSync(dir);
    writeFileSync(join(dir, 'stat'), stat);
    if (cmdline !== undefined) writeFileSync(join(dir, 'cmdline'), cmdline);
    if (exe) symlinkSync(exe, join(dir, 'exe'));
  };
  // 22nd field (starttime) is 12345 ticks = 123.45 s after boot.
  const rest = (ppid: number) =>
    `S ${ppid} 1 1 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 0 12345 1000 10`;
  add(
    4242,
    `4242 (node) ${rest(4000)}`,
    'node\0/home/a/.local/bin/claude\0--resume\0',
    '/usr/bin/node',
  );
  // A name with spaces and a parenthesis, owned by someone else (no exe link).
  add(17, `17 (Web Content (x)) ${rest(1)}`, '');
  writeFileSync(join(proc, 'self'), '');
  return proc;
}

describe('process table on Linux', () => {
  it('reads pid, parent, start time, executable and arguments from /proc', () => {
    const rows = readLinuxProcessTable(fakeProc()).sort((a, b) => a.pid - b.pid);
    expect(rows).toEqual([
      { pid: 17, ppid: 1, startedAt: 1700000123450, path: 'Web Content (x)' },
      {
        pid: 4242,
        ppid: 4000,
        startedAt: 1700000123450,
        path: '/usr/bin/node',
        args: ['node', '/home/a/.local/bin/claude', '--resume'],
      },
    ]);
  });

  it('gives nothing where /proc is missing', () => {
    expect(readLinuxProcessTable('/nonexistent-proc')).toEqual([]);
  });

  it('reads this computer’s own processes', async () => {
    if (process.platform !== 'linux') return;
    const rows = await processTableReader('linux')();
    const me = rows.find((r) => r.pid === process.pid);
    expect(me?.path).toBe(process.execPath);
    expect(me?.ppid).toBe(process.ppid);
    expect(Math.abs(me!.startedAt - (Date.now() - process.uptime() * 1000))).toBeLessThan(5000);
  });

  it('reads nothing on systems Vigil can’t list', async () => {
    expect(await processTableReader('win32')()).toEqual([]);
  });
});
