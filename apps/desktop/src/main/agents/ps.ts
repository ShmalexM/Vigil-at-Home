// Reads the process table, so the agent tracker knows what was already
// running when Vigil started (an agent launched earlier, say) and can fill
// holes the sensors left. At start and at most every 30 s on a miss; never per
// event. macOS: two `ps` spawns, parsed in @vigil/detection (ps-table.ts).
// Linux: /proc, read directly.

import { execFile } from 'node:child_process';
import { readFileSync, readdirSync, readlinkSync } from 'node:fs';
import { join } from 'node:path';
import { MAX_PS_ARGS, mergePsArgs, parsePsComm, type PsRow } from '@vigil/detection';

const PS = '/bin/ps';
const TIMEOUT_MS = 3000;
const MAX_BUFFER = 8 * 1024 * 1024;

/** One `ps` run's output. The C locale fixes the `lstart` format the parser reads. */
export type RunPs = (args: string[]) => Promise<string>;

const runPs: RunPs = (args) =>
  new Promise((resolve, reject) =>
    execFile(
      PS,
      args,
      { env: { LC_ALL: 'C' }, timeout: TIMEOUT_MS, maxBuffer: MAX_BUFFER },
      (err, stdout) => (err ? reject(err) : resolve(String(stdout))),
    ),
  );

/**
 * Every process with its parent, start time, program and command line. The
 * command lines stay in memory (the tracker keeps them only where they decide
 * an agent match); nothing here is stored.
 */
export async function readProcessTable(run: RunPs = runPs): Promise<PsRow[]> {
  const comm = await run(['-axww', '-o', 'pid=,ppid=,lstart=,comm=']);
  const args = await run(['-axww', '-o', 'pid=,args=']);
  return mergePsArgs(parsePsComm(comm), args);
}

/** Clock ticks per second in /proc/<pid>/stat: USER_HZ, 100 on every Linux build Vigil runs on. */
const USER_HZ = 100;

const read = (path: string): string | undefined => {
  try {
    return readFileSync(path, 'utf8');
  } catch {
    return undefined;
  }
};

/**
 * Linux: every process from /proc. The path is the real executable where
 * /proc/<pid>/exe can be read (this user's processes), otherwise the short
 * name the kernel keeps; the command line comes NUL-separated, so arguments
 * keep their own spaces.
 */
export function readLinuxProcessTable(proc = '/proc'): PsRow[] {
  const btime = Number(/^btime (\d+)$/m.exec(read(join(proc, 'stat')) ?? '')?.[1]);
  if (!Number.isFinite(btime)) return [];
  let pids: string[];
  try {
    pids = readdirSync(proc).filter((d) => /^\d+$/.test(d));
  } catch {
    return [];
  }
  const rows: PsRow[] = [];
  for (const pid of pids) {
    const stat = read(join(proc, pid, 'stat'));
    if (!stat) continue; // exited since the listing
    // "pid (comm) state ppid …": comm can hold spaces and parentheses, so cut at the last ')'.
    const close = stat.lastIndexOf(')');
    const comm = stat.slice(stat.indexOf('(') + 1, close);
    const fields = stat.slice(close + 2).split(' ');
    const ppid = Number(fields[1]);
    const ticks = Number(fields[19]);
    if (!Number.isFinite(ppid) || !Number.isFinite(ticks)) continue;
    let path = comm;
    try {
      path = readlinkSync(join(proc, pid, 'exe')).replace(/ \(deleted\)$/, '');
    } catch {
      // Another user's process, or a kernel thread: keep the short name.
    }
    const cmdline = read(join(proc, pid, 'cmdline'))?.replace(/\0+$/, '');
    const row: PsRow = {
      pid: Number(pid),
      ppid,
      startedAt: Math.round((btime + ticks / USER_HZ) * 1000),
      path,
    };
    if (cmdline) row.args = cmdline.slice(0, MAX_PS_ARGS).split('\0');
    rows.push(row);
  }
  return rows;
}

/** The process table on this computer, or none where Vigil can't read it. */
export function processTableReader(
  platform: NodeJS.Platform = process.platform,
): () => Promise<PsRow[]> {
  if (platform === 'darwin') return () => readProcessTable();
  if (platform === 'linux') return async () => readLinuxProcessTable();
  return async () => [];
}
