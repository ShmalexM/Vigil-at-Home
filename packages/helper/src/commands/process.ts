// Suspend or kill a process, after checking the pid still belongs to the
// program the caller meant. pids get reused, so every action carries the
// expected executable path or start time, and suspend records the identity
// so resume can check it again.

import type { System } from '../system.js';
import { PROTECTED_PROCESS_PREFIXES } from '../config.js';
import { ActionError } from './errors.js';

export interface ProcessIdentity {
  pid: number;
  path: string;
  /** Start time as printed by ps; stable for the life of the process. */
  started: string;
}

/**
 * Identify a running process from kernel data: the executable path from its
 * text mapping (lsof "txt", which argv tricks cannot fake) and its start time.
 */
export async function identifyProcess(
  sys: System,
  pid: number,
): Promise<ProcessIdentity | undefined> {
  const ps = await sys.run('ps', ['-o', 'lstart=', '-p', String(pid)]);
  const started = ps.stdout.trim();
  if (ps.code !== 0 || !started) return undefined;
  const lsof = await sys.run('lsof', ['-a', '-p', String(pid), '-d', 'txt', '-Fn']);
  if (lsof.code !== 0) return undefined;
  // -Fn prints "p<pid>", then "f<fd>", "n<name>" pairs; the first txt name is the executable.
  const nameLine = lsof.stdout.split('\n').find((l) => l.startsWith('n/'));
  if (!nameLine) return undefined;
  return { pid, path: nameLine.slice(1), started };
}

export function isProtectedProcess(path: string): boolean {
  return PROTECTED_PROCESS_PREFIXES.some(
    (p) => path === p.replace(/\/$/, '') || path.startsWith(p),
  );
}

export interface ProcessTarget {
  /** Expected executable path. */
  path?: string;
  /** Expected start time, ms since epoch. ps reports whole seconds, so it matches within a second. */
  startTime?: number;
}

/** ps -o lstart prints local time like "Sat Sep 26 21:00:00 2026". */
export function parseLstart(lstart: string): number {
  return Date.parse(lstart.replace(/\s+/g, ' ').trim());
}

async function checkTarget(
  sys: System,
  pid: number,
  expect: ProcessTarget,
): Promise<ProcessIdentity> {
  if (pid <= 1 || pid === process.pid)
    throw new ActionError('refused', 'that process cannot be touched');
  const id = await identifyProcess(sys, pid);
  if (!id) throw new ActionError('not_found', `process ${pid} is not running`);
  if (expect.path !== undefined && id.path !== expect.path) {
    throw new ActionError('refused', `process ${pid} is now ${id.path}, not ${expect.path}`);
  }
  if (expect.startTime !== undefined) {
    const started = parseLstart(id.started);
    if (!Number.isFinite(started) || Math.abs(started - expect.startTime) >= 1000) {
      throw new ActionError(
        'refused',
        `process ${pid} is not the one that started at ${new Date(expect.startTime).toISOString()}`,
      );
    }
  }
  if (isProtectedProcess(id.path))
    throw new ActionError('refused', `${id.path} is part of macOS or Vigil`);
  return id;
}

export async function suspendProcess(
  sys: System,
  pid: number,
  expect: ProcessTarget,
): Promise<ProcessIdentity> {
  const id = await checkTarget(sys, pid, expect);
  sys.signal(pid, 'SIGSTOP');
  return id;
}

export async function killProcess(
  sys: System,
  pid: number,
  expect: ProcessTarget,
): Promise<ProcessIdentity> {
  const id = await checkTarget(sys, pid, expect);
  sys.signal(pid, 'SIGKILL');
  return id;
}
