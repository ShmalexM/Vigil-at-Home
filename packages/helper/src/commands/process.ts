// Suspend or kill a process, after checking the pid still belongs to the
// program the caller meant. pids get reused, so every action carries the
// expected executable path or start time, and suspend records the identity
// so resume can check it again.

import type { System } from '../system.js';
import type { Platform } from '../platform.js';
import { protectionFor } from '../config.js';
import { ActionError } from './errors.js';

export interface ProcessIdentity {
  pid: number;
  path: string;
  /** Start time as printed by ps; stable for the life of the process. */
  started: string;
}

/**
 * Identify a running process from kernel data: the executable path from its
 * text mapping (lsof "txt" on macOS, /proc/<pid>/exe on Linux, neither of
 * which argv tricks can fake) and its start time.
 */
export async function identifyProcess(
  sys: System,
  pid: number,
): Promise<ProcessIdentity | undefined> {
  const ps = await sys.run('ps', ['-o', 'lstart=', '-p', String(pid)]);
  const started = ps.stdout.trim();
  if (ps.code !== 0 || !started) return undefined;
  if (sys.platform === 'linux') {
    const path = sys.procExe?.(pid);
    return path?.startsWith('/') ? { pid, path, started } : undefined;
  }
  const lsof = await sys.run('lsof', ['-a', '-p', String(pid), '-d', 'txt', '-Fn']);
  if (lsof.code !== 0) return undefined;
  // -Fn prints "p<pid>", then "f<fd>", "n<name>" pairs; the first txt name is the executable.
  const nameLine = lsof.stdout.split('\n').find((l) => l.startsWith('n/'));
  if (!nameLine) return undefined;
  return { pid, path: nameLine.slice(1), started };
}

export function isProtectedProcess(path: string, platform: Platform = 'darwin'): boolean {
  return protectionFor(platform).processPrefixes.some(
    (p) => path === p.replace(/\/$/, '') || path.startsWith(p),
  );
}

export interface ProcessTarget {
  /** Expected executable path. */
  path?: string;
  /**
   * Vigil's own program files. On Linux an AppImage runs Vigil from a fresh
   * mount under /tmp on every launch, so anything started by the AppImage
   * file itself counts as Vigil.
   */
  self?: readonly string[];
  /** Expected start time, ms since epoch. ps reports whole seconds, so it matches within a second. */
  startTime?: number;
}

/** ps -o lstart prints local time like "Sat Sep 26 21:00:00 2026". */
export function parseLstart(lstart: string): number {
  return Date.parse(lstart.replace(/\s+/g, ' ').trim());
}

/** Linux: whether the pid or one of its ancestors runs one of Vigil's own program files. */
function startedBySelf(sys: System, pid: number, self: readonly string[]): boolean {
  if (sys.platform !== 'linux' || !sys.procExe || !sys.procPpid || self.length === 0) return false;
  let at: number | undefined = pid;
  for (let hop = 0; hop < 16 && at !== undefined && at > 1; hop++) {
    const exe = sys.procExe(at);
    if (exe && self.includes(exe)) return true;
    at = sys.procPpid(at);
  }
  return false;
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
  if (startedBySelf(sys, pid, expect.self ?? []))
    throw new ActionError('refused', `${id.path} is part of Vigil`);
  if (isProtectedProcess(id.path, sys.platform))
    throw new ActionError(
      'refused',
      `${id.path} is part of ${sys.platform === 'linux' ? 'the system' : 'macOS'} or Vigil`,
    );
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
