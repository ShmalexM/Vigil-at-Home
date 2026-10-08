// Suspend or kill a process, after checking the pid still belongs to the
// program the caller meant. pids get reused, so every action carries the
// expected executable path or start time, and suspend records the identity
// so resume can check it again.

import { insideInstalledRoot, selfRoots, underSelfRoot } from '@vigil/core/self';
import type { System } from '../system.js';
import type { Platform } from '../platform.js';
import { protectionFor } from '../config.js';
import { ActionError } from './errors.js';
import { runsFromSelfImage } from './selfImage.js';

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
 *
 * exec keeps the pid and start time, so a process that execs another
 * program is still "the same process" here, now running that program. For
 * the app pin that is accepted (see appPin.ts runsPinnedApp): a process that
 * execs the pinned app's code is the app from then on, and only a process
 * whose code is already someone's choosing can do it, so nothing the real
 * app depends on changes.
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
  return (
    insideInstalledRoot(path, platform) ||
    protectionFor(platform).processPrefixes.some(
      (p) => path === p.replace(/\/$/, '') || path.startsWith(p),
    )
  );
}

export interface ProcessTarget {
  /** Expected executable path. */
  path?: string;
  /** Linux: what is Vigil's own (FastPath.self()), never paused or stopped. */
  self?: { paths: readonly string[]; images: readonly string[] };
  /**
   * Whether the process runs the app pinned at install (appPin.ts
   * runsPinnedApp); 'changed' when it was replaced while being checked.
   */
  isPinnedApp?: (id: ProcessIdentity) => Promise<boolean | 'changed'>;
  /** Expected start time, ms since epoch. ps reports whole seconds, so it matches within a second. */
  startTime?: number;
}

/** ps -o lstart prints local time like "Sat Sep 26 21:00:00 2026". */
export function parseLstart(lstart: string): number {
  return Date.parse(lstart.replace(/\s+/g, ' ').trim());
}

/**
 * Linux: whether the pid is Vigil. That is a program at or inside one of
 * Vigil's own paths (a .deb install folder, the AppImage file), or Vigil
 * running from its approved AppImage's mount (selfImage.ts). Who started the process doesn't count: programs Vigil
 * starts from anywhere else, such as connectors, are not Vigil.
 */
function isSelf(sys: System, pid: number, exe: string, self: ProcessTarget['self']): boolean {
  if (sys.platform !== 'linux' || !self) return false;
  if (underSelfRoot(selfRoots(self.paths, false), exe, false)) return true;
  return runsFromSelfImage(sys, pid, self.images);
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
  if (isSelf(sys, pid, id.path, expect.self))
    throw new ActionError('refused', `${id.path} is part of Vigil`);
  if (isProtectedProcess(id.path, sys.platform))
    throw new ActionError(
      'refused',
      `${id.path} is part of ${sys.platform === 'linux' ? 'the system' : 'macOS'} or Vigil`,
    );
  // Last, so a program already protected by path costs no codesign.
  const pinned = await expect.isPinnedApp?.(id);
  if (pinned === 'changed')
    throw new ActionError('refused', `process ${pid} changed while it was being checked`);
  if (pinned) throw new ActionError('refused', `${id.path} is Vigil`);
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
