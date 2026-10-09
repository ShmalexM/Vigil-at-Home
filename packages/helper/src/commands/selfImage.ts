// Linux: whether a process is Vigil running from its AppImage.
//
// An AppImage's runtime mounts the image read-only through FUSE under /tmp
// on every launch, then runs Vigil from that mount. The launch looks like
// this (see the AppImage type 2 runtime):
//
//   launcher (shell, desktop)
//    └─ R: runs the image file, forks the mount server, waits for the
//          mount, then execs <mount>/AppRun, which execs Vigil. R keeps
//          the read end of a keepalive pipe across those execs.
//   S: the mount server. It runs the image file too, holds the image and
//      /dev/fuse open, and leaves R's tree when it daemonizes. It writes
//      to the keepalive pipe and exits once every read end is closed.
//
// So a program counts as Vigil only when:
//   - it runs the approved image itself (by device and inode), or
//   - its executable is on a read-only FUSE mount in the kernel's mount
//     table, and that mount is where the earliest-started process sharing
//     a mount server's keepalive pipe runs from, the server being a process
//     that runs the approved image and holds it and /dev/fuse open.
//
// Nothing is decided by folder names (a folder called .mount_X anywhere is
// nothing), and descendants inherit nothing: a connector Vigil starts runs
// its own program and is contained like any other, while a process running a
// program from inside Vigil's own mount is Vigil. Processes that later share
// the pipe (everything Vigil starts inherits it) started after R, so they
// can't stand in for it.
//
// The earliest-started holder stands in for R. A process the launcher never
// handed the pipe to could hold it only by opening it out of Vigil's own
// /proc/<pid>/fd, which the kernel gates behind ptrace read access to Vigil:
// a same-user attacker with that access is already inside Vigil's own process
// and past any boundary this test could draw. So the pipe need not be proven
// unforgeable here, only unforgeable by a process the kernel keeps at arm's
// length from Vigil, which is every process Vigil did not start.

import {
  isImageMount,
  mountContaining,
  parseMountInfo,
  runsFromMount,
  type MountEntry,
} from '@vigil/core/self';
import type { System } from '../system.js';

const PIPE = /^pipe:\[\d+\]$/;

/** Whether `pid` is Vigil running from one of the approved AppImages (by file id). */
export function runsFromSelfImage(sys: System, pid: number, images: readonly string[]): boolean {
  return selfImageOf(sys, pid, images) !== undefined;
}

/**
 * What {@link runsFromSelfImage} matched: a /proc path that names the
 * approved image file itself (`/proc/<pid>/exe` of the process or of its
 * mount server), never one on a FUSE mount. Reading it reads the image the
 * process runs now, whatever its name. Undefined when there is no match.
 */
export function selfImageOf(
  sys: System,
  pid: number,
  images: readonly string[],
): string | undefined {
  if (sys.platform !== 'linux' || images.length === 0) return undefined;
  if (!sys.procExe || !sys.procPids || !sys.procFds || !sys.procStart || !sys.fileId)
    return undefined;
  const approved = new Set(images);
  const mounts = parseMountInfo(sys.mountInfo?.() ?? '');
  // The file id behind a /proc link, never asked of a FUSE mount: its server
  // answers stat, and one that never answers would hang the helper.
  const idOf = (procPath: string, target: string | undefined) => {
    if (!target?.startsWith('/')) return undefined;
    const fs = mountContaining(mounts, target)?.fsType ?? '';
    return fs === 'fuse' || fs.startsWith('fuse.') ? undefined : sys.fileId!(procPath);
  };
  const exeId = (p: number) => idOf(`/proc/${p}/exe`, sys.procExe!(p));

  // The runtime itself, and the mount server.
  const own = exeId(pid);
  if (own && approved.has(own)) return `/proc/${pid}/exe`;

  const exe = sys.procExe(pid);
  const mount = exe ? mountContaining(mounts, exe) : undefined;
  if (!isImageMount(mount) || mount.mountPoint === '/') return undefined;

  const pids = sys.procPids();
  const fds = new Map<number, [number, string][]>();
  const fdsOf = (p: number) => {
    let f = fds.get(p);
    if (!f) fds.set(p, (f = sys.procFds!(p)));
    return f;
  };
  for (const server of pids) {
    const id = exeId(server);
    if (!id || !approved.has(id)) continue;
    const open = fdsOf(server);
    if (!open.some(([, link]) => link === '/dev/fuse')) continue;
    // Serving this image, not another file it was pointed at.
    if (!open.some(([n, link]) => idOf(`/proc/${server}/fd/${n}`, link) === id)) continue;
    for (const [, link] of open) {
      if (!PIPE.test(link)) continue;
      const first = firstHolder(sys, pids, fdsOf, server, link);
      if (first !== undefined && servesFrom(sys, mounts, first, mount))
        return `/proc/${server}/exe`;
    }
  }
  return undefined;
}

/** The earliest-started process other than `server` that has `pipe` open. */
function firstHolder(
  sys: System,
  pids: readonly number[],
  fdsOf: (pid: number) => [number, string][],
  server: number,
  pipe: string,
): number | undefined {
  let first: { pid: number; start: number } | undefined;
  for (const p of pids) {
    if (p === server || !fdsOf(p).some(([, link]) => link === pipe)) continue;
    const start = sys.procStart?.(p);
    if (start === undefined) continue;
    if (!first || start < first.start || (start === first.start && p < first.pid))
      first = { pid: p, start };
  }
  return first?.pid;
}

/** Whether `pid` runs a program from `mount`. */
function servesFrom(sys: System, mounts: MountEntry[], pid: number, mount: MountEntry): boolean {
  const exe = sys.procExe?.(pid);
  return !!exe && runsFromMount(mounts, exe, mount);
}
