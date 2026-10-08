// Everything the helper does to the operating system goes through this
// module: a fixed set of absolute binary paths run with execFile (never a
// shell), and signal delivery. Tests swap in fakes.

import { execFile } from 'node:child_process';
import { readFileSync, readlinkSync, statSync } from 'node:fs';
import { hostPlatform, type Platform } from './platform.js';

export const BINARIES = {
  pfctl: '/sbin/pfctl',
  launchctl: '/bin/launchctl',
  ps: '/bin/ps',
  lsof: '/usr/sbin/lsof',
  plutil: '/usr/bin/plutil',
  santactl: '/Applications/Santa.app/Contents/MacOS/santactl',
  osascript: '/usr/bin/osascript',
  codesign: '/usr/bin/codesign',
  osqueryd: '/opt/osquery/lib/osquery.app/Contents/MacOS/osqueryd',
} as const;

/**
 * The Linux set. Paths are the merged-/usr locations every current Debian,
 * Ubuntu and Fedora release uses (/bin and /sbin link into /usr there).
 */
export const LINUX_BINARIES = {
  ps: '/usr/bin/ps',
  nft: '/usr/sbin/nft',
  systemctl: '/usr/bin/systemctl',
  pkexec: '/usr/bin/pkexec',
  dpkgQuery: '/usr/bin/dpkg-query',
  rpm: '/usr/bin/rpm',
  fagenrules: '/usr/sbin/fagenrules',
  osqueryd: '/opt/osquery/bin/osqueryd',
} as const;

export type MacBinaryName = keyof typeof BINARIES;
export type LinuxBinaryName = keyof typeof LINUX_BINARIES;
export type BinaryName = MacBinaryName | LinuxBinaryName;

/** Absolute paths for every binary the helper may run on `platform`; the others are left out. */
export function binariesFor(platform: Platform): Partial<Record<BinaryName, string>> {
  return platform === 'linux' ? LINUX_BINARIES : BINARIES;
}

export interface RunResult {
  code: number;
  stdout: string;
  stderr: string;
}

export interface System {
  run(
    bin: BinaryName,
    args: string[],
    opts?: { input?: string; timeoutMs?: number },
  ): Promise<RunResult>;
  signal(pid: number, signal: 'SIGSTOP' | 'SIGCONT' | 'SIGKILL'): void;
  /** uid of the user logged in at the screen, if any. */
  consoleUid(): number | undefined;
  now(): number;
  /** Which OS the commands target. Absent means macOS, which is what every fake assumed. */
  readonly platform?: Platform;
  /**
   * Linux only: the executable a pid runs, from /proc/<pid>/exe. The kernel
   * keeps that link, so argv tricks can't fake it.
   */
  procExe?(pid: number): string | undefined;
  /** Linux only: a pid's parent, from /proc/<pid>/stat. */
  procPpid?(pid: number): number | undefined;
}

export function realSystem(
  binaries: Partial<Record<BinaryName, string>> = binariesFor(hostPlatform()),
  platform: Platform = hostPlatform(),
): System {
  return {
    platform,
    run(bin, args, opts = {}) {
      const file = binaries[bin];
      if (!file) {
        return Promise.resolve({
          code: 127,
          stdout: '',
          stderr: `${bin} is not used on ${platform}`,
        });
      }
      return new Promise((resolve) => {
        const child = execFile(
          file,
          args,
          {
            timeout: opts.timeoutMs ?? 15_000,
            maxBuffer: 8 * 1024 * 1024,
            env: { PATH: '/usr/bin:/bin:/usr/sbin:/sbin' },
          },
          (err, stdout, stderr) => {
            const code = err
              ? typeof (err as NodeJS.ErrnoException).code === 'number'
                ? Number((err as NodeJS.ErrnoException).code)
                : 1
              : 0;
            resolve({
              code,
              stdout: String(stdout),
              stderr: String(stderr) || (err?.message ?? ''),
            });
          },
        );
        if (opts.input !== undefined) child.stdin?.end(opts.input);
      });
    },
    signal(pid, sig) {
      process.kill(pid, sig);
    },
    consoleUid() {
      if (platform === 'linux') return linuxSeatUid();
      try {
        return statSync('/dev/console').uid;
      } catch {
        return undefined;
      }
    },
    now: () => Date.now(),
    procExe(pid) {
      try {
        return readlinkSync(`/proc/${pid}/exe`).replace(/ \(deleted\)$/, '');
      } catch {
        return undefined;
      }
    },
    procPpid(pid) {
      try {
        // "pid (comm) state ppid ...": comm may hold spaces or parens, so read after the last ')'.
        const stat = readFileSync(`/proc/${pid}/stat`, 'utf8');
        const ppid = Number(stat.slice(stat.lastIndexOf(')') + 2).split(' ')[1]);
        return Number.isInteger(ppid) ? ppid : undefined;
      } catch {
        return undefined;
      }
    },
  };
}

/**
 * The user at the screen on Linux. /dev/console belongs to root there, so
 * ask systemd-logind instead: it writes the active session's owner of the
 * first seat to /run/systemd/seats/seat0.
 */
export function linuxSeatUid(
  read: (path: string) => string = (p) => readFileSync(p, 'utf8'),
): number | undefined {
  try {
    const m = /^ACTIVE_UID=(\d+)$/m.exec(read('/run/systemd/seats/seat0'));
    return m ? Number(m[1]) : undefined;
  } catch {
    return undefined;
  }
}
