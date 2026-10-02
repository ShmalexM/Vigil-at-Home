// Everything the helper does to the operating system goes through this
// module: a fixed set of absolute binary paths run with execFile (never a
// shell), and signal delivery. Tests swap in fakes.

import { execFile } from 'node:child_process';
import { statSync } from 'node:fs';

export const BINARIES = {
  pfctl: '/sbin/pfctl',
  launchctl: '/bin/launchctl',
  ps: '/bin/ps',
  lsof: '/usr/sbin/lsof',
  plutil: '/usr/bin/plutil',
  santactl: '/Applications/Santa.app/Contents/MacOS/santactl',
  osascript: '/usr/bin/osascript',
  codesign: '/usr/bin/codesign',
} as const;

export type BinaryName = keyof typeof BINARIES;

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
}

export function realSystem(binaries: Record<BinaryName, string> = BINARIES): System {
  return {
    run(bin, args, opts = {}) {
      return new Promise((resolve) => {
        const child = execFile(
          binaries[bin],
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
      try {
        return statSync('/dev/console').uid;
      } catch {
        return undefined;
      }
    },
    now: () => Date.now(),
  };
}
