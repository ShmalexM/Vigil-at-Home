import { execFile } from 'node:child_process';

/** How long a program told to stop gets before it is killed outright. */
const KILL_GRACE_MS = 2_000;

export interface ExecResult {
  /** Exit code, or null when it was stopped or failed to start. */
  code: number | null;
  stdout: string;
  stderr: string;
  /** It ran past its time limit and was stopped. */
  timedOut: boolean;
}

/**
 * Run a program and settle within `timeoutMs` whatever it does. execFile's own
 * timeout only sends SIGTERM, and its callback waits for the program to
 * exit, so one that ignores SIGTERM (or is stopped) would keep the caller
 * waiting. This answers at the limit and sends SIGKILL a little later.
 */
export function execFileWithin(
  file: string,
  args: readonly string[],
  timeoutMs: number,
  opts: { env?: NodeJS.ProcessEnv; maxBuffer?: number } = {},
): Promise<ExecResult> {
  return new Promise((resolve) => {
    let settled = false;
    const done = (r: ExecResult): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(r);
    };
    const child = execFile(file, [...args], opts, (err, stdout, stderr) =>
      done({
        code: err ? (typeof err.code === 'number' ? err.code : null) : 0,
        stdout: String(stdout),
        stderr: String(stderr),
        timedOut: false,
      }),
    );
    const timer = setTimeout(() => {
      child.kill();
      setTimeout(() => {
        if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
      }, KILL_GRACE_MS).unref();
      done({ code: null, stdout: '', stderr: '', timedOut: true });
    }, timeoutMs);
    timer.unref();
  });
}
