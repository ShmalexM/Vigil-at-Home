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
  /** The program itself isn't on this computer. */
  missing?: true;
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
        ...(err?.code === 'ENOENT' ? { missing: true as const } : {}),
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

/** Like execFileWithin, but gives stdout and throws if the program fails or runs out of time. */
export async function execOutputWithin(
  file: string,
  args: readonly string[],
  timeoutMs: number,
  opts: { env?: NodeJS.ProcessEnv; maxBuffer?: number } = {},
): Promise<string> {
  const r = await execFileWithin(file, args, timeoutMs, opts);
  const what = [file.split('/').pop(), ...args].join(' ');
  if (r.timedOut) throw new Error(`${what}: no answer in ${Math.round(timeoutMs / 1000)} s`);
  if (r.code !== 0) {
    const last = r.stderr.trim().split('\n').pop();
    throw new Error(`${what} failed (${r.code ?? 'no exit code'})${last ? `: ${last}` : ''}`);
  }
  return r.stdout;
}
