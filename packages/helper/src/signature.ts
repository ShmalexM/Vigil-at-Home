// Reads a program's code signature with codesign, for programs that started
// before Vigil and so never had their launch (and signature) logged by Santa.
// Rules treat unsigned and ad hoc programs as untrusted; without this, such a
// program's file reads and connections carry no signature at all.
//
// Lookups run one at a time and at most 60 a minute, so a burst of unknown
// programs right after the helper starts can't load the Mac.

import { parsePsStart } from '@vigil/detection';
import type { SignatureInfo } from '@vigil/sensors';
import type { System } from './system.js';

const PER_MINUTE = 60;

/** Parses `codesign -dv` output (it writes to stderr). */
export function parseCodesign(output: string): SignatureInfo | undefined {
  if (/code object is not signed at all/.test(output)) return { signing: 'unsigned' };
  // A path holding a newline can plant lines of its own; the real ones then
  // appear twice, and nothing is trusted.
  if (once(output, /^Identifier=/gm) !== 1 || once(output, /^TeamIdentifier=/gm) > 1)
    return undefined;
  const identifier = /^Identifier=(.+)$/m.exec(output)?.[1]?.trim();
  if (!identifier) return undefined;
  const team = /^TeamIdentifier=([A-Z0-9]{10})$/m.exec(output)?.[1];
  if (/^Platform identifier=\d+/m.test(output))
    return { signing: 'apple', signingId: `platform:${identifier}` };
  if (/^Signature=adhoc$/m.test(output)) return { signing: 'adhoc' };
  const authority = /^Authority=(.+)$/m.exec(output)?.[1] ?? '';
  const signingId = team ? `${team}:${identifier}` : undefined;
  const base = { ...(team ? { teamId: team } : {}), ...(signingId ? { signingId } : {}) };
  if (authority.startsWith('Developer ID Application')) return { signing: 'developer_id', ...base };
  if (authority === 'Apple Mac OS Application Signing') return { signing: 'app_store', ...base };
  return { signing: 'unknown', ...base };
}

function once(output: string, line: RegExp): number {
  return output.match(line)?.length ?? 0;
}

export function signatureLookup(
  sys: System,
  now: () => number = Date.now,
): (path: string) => Promise<SignatureInfo | undefined> {
  const recent: number[] = [];
  let chain: Promise<unknown> = Promise.resolve();
  return (path) => {
    const run = chain.then(async () => {
      const t = now();
      while (recent.length > 0 && t - recent[0]! >= 60_000) recent.shift();
      if (recent.length >= PER_MINUTE || !path.startsWith('/')) return undefined;
      recent.push(t);
      const r = await sys.run('codesign', ['-dv', path], { timeoutMs: 10_000 });
      return parseCodesign(`${r.stderr}\n${r.stdout}`);
    });
    chain = run.catch(() => undefined);
    return run;
  };
}

/** Runs one of the two programs a process signature lookup needs; never a shell. */
export type RunTool = (
  bin: 'codesign' | 'ps',
  args: string[],
) => Promise<{ code: number | null; stdout: string; stderr: string }>;

/** Characters a signing identifier may have before it goes into a requirement. */
const IDENTIFIER = /^[A-Za-z0-9._-]{1,255}$/;

/**
 * Reads the code signature of the program a running process runs, for an
 * agent root found by `ps` (see AgentTracker.onSeededRoot). The answer
 * belongs to that process, not to a path:
 *
 *   1. `codesign -dvv <pid>` names the team and identifier of the program the
 *      kernel says the pid runs (not argv[0], which any program can choose).
 *   2. `codesign --verify -R=<that team and identifier> <pid>` checks the
 *      running code itself is valid and is exactly that team's program, so a
 *      file swapped on disk between the two steps cannot lend its signature.
 *   3. `ps -o lstart= -p <pid>` must still give the start time the tracker
 *      had, so a pid that exited and was reused meanwhile gets nothing.
 *
 * A program with no team ID (unsigned, ad hoc, Apple's own) gets undefined.
 * Lookups run one at a time and at most 60 a minute, like signatureLookup.
 * Accepted limits: ps reports whole seconds, so a pid reused within the same
 * second as the first process started would pass step 3; macOS hands out
 * pids in order, so that needs the whole pid range to wrap within a second.
 * Each step resolves the pid again, so an exec into another program after
 * step 2 keeps the pid and start time and is not seen here. Santa logs that
 * exec, and the tracker's process.exec handling then replaces the program and
 * drops this signature (reExeced); only a missed launch event leaves the
 * window open. Closing it needs the audit-token Security APIs (native code).
 */
export function processSignatureLookup(
  run: RunTool,
  now: () => number = Date.now,
): (
  pid: number,
  startedAt: number,
) => Promise<(SignatureInfo & { executable?: string }) | undefined> {
  const recent: number[] = [];
  let chain: Promise<unknown> = Promise.resolve();
  return (pid, startedAt) => {
    const go = chain.then(
      async (): Promise<(SignatureInfo & { executable?: string }) | undefined> => {
        const t = now();
        while (recent.length > 0 && t - recent[0]! >= 60_000) recent.shift();
        if (recent.length >= PER_MINUTE || !Number.isSafeInteger(pid) || pid <= 1) return undefined;
        recent.push(t);
        const id = String(pid);
        const shown = await run('codesign', ['-dvv', id]);
        if (shown.code !== 0) return undefined;
        const output = `${shown.stderr}\n${shown.stdout}`;
        const info = parseCodesign(output);
        const team = info?.teamId;
        const identifier = info?.signingId?.slice(`${team}:`.length);
        if (!info || !team || !identifier || !IDENTIFIER.test(identifier)) return undefined;
        const req = `anchor apple generic and identifier "${identifier}" and certificate leaf[subject.OU] = "${team}"`;
        const verified = await run('codesign', ['--verify', `-R=${req}`, id]);
        if (verified.code !== 0) return undefined;
        const start = await run('ps', ['-o', 'lstart=', '-p', id]);
        if (start.code !== 0 || parsePsStart(start.stdout) !== startedAt) return undefined;
        // The program verified, so the tracker can tell a sensor naming another one apart.
        const executable =
          once(output, /^Executable=/gm) === 1
            ? /^Executable=(\/.*)$/m.exec(output)?.[1]
            : undefined;
        return executable ? { ...info, executable } : info;
      },
    );
    chain = go.catch(() => undefined);
    return go;
  };
}
