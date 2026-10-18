import { execFileWithin } from '@vigil/ai';
import type { SensorEvent } from '@vigil/core';
import { regexProblem, type Condition } from '@vigil/detection';

/**
 * Keeping the alert list to what needs the user: what counts as "the same
 * thing again" for an agent, and the timings for folding, expiring and
 * ageing out. AlertService and VigilCore use these; nothing here acts.
 */

/**
 * A folded agent row takes repeats for at most this long after its first
 * detection, however often they come: then a new row starts and is shown.
 */
export const AGENT_REPEAT_WINDOW_MS = 24 * 60 * 60_000;
/** How often pending suggestions and ageing alerts are checked. */
export const QUIET_SWEEP_MS = 5 * 60_000;
/** "Close my agents' alerts older than" this. */
export const OLD_AGENT_ALERT_MS = 7 * 24 * 60 * 60_000;
/** Default for the age-out setting: untouched Noticed alerts move to History after this many days. */
export const DEFAULT_AGE_OUT_DAYS = 7;
/** "That was me" this many times on one pattern brings a "Don't show this again" suggestion. */
export const EXCEPTION_AFTER = 3;
/** Those answers count from this far back. */
export const EXCEPTION_WINDOW_MS = 30 * 24 * 60 * 60_000;

/** Placeholders the normalizer writes (private-use characters), one per kind of volatile text. */
const SNAP = '\uE000snap\uE001';
const RAND = '\uE000rand\uE001';
const UUID = '\uE000uuid\uE001';
const HEX = '\uE000hex\uE001';

/** What each placeholder may match in an exception: only text of its own kind and shape. */
const MATCHES: Record<string, string> = {
  [SNAP]: 'snapshot-[a-z]+-[0-9]+-[a-z0-9]+',
  [RAND]: '(?:tmp\\.[A-Za-z0-9]{10}|tmp[a-z0-9_]{8})',
  [UUID]: '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
  [HEX]: '[0-9a-f]{16,}',
};

/** A whole path segment: after a slash, up to the next slash, quote or the end. */
const SEGMENT_END = `(?=[/'"]|$)`;
const VOLATILE_SEGMENTS: Array<[RegExp, string]> = [
  // mktemp's tmp.XXXXXXXXXX and Python tempfile's tmpXXXXXXXX: their exact shapes only.
  [new RegExp(`(?<=/)(?:tmp\\.[A-Za-z0-9]{10}|tmp[a-z0-9_]{8})${SEGMENT_END}`, 'g'), RAND],
  [
    new RegExp(
      `(?<=/)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}${SEGMENT_END}`,
      'gi',
    ),
    UUID,
  ],
  // Long lowercase hex mixing letters and digits: session and request ids.
  [new RegExp(`(?<=/)(?=[0-9a-f]*\\d)(?=[0-9a-f]*[a-f])[0-9a-f]{16,}${SEGMENT_END}`, 'g'), HEX],
];

/**
 * The same text with only the parts that are random on every run made
 * alike: Claude Code's shell snapshot names, and, as whole segments of a
 * local file path, mktemp and tempfile names, UUIDs and long hex ids.
 * Everything that says what was run stays as it is: script and file names,
 * hosts, IP addresses (decimal ones too), ports, numbers and timestamps. A
 * word holding a URL (`://`) or a reference (`@`, as in `image@sha256:`) is
 * left whole, so an attacker-chosen host, path or digest never looks like
 * another.
 */
function placeholders(s: string): string {
  return s
    .split(/(\s+)/)
    .map((word) => {
      if (word.includes('://') || word.includes('@')) return word;
      let out = word.replace(/snapshot-[a-z]+-\d+-[a-z0-9]+/g, SNAP);
      for (const [re, to] of VOLATILE_SEGMENTS) out = out.replace(re, to);
      return out;
    })
    .join('');
}

/** Human-readable form of a normalized string, for keys and notes. */
export function normalize(s: string): string {
  return placeholders(s)
    .replaceAll(SNAP, 'snapshot-<id>')
    .replaceAll(RAND, 'tmp.<random>')
    .replaceAll(UUID, '<uuid>')
    .replaceAll(HEX, '<id>');
}

/** Which program ran: its hash, or its path and signature when there is no hash. */
export function binaryOf(e: SensorEvent): string | undefined {
  const proc = 'process' in e ? e.process : undefined;
  if (!proc) return undefined;
  if (proc.sha256) return `sha256:${proc.sha256}`;
  return `path:${proc.path}|${proc.teamId ?? ''}|${proc.signingId ?? ''}|${proc.signing ?? ''}`;
}

/**
 * What an event did, with only random per-run text removed: its kind and
 * operation, the program, its command line, working directory and parent
 * program, and the file, address or port it touched. Two runs of the same command give the same pattern; a different
 * script, file, host, address or port gives a different one.
 */
export function patternOf(e: SensorEvent): string {
  const proc = 'process' in e ? e.process : undefined;
  const parts: Record<string, string> = { kind: e.kind };
  if ('op' in e && typeof e.op === 'string') parts.op = e.op;
  if (proc?.path) parts.program = normalize(proc.path);
  if (proc?.args?.length) parts.command = normalize(proc.args.join(' '));
  // Where it ran and what started it: `bash ./install.sh` in a project and in Downloads differ.
  if (proc?.cwd) parts.cwd = normalize(proc.cwd);
  if (proc?.parentPath) parts.parent = proc.parentPath;
  if ('path' in e && typeof e.path === 'string') parts.path = normalize(e.path);
  if (e.kind === 'network.connection') {
    parts.remoteAddress = e.remoteAddress;
    if (e.remoteHost) parts.remoteHost = e.remoteHost;
    if (e.remotePort !== undefined) parts.remotePort = String(e.remotePort);
  }
  if (e.kind === 'network.listen') {
    parts.localPort = String(e.localPort);
    if (e.localAddress) parts.localAddress = e.localAddress;
  }
  if (e.kind === 'santa.decision') parts.decision = `${e.target}:${e.decision}`;
  return JSON.stringify(parts);
}

/**
 * The pattern a "That was me" counts toward: the rule, who did it (an agent
 * or the program outside one) and {@link patternOf}.
 */
export function answerPattern(ruleId: string, e: SensorEvent): string {
  const proc = 'process' in e ? e.process : undefined;
  return JSON.stringify([ruleId, proc?.agent?.id ?? null, patternOf(e)]);
}

/**
 * A rule exclusion for this exact program running this exact command, and
 * nothing else: the program's hash (or its path, team and signing ID when
 * there is no hash), and the whole command line as an anchored regex where
 * only random per-run text (snapshot names, mktemp and tempfile names, ids
 * in file paths) may differ. Another script, host, address or port doesn't match,
 * and nothing can be added to the command. Undefined for anything an AI
 * agent ran (an exclusion can't name the agent, so it would hide every
 * agent's and every program's same command), with no command line or no
 * identity to pin, or when the command is too long for a rule's regex.
 */
export function commandExclusion(e: SensorEvent): Condition | undefined {
  const proc = 'process' in e ? e.process : undefined;
  if (!proc?.path || !proc.args?.length || proc.agent) return undefined;
  const regex = commandRegex(proc.args.join(' '));
  if (!regex) return undefined;
  const eq = (field: string, value: string) => ({ field, op: 'eq' as const, value });
  let who: Condition[];
  if (proc.sha256) who = [eq('process.sha256', proc.sha256)];
  else if (proc.teamId && proc.signingId)
    who = [
      eq('process.path', proc.path),
      eq('process.teamId', proc.teamId),
      eq('process.signingId', proc.signingId),
    ];
  else return undefined;
  return { all: [...who, { field: 'process.commandLine', op: 'regex', value: regex }] };
}

/** The command line as an anchored regex (see commandExclusion), or undefined. */
export function commandRegex(command: string): string | undefined {
  const parts = placeholders(command).split(/(\uE000\w+\uE001)/);
  const regex = `^${parts.map((p) => MATCHES[p] ?? escape(p)).join('')}$`;
  if (regexProblem(regex)) return undefined;
  return regex;
}

function escape(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&');
}

/** Whether the process a suggestion is about still runs: its pid, and its start time when known. */
export type Alive = (pid: number, startTime?: number) => boolean;

/** How far apart two start times may be and still be one process (ps reports whole seconds). */
const START_SLACK_MS = 2000;

/**
 * A liveness check for these pids, reading each one's start time with one
 * `ps` call. A pid that runs with another start time is a different
 * process. A pid `ps` doesn't list counts as gone only when signal 0 finds
 * no such process, and when `ps` can't run at all every pid signal 0 finds
 * counts as alive: a suggestion is never dropped for a process that may
 * still run.
 */
export async function liveChecker(
  pids: readonly number[],
  run: typeof execFileWithin = execFileWithin,
): Promise<Alive> {
  const unique = [...new Set(pids)].filter((p) => Number.isInteger(p) && p > 0);
  if (unique.length === 0) return () => false;
  let r: Awaited<ReturnType<typeof execFileWithin>>;
  try {
    r = await run('ps', ['-o', 'pid=,lstart=', '-p', unique.join(',')], 5000, {
      env: { ...process.env, LC_ALL: 'C' },
    });
  } catch {
    // Starting ps can throw outright (spawn EPERM): fall back, never reject.
    return (pid) => pidAlive(pid);
  }
  // ps exits 1 when some pid is gone, still listing the rest.
  if (r.timedOut || (r.code !== 0 && r.code !== 1)) return (pid) => pidAlive(pid);
  const out = r.stdout;
  const starts = new Map<number, number>();
  for (const line of out.split('\n')) {
    const m = /^\s*(\d+)\s+(.+?)\s*$/.exec(line);
    if (!m) continue;
    starts.set(Number(m[1]), Date.parse(m[2]!));
  }
  return (pid, startTime) => {
    // Not listed: gone only if signal 0 agrees (ps lists nothing at all for some bad input).
    if (!starts.has(pid)) return pidAlive(pid);
    const began = starts.get(pid)!;
    if (startTime === undefined || !Number.isFinite(began)) return true;
    return Math.abs(began - startTime) <= START_SLACK_MS;
  };
}

/** Signal 0 checks a pid without touching it; EPERM means it runs as someone else (root). */
function pidAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return (err as NodeJS.ErrnoException).code === 'EPERM';
  }
}

/** Local midnight before `ms`, so "one a day" matches the user's clock. */
export function startOfDay(ms: number): number {
  const d = new Date(ms);
  d.setHours(0, 0, 0, 0);
  return d.getTime();
}
