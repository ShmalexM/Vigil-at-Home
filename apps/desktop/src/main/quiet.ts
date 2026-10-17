import type { SensorEvent } from '@vigil/core';
import { regexProblem, type Condition } from '@vigil/detection';

/**
 * Keeping the alert list to what needs the user: what counts as "the same
 * thing again" for an agent, and the timings for folding, expiring and
 * ageing out. AlertService and VigilCore use these; nothing here acts.
 */

/** A folded agent row keeps taking repeats while the last one is at most this old. */
export const AGENT_REPEAT_WINDOW_MS = 24 * 60 * 60_000;
/** A rule's suggestion to stop a process lapses after this, even if the pid is still in use. */
export const PROCESS_PROPOSAL_TTL_MS = 4 * 60 * 60_000;
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

/** Placeholders the normalizer writes (private-use characters), one per kind of changing text. */
const TMP = '\uE000tmp\uE001';
const SNAP = '\uE000snap\uE001';
const ID = '\uE000id\uE001';
const NUM = '\uE000n\uE001';

/** What each placeholder may match in an exception: only text of its own kind. */
const MATCHES: Record<string, string> = {
  [TMP]: `(?:/private)?(?:/var/folders/[^/\\s'"]+/[^/\\s'"]+/[TC]|/tmp)/[\\w./+@%=,~-]*`,
  [SNAP]: 'snapshot-[\\w.-]+',
  [ID]: '[0-9a-fA-F-]{8,}',
  [NUM]: '[0-9]+',
};

/**
 * The same text with the parts that change on every run made alike: temp
 * folders and what is in them, snapshot file names, UUIDs, long hex strings
 * and numbers (pids, ports, timestamps, counters).
 */
function placeholders(s: string): string {
  return (
    s
      // macOS per-user temp folders and /tmp, with whatever follows in that path.
      .replace(
        /(?:\/private)?(?:\/var\/folders\/[^/\s'"]+\/[^/\s'"]+\/[TC]|\/tmp)\/[\w./+@%=,~-]*/g,
        TMP,
      )
      // Shell snapshots and similar per-run files: snapshot-zsh-1697-abc123.sh.
      .replace(/snapshot-[\w.-]+/g, SNAP)
      .replace(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi, ID)
      // Long hex mixing letters and digits: hashes, request and session ids.
      .replace(/\b(?=[0-9a-f]*\d)(?=[0-9a-f]*[a-f])[0-9a-f]{8,}\b/gi, ID)
      .replace(/\b\d+\b/g, NUM)
  );
}

/** Human-readable form of a normalized string, for keys and notes. */
export function normalize(s: string): string {
  return placeholders(s)
    .replaceAll(TMP, '<tmp>')
    .replaceAll(SNAP, 'snapshot-<id>')
    .replaceAll(ID, '<id>')
    .replaceAll(NUM, '#');
}

/**
 * What an event did, with run-to-run noise removed: its kind and operation,
 * the program, its command line, and the file, address or port it touched.
 * Two runs of the same agent command give the same pattern.
 */
export function patternOf(e: SensorEvent): string {
  const proc = 'process' in e ? e.process : undefined;
  const parts: Record<string, string> = { kind: e.kind };
  if ('op' in e && typeof e.op === 'string') parts.op = e.op;
  if (proc?.path) parts.program = normalize(proc.path);
  if (proc?.args?.length) parts.command = normalize(proc.args.join(' '));
  if ('path' in e && typeof e.path === 'string') parts.path = normalize(e.path);
  if (e.kind === 'network.connection')
    parts.remote = normalize(e.remoteHost ?? e.remoteAddress ?? '');
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
 * A rule exclusion that matches this event's program and command line again
 * however the changing parts differ, and nothing else: the program's path
 * exactly, and the whole command line as an anchored regex where each
 * changing part may only be text of its kind (digits for a number, and so
 * on), so nothing can be added to the command. Undefined when there is no
 * command line, or it is too long for a rule's regex.
 */
export function commandExclusion(e: SensorEvent): Condition | undefined {
  const proc = 'process' in e ? e.process : undefined;
  if (!proc?.path || !proc.args?.length) return undefined;
  const regex = commandRegex(proc.args.join(' '));
  if (!regex) return undefined;
  return {
    all: [
      { field: 'process.path', op: 'eq', value: proc.path },
      { field: 'process.commandLine', op: 'regex', value: regex },
    ],
  };
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

/**
 * Whether a process is still running. Signal 0 checks without touching it;
 * EPERM means it runs as someone else (root), which still counts.
 */
export function pidAlive(pid: number): boolean {
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
