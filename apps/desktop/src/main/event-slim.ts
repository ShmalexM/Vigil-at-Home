import type { SensorEvent } from '@vigil/core';

/**
 * The event as the history keeps it. Free of Electron so the benchmarks can
 * measure stored bytes with it.
 *
 * - The sensor's raw record roughly doubles an event's size and no rule
 *   reads it, so it goes. It is kept only on events an alert refers to,
 *   which AlertService stores itself.
 * - `process.ancestors` (the parent chain's program names) is kept where
 *   someone will look at it: on events under a watched agent, whose session
 *   view shows the tree, and on events a rule matched.
 * - Elsewhere a launch keeps its parent's name when the sensor gave no
 *   parent path (Santa's log never does): `process.parentName` falls back to
 *   it, so replay and a new rule's preview see the parent the live rules saw.
 * - A long command line (an agent's shell wrapper with a whole script in it
 *   averaged 4.3 KB on a developer's Mac, up to 89 KB) keeps the start and
 *   end of each long argument and the first arguments up to a budget, with
 *   a marker saying how much was not stored. Rules saw all of it live;
 *   matched events keep it whole.
 * - `process.parentPath` and `process.downloadedAncestor`, which the helper's
 *   sensor hub fills in from the process tree, always stay: chain rules key
 *   on the download a process came from, and replay needs it.
 */
export function slimForStorage(e: SensorEvent, matched: boolean): SensorEvent {
  const { raw: _raw, ...slim } = e;
  const p = 'process' in slim ? slim.process : undefined;
  if (!p || matched) return slim as SensorEvent;
  const args = p.args && storedArgs(p.args);
  if (p.ancestors && !p.agent) {
    const { ancestors, ...process } = p;
    const launch = slim.kind === 'process.exec' || slim.kind === 'santa.decision';
    const keepParent = launch && !p.parentPath && ancestors.length > 0;
    return {
      ...slim,
      process: {
        ...process,
        ...(keepParent ? { ancestors: ancestors.slice(0, 1) } : {}),
        ...(args && args !== p.args ? { args } : {}),
      },
    } as SensorEvent;
  }
  if (args && args !== p.args) return { ...slim, process: { ...p, args } } as SensorEvent;
  return slim as SensorEvent;
}

/** An argument longer than this keeps its first and last characters only. */
export const MAX_STORED_ARG = 1024;
/** Arguments after this many characters in all are left out. */
export const MAX_STORED_ARGS = 4096;
const ARG_HEAD = 768;
const ARG_TAIL = 192;

/** The arguments as stored: the same array when nothing is long. */
export function storedArgs(args: string[]): string[] {
  let total = 0;
  let long = false;
  for (const a of args) {
    total += a.length;
    if (a.length > MAX_STORED_ARG) long = true;
  }
  if (!long && total <= MAX_STORED_ARGS) return args;
  const out: string[] = [];
  let used = 0;
  for (let i = 0; i < args.length; i++) {
    const a = args[i]!;
    const kept =
      a.length > MAX_STORED_ARG
        ? `${a.slice(0, ARG_HEAD)}…[${a.length - ARG_HEAD - ARG_TAIL} characters not stored]…${a.slice(-ARG_TAIL)}`
        : a;
    if (used + kept.length > MAX_STORED_ARGS && out.length > 0) {
      out.push(`…[${args.length - i} more arguments not stored]`);
      break;
    }
    out.push(kept);
    used += kept.length;
  }
  return out;
}
