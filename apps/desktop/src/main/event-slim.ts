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
/** Arguments past this many bytes of stored JSON in all are left out. */
export const MAX_STORED_ARGS = 4096;
const ARG_HEAD = 768;
const ARG_TAIL = 192;

const isHighSurrogate = (c: number) => c >= 0xd800 && c <= 0xdbff;

/** Keep the start and end of a long argument, never splitting an emoji's surrogate pair. */
function trimArg(a: string): string {
  let head = ARG_HEAD;
  if (isHighSurrogate(a.charCodeAt(head - 1))) head--;
  let tail = a.length - ARG_TAIL;
  if (isHighSurrogate(a.charCodeAt(tail - 1))) tail++;
  return `${a.slice(0, head)}…[${tail - head} characters not stored]…${a.slice(tail)}`;
}

/** Bytes an argument takes in the stored JSON: its escaped UTF-8, quotes and comma. */
const storedSize = (a: string) => Buffer.byteLength(JSON.stringify(a)) + 1;

/**
 * The arguments as stored: the same array when nothing is long. The budget
 * counts stored bytes, so many short, empty or non-ASCII arguments are
 * bounded too.
 */
export function storedArgs(args: string[]): string[] {
  // A JSON string takes at most 6 bytes a character (\u escapes), so most
  // command lines are known to fit without encoding them.
  let worst = 0;
  let long = false;
  for (const a of args) {
    worst += a.length * 6 + 3;
    if (a.length > MAX_STORED_ARG) long = true;
  }
  if (!long && worst <= MAX_STORED_ARGS) return args;
  if (!long) {
    let size = 0;
    for (const a of args) if ((size += storedSize(a)) > MAX_STORED_ARGS) break;
    if (size <= MAX_STORED_ARGS) return args;
  }
  const out: string[] = [];
  let used = 0;
  for (let i = 0; i < args.length; i++) {
    const a = args[i]!;
    const kept = a.length > MAX_STORED_ARG ? trimArg(a) : a;
    const size = storedSize(kept);
    if (used + size > MAX_STORED_ARGS && out.length > 0) {
      out.push(`…[${args.length - i} more arguments not stored]`);
      break;
    }
    out.push(kept);
    used += size;
  }
  return out;
}
