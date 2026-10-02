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
 * - `process.parentPath` and `process.downloadedAncestor`, which the helper's
 *   sensor hub fills in from the process tree, always stay: chain rules key
 *   on the download a process came from, and replay needs it.
 */
export function slimForStorage(e: SensorEvent, matched: boolean): SensorEvent {
  const { raw: _raw, ...slim } = e;
  const p = 'process' in slim ? slim.process : undefined;
  if (p?.ancestors && !p.agent && !matched) {
    const { ancestors, ...process } = p;
    const launch = slim.kind === 'process.exec' || slim.kind === 'santa.decision';
    const keepParent = launch && !p.parentPath && ancestors.length > 0;
    return {
      ...slim,
      process: keepParent ? { ...process, ancestors: ancestors.slice(0, 1) } : process,
    } as SensorEvent;
  }
  return slim as SensorEvent;
}
