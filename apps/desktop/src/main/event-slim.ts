import type { SensorEvent } from '@vigil/core';

/**
 * The event as the history keeps it. Free of Electron so the benchmarks can
 * measure stored bytes with it.
 *
 * - The sensor's raw record roughly doubles an event's size and no rule
 *   reads it, so it goes. It is kept only on events an alert refers to,
 *   which AlertService stores itself.
 * - `process.ancestors` (the parent chain's program names) is kept only
 *   where someone will look at it: on events under a watched agent, whose
 *   session view shows the tree, and on events a rule matched.
 */
export function slimForStorage(e: SensorEvent, matched: boolean): SensorEvent {
  const { raw: _raw, ...slim } = e;
  const p = 'process' in slim ? slim.process : undefined;
  if (p?.ancestors && !p.agent && !matched) {
    const { ancestors: _ancestors, ...process } = p;
    return { ...slim, process } as SensorEvent;
  }
  return slim as SensorEvent;
}
