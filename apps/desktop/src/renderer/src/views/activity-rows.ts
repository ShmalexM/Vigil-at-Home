import type { EventView } from '../../../shared/ipc';

/**
 * The feed after an older page arrives: the rows current now, up to the row
 * the page was asked from, then the page. Undefined when that row is no
 * longer on screen (a live refresh moved it off the newest page), since the
 * page would leave a gap. Without a cursor row (searching back by day) the
 * page goes after whatever is there. Rows already shown are not repeated.
 */
export function appendOlder(
  current: readonly EventView[],
  page: readonly EventView[],
  fromId: string | undefined,
): EventView[] | undefined {
  let kept = current;
  if (fromId !== undefined) {
    const at = current.findIndex((r) => r.event.id === fromId);
    if (at < 0) return undefined;
    kept = current.slice(0, at + 1);
  }
  const seen = new Set(kept.map((r) => r.event.id));
  return [...kept, ...page.filter((r) => !seen.has(r.event.id))];
}
