/** Which list an alert opened by link belongs to, once both lists are loaded. */
export function tabFor(
  id: string | undefined,
  open: readonly { id: string }[] | undefined,
  resolved: readonly { id: string }[] | undefined,
): 'open' | 'resolved' | undefined {
  if (!id || !open || !resolved) return undefined;
  if (open.some((a) => a.id === id)) return 'open';
  if (resolved.some((a) => a.id === id)) return 'resolved';
  return undefined;
}

/**
 * The alert the detail pane shows: the selected one while it is in the list
 * on screen, otherwise the first in that list. So the details always match the
 * chosen tab, and after a decision moves an alert out of Open the next one
 * shows.
 */
export function shownAlert(
  selected: string | undefined,
  list: readonly { id: string }[],
): string | undefined {
  return list.some((a) => a.id === selected) ? selected : list[0]?.id;
}
