/** "3:04 PM" today, "yesterday at 3:04 PM", else "Oct 2 at 3:04 PM". */
export function checkedAt(ts: number, now = Date.now()): string {
  const time = new Date(ts).toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' });
  const day = (t: number) => new Date(t).toDateString();
  if (day(ts) === day(now)) return time;
  if (day(ts) === day(now - 86_400_000)) return `yesterday at ${time}`;
  const date = new Date(ts).toLocaleDateString([], { month: 'short', day: 'numeric' });
  return `${date} at ${time}`;
}
