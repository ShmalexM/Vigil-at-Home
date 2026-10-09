import { describe, expect, it } from 'vitest';
import { lineEventId } from './eventId.js';
import { santaLogLineToEvent } from './santa/logParser.js';

describe('lineEventId', () => {
  it('is the same for the same line, and grows with time', () => {
    const a = lineEventId('santa-log:', 'line a', 1_700_000_000_000);
    expect(lineEventId('santa-log:', 'line a', 1_700_000_000_000)).toBe(a);
    expect(a).toMatch(/^santa-log:[0-9a-f]{32}$/);
    const later = lineEventId('santa-log:', 'line 0', 1_700_000_000_001);
    expect(later > a).toBe(true);
    expect(lineEventId('santa-log:', 'line b', 1_700_000_000_000)).not.toBe(a);
  });

  it('is a plain hash when the line has no usable time', () => {
    for (const ts of [undefined, Number.NaN, -1, 1.5, 16 ** 12]) {
      expect(lineEventId('osquery:', 'x', ts)).toBe(lineEventId('osquery:', 'x'));
    }
    expect(lineEventId('osquery:', 'x')).toMatch(/^osquery:[0-9a-f]{32}$/);
  });

  it('gives a reread Santa line the same id, with or without its timestamp', () => {
    const line = '[2026-09-26T21:00:00.123Z] I santad: action=EXIT|pid=5|ppid=1|uid=501';
    expect(santaLogLineToEvent(line)!.id).toBe(santaLogLineToEvent(line)!.id);
    const bare = 'action=EXIT|pid=5|ppid=1|uid=501';
    expect(santaLogLineToEvent(bare, () => 1)!.id).toBe(santaLogLineToEvent(bare, () => 2)!.id);
  });

  it('leaves a Santa time without a zone out of the id, so the time zone can’t change it', () => {
    const local = '[2026-09-26T21:00:00.123] I santad: action=EXIT|pid=5|ppid=1|uid=501';
    expect(santaLogLineToEvent(local)!.id).toBe(lineEventId('santa-log:', local));
    const offset = '[2026-09-26T21:00:00.123+02:00] I santad: action=EXIT|pid=5|ppid=1|uid=501';
    expect(santaLogLineToEvent(offset)!.id).toBe(
      lineEventId('santa-log:', offset, Date.parse('2026-09-26T19:00:00.123Z')),
    );
  });
});
