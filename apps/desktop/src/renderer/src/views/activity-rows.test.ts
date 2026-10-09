import { describe, expect, it } from 'vitest';
import type { EventView } from '../../../shared/ipc';
import { appendOlder } from './activity-rows';

const row = (id: string) => ({ event: { id } }) as unknown as EventView;
const ids = (rows: EventView[] | undefined) => rows?.map((r) => r.event.id);

describe('appendOlder', () => {
  it('adds the older page to the rows current when it lands, not the ones it started from', () => {
    // Asked from c with rows a b c; a live refresh then brought n in on top.
    expect(ids(appendOlder([row('n'), row('a'), row('b'), row('c')], [row('d')], 'c'))).toEqual([
      'n',
      'a',
      'b',
      'c',
      'd',
    ]);
  });

  it('drops the page when its row has left the screen, rather than leave a gap', () => {
    expect(appendOlder([row('n'), row('m')], [row('d')], 'c')).toBeUndefined();
  });

  it('never shows a row twice, and appends after anything when searching back by day', () => {
    expect(ids(appendOlder([row('a'), row('b')], [row('b'), row('c')], undefined))).toEqual([
      'a',
      'b',
      'c',
    ]);
  });
});
