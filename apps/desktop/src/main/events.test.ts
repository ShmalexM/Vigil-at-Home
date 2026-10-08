import { afterEach, describe, expect, it, vi } from 'vitest';
import { EventLog } from './events.js';
import { makeExec, memoryStore } from './testing.js';

describe('EventLog', () => {
  afterEach(() => vi.useRealTimers());

  it('writes events in one batch after the flush interval', () => {
    vi.useFakeTimers();
    const store = memoryStore();
    const spy = vi.spyOn(store, 'insertEvents');
    const log = new EventLog(store, { flushMs: 1000 });
    for (let i = 0; i < 10; i++) log.add(makeExec());
    expect(store.recentEvents()).toHaveLength(0);
    vi.advanceTimersByTime(1000);
    expect(spy).toHaveBeenCalledTimes(1);
    expect(store.recentEvents()).toHaveLength(10);
  });

  it('writes straight away once a batch is full', () => {
    const store = memoryStore();
    const log = new EventLog(store, { maxBatch: 3 });
    for (let i = 0; i < 3; i++) log.add(makeExec());
    expect(store.recentEvents()).toHaveLength(3);
    log.flush();
  });

  it('drops the raw sensor record, which no rule reads', () => {
    const store = memoryStore();
    const log = new EventLog(store);
    const e = { ...makeExec(), raw: { big: 'x'.repeat(1000) } };
    log.add(e);
    log.flush();
    expect(store.getEvent(e.id)).not.toHaveProperty('raw');
  });

  it('keeps the whole event when an alert stores it after a trimmed copy', () => {
    const store = memoryStore();
    const log = new EventLog(store);
    const base = makeExec();
    const script = 'start ' + 'x'.repeat(3000) + ' MIDDLE ' + 'y'.repeat(3000) + ' end';
    const e = { ...base, process: { ...base.process, args: ['/bin/sh', '-c', script] } };
    log.add(e, { checked: 3, matches: [] });
    log.flush();
    const trimmed = store.getEvent(e.id);
    expect(trimmed?.kind === 'process.exec' && trimmed.process.args?.[2]).not.toContain('MIDDLE');
    // Worth a look raises an alert on the live event a little later.
    store.insertEvent(e);
    const full = store.getEvent(e.id);
    expect(full?.kind === 'process.exec' && full.process.args?.[2]).toBe(script);
    // And a later trimmed copy never replaces the whole one.
    log.add(e, { checked: 3, matches: [] });
    log.flush();
    const still = store.getEvent(e.id);
    expect(still?.kind === 'process.exec' && still.process.args?.[2]).toBe(script);
  });

  it('skips invalid events without losing the rest of the batch', () => {
    const store = memoryStore();
    const log = new EventLog(store);
    log.add(makeExec());
    log.add({ id: 'bad', kind: 'process.exec' } as never);
    log.add(makeExec());
    log.flush();
    expect(store.recentEvents()).toHaveLength(2);
    expect(log.stats()).toMatchObject({ invalid: 1, pending: 0 });
  });

  it('drops events past maxPending instead of growing without limit', () => {
    vi.useFakeTimers();
    const log = new EventLog(memoryStore(), { maxPending: 2, maxBatch: 100 });
    for (let i = 0; i < 5; i++) log.add(makeExec());
    expect(log.stats()).toMatchObject({ pending: 2, dropped: 3 });
  });

  it('tries a failed batch once more before counting it as dropped', () => {
    vi.useFakeTimers();
    const store = memoryStore();
    const errors: unknown[] = [];
    const spy = vi.spyOn(store, 'insertEvents').mockImplementationOnce(() => {
      throw new Error('disk busy');
    });
    const log = new EventLog(store, { flushMs: 1000, onError: (e) => errors.push(e) });
    log.add(makeExec());
    log.add(makeExec());
    log.flush();
    expect(errors).toHaveLength(1);
    expect(log.stats()).toMatchObject({ pending: 2, dropped: 0 });
    vi.advanceTimersByTime(1000);
    expect(spy).toHaveBeenCalledTimes(2);
    expect(store.recentEvents()).toHaveLength(2);
    expect(log.stats()).toMatchObject({ pending: 0, dropped: 0 });
  });

  it('counts a batch that fails twice as dropped', () => {
    const store = memoryStore();
    vi.spyOn(store, 'insertEvents').mockImplementation(() => {
      throw new Error('disk full');
    });
    const log = new EventLog(store, { onError: () => {} });
    log.add(makeExec());
    log.add(makeExec());
    log.flush();
    log.flush();
    expect(log.stats()).toMatchObject({ pending: 0, dropped: 2 });
  });
});
