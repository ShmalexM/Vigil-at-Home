import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { Hold, type HoldState } from './hold';

function hold(ms = 1000) {
  const states: HoldState[] = [];
  const onConfirm = vi.fn();
  const h = new Hold(ms, (s) => states.push(s), onConfirm);
  return { h, states, onConfirm };
}

describe('Hold', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  it('confirms once held for long enough', () => {
    const { h, states, onConfirm } = hold();
    h.press({ key: ' ' });
    vi.advanceTimersByTime(1000);
    expect(onConfirm).toHaveBeenCalledOnce();
    expect(states).toEqual(['holding', 'done']);
  });

  it('cancels when the same key lets go early', () => {
    const { h, onConfirm } = hold();
    h.press({ key: 'Enter' });
    vi.advanceTimersByTime(500);
    h.release({ key: 'Enter' });
    vi.advanceTimersByTime(1000);
    expect(onConfirm).not.toHaveBeenCalled();
    expect(h.current).toBe('idle');
  });

  it('ignores a different key, or a pointer, letting go during a key hold', () => {
    const { h, onConfirm } = hold();
    h.press({ key: ' ' });
    h.release({ key: 'Enter' });
    h.release({ key: 'Tab' });
    h.release({ pointer: 1 });
    h.pointerLeft(1);
    expect(h.current).toBe('holding');
    vi.advanceTimersByTime(1000);
    expect(onConfirm).toHaveBeenCalledOnce();
  });

  it('cancels a key hold when focus leaves the button (press Space, Tab away, release)', () => {
    const { h, onConfirm } = hold();
    h.press({ key: ' ' });
    h.abort(); // blur
    vi.advanceTimersByTime(2000);
    // The Space keyup now lands elsewhere; nothing is holding any more.
    h.release({ key: ' ' });
    expect(onConfirm).not.toHaveBeenCalled();
    expect(h.current).toBe('idle');
  });

  it('cancels a pointer hold when that pointer leaves or is cancelled', () => {
    const left = hold();
    left.h.press({ pointer: 7 });
    left.h.pointerLeft(7);
    vi.advanceTimersByTime(2000);
    expect(left.onConfirm).not.toHaveBeenCalled();

    const cancelled = hold();
    cancelled.h.press({ pointer: 7 });
    cancelled.h.abort(); // pointercancel
    vi.advanceTimersByTime(2000);
    expect(cancelled.onConfirm).not.toHaveBeenCalled();
  });

  it('only lets the pointer that started the hold end it', () => {
    const { h, onConfirm } = hold();
    h.press({ pointer: 1 });
    h.release({ pointer: 2 });
    h.release({ key: ' ' });
    h.press({ key: ' ' }); // a second press while holding is ignored
    vi.advanceTimersByTime(1000);
    expect(onConfirm).toHaveBeenCalledOnce();
  });

  it('does not start again once done', () => {
    const { h, onConfirm } = hold();
    h.press({ pointer: 1 });
    vi.advanceTimersByTime(1000);
    h.press({ pointer: 1 });
    vi.advanceTimersByTime(1000);
    expect(onConfirm).toHaveBeenCalledOnce();
    expect(h.current).toBe('done');
  });
});
