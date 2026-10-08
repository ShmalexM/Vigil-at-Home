import { EventEmitter } from 'node:events';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { PowerPolicy, WAKE_RECHECK_MS, type PowerSource, type ThermalState } from './power.js';

function fakeSource(battery = false, thermal: ThermalState = 'nominal') {
  const em = new EventEmitter();
  const source = {
    isOnBatteryPower: () => battery,
    getCurrentThermalState: () => thermal,
    on: em.on.bind(em),
  } as unknown as PowerSource;
  return { source, emit: (event: string, arg?: unknown) => em.emit(event, arg) };
}

describe('PowerPolicy', () => {
  it('starts from the current power state', () => {
    expect(new PowerPolicy(fakeSource(false).source, () => 0).mode).toBe('normal');
    expect(new PowerPolicy(fakeSource(true).source, () => 0).mode).toBe('saving');
    expect(new PowerPolicy(fakeSource(false, 'serious').source, () => 0).mode).toBe('constrained');
  });

  it('follows battery, heat and sleep, and announces each change once', () => {
    const { source, emit } = fakeSource();
    const p = new PowerPolicy(source, () => 0);
    const seen: string[] = [];
    p.on('change', (m) => seen.push(m));
    emit('on-battery');
    emit('on-battery');
    emit('thermal-state-change', { state: 'critical' });
    emit('thermal-state-change', { state: 'fair' });
    emit('suspend');
    emit('resume');
    emit('on-ac');
    expect(seen).toEqual(['saving', 'constrained', 'saving', 'constrained', 'saving', 'normal']);
  });

  it('is busy off mains power or when the Mac is loaded', () => {
    let load = 0.1;
    const { source, emit } = fakeSource();
    const p = new PowerPolicy(source, () => load);
    expect(p.isBusy()).toBe(false);
    load = 0.95;
    expect(p.isBusy()).toBe(true);
    load = 0.1;
    emit('on-battery');
    expect(p.isBusy()).toBe(true);
  });

  describe('after sleep', () => {
    afterEach(() => vi.useRealTimers());

    it('wakes up on its own when "resume" never comes', () => {
      vi.useFakeTimers();
      const { source, emit } = fakeSource();
      const p = new PowerPolicy(source, () => 0);
      const modes: string[] = [];
      p.on('change', (m) => modes.push(m));
      emit('suspend');
      expect(p.mode).toBe('constrained');
      vi.advanceTimersByTime(WAKE_RECHECK_MS - 1);
      expect(p.mode).toBe('constrained');
      vi.advanceTimersByTime(1);
      expect(p.mode).toBe('normal');
      expect(modes).toEqual(['constrained', 'normal']);
    });

    it('reads battery and heat afresh when it wakes up that way', () => {
      vi.useFakeTimers();
      let battery = false;
      const em = new EventEmitter();
      const source = {
        isOnBatteryPower: () => battery,
        getCurrentThermalState: () => 'nominal' as ThermalState,
        on: em.on.bind(em),
      } as unknown as PowerSource;
      const p = new PowerPolicy(source, () => 0);
      em.emit('suspend');
      battery = true; // unplugged while asleep, and nothing said so
      vi.advanceTimersByTime(WAKE_RECHECK_MS);
      expect(p.mode).toBe('saving');
    });

    it('leaves a normal resume alone', () => {
      vi.useFakeTimers();
      const { source, emit } = fakeSource();
      const p = new PowerPolicy(source, () => 0);
      const modes: string[] = [];
      p.on('change', (m) => modes.push(m));
      emit('suspend');
      emit('resume');
      emit('suspend');
      vi.advanceTimersByTime(WAKE_RECHECK_MS / 2);
      emit('resume');
      vi.advanceTimersByTime(WAKE_RECHECK_MS);
      expect(modes).toEqual(['constrained', 'normal', 'constrained', 'normal']);
      expect(vi.getTimerCount()).toBe(0);
    });

    it('stays asleep through a dark wake, until someone uses the Mac', () => {
      vi.useFakeTimers();
      let idle = 3_600;
      const em = new EventEmitter();
      const source = {
        isOnBatteryPower: () => false,
        getCurrentThermalState: () => 'nominal' as ThermalState,
        getSystemIdleTime: () => idle,
        on: em.on.bind(em),
      } as unknown as PowerSource;
      const p = new PowerPolicy(source, () => 0);
      em.emit('suspend');
      vi.advanceTimersByTime(WAKE_RECHECK_MS * 3); // Power Nap ran, nobody there
      expect(p.mode).toBe('constrained');
      idle = 5; // the lid opened, and "resume" never came
      vi.advanceTimersByTime(WAKE_RECHECK_MS);
      expect(p.mode).toBe('normal');
      expect(vi.getTimerCount()).toBe(0);
    });
  });
});
