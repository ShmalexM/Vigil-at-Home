import { EventEmitter } from 'node:events';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  AWAKE_UNBROKEN_MS,
  PowerPolicy,
  WAKE_RECHECK_MS,
  type PowerSource,
  type ThermalState,
} from './power.js';

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

    function sleepyMac(idle: () => number = () => 30 * 86_400) {
      const em = new EventEmitter();
      const source = {
        isOnBatteryPower: () => false,
        getCurrentThermalState: () => 'nominal' as ThermalState,
        getSystemIdleTime: idle,
        on: em.on.bind(em),
      } as unknown as PowerSource;
      // Both clocks keep counting through sleep, as on macOS; timers don't fire.
      const clock = { slept: 0, wallStep: 0 };
      const clocks = {
        wall: () => Date.now() + clock.slept + clock.wallStep,
        monotonic: () => Date.now() + clock.slept,
      };
      const p = new PowerPolicy(source, () => 0, clocks);
      return { p, clock, emit: (e: string) => em.emit(e) };
    }

    it('wakes up after running unbroken for a while, even with nobody at the keyboard', () => {
      vi.useFakeTimers();
      const { p, clock, emit } = sleepyMac();
      emit('suspend');
      // Dark wakes: an hour of sleep, then the check fires during a short wake.
      for (let i = 0; i < 20; i++) {
        clock.slept += 3_600_000;
        vi.advanceTimersByTime(WAKE_RECHECK_MS);
      }
      expect(p.mode).toBe('constrained');
      // Then a real wake with nobody touching it (say, a film playing).
      vi.advanceTimersByTime(AWAKE_UNBROKEN_MS - WAKE_RECHECK_MS);
      expect(p.mode).toBe('constrained');
      vi.advanceTimersByTime(WAKE_RECHECK_MS);
      expect(p.mode).toBe('normal');
    });

    it('does not add up short dark wakes into an unbroken run', () => {
      vi.useFakeTimers();
      const { p, clock, emit } = sleepyMac();
      emit('suspend');
      // Each dark wake runs long enough for two checks, then sleeps an hour.
      for (let i = 0; i < 30; i++) {
        clock.slept += 3_600_000;
        vi.advanceTimersByTime(WAKE_RECHECK_MS * 2);
      }
      expect(p.mode).toBe('constrained');
    });

    it('still sees sleep when the wall clock steps back', () => {
      vi.useFakeTimers();
      const { p, clock, emit } = sleepyMac();
      emit('suspend');
      for (let i = 0; i < 20; i++) {
        clock.slept += 3_600_000;
        clock.wallStep -= 3_600_000; // e.g. a time-zone or NTP correction cancelling it out
        vi.advanceTimersByTime(WAKE_RECHECK_MS * 2);
      }
      expect(p.mode).toBe('constrained');
    });

    it('only waits longer when the wall clock steps forward', () => {
      vi.useFakeTimers();
      const { p, clock, emit } = sleepyMac();
      emit('suspend');
      vi.advanceTimersByTime(WAKE_RECHECK_MS * 3);
      clock.wallStep += 60_000;
      vi.advanceTimersByTime(WAKE_RECHECK_MS);
      expect(p.mode).toBe('constrained');
      vi.advanceTimersByTime(AWAKE_UNBROKEN_MS);
      expect(p.mode).toBe('normal');
    });

    it('takes use of the Mac since the last check as awake, even when the check ran late', () => {
      vi.useFakeTimers();
      let idle = 30 * 86_400; // a long weekend away
      const { p, clock, emit } = sleepyMac(() => idle);
      emit('suspend');
      clock.slept += 3_600_000;
      vi.advanceTimersByTime(WAKE_RECHECK_MS);
      expect(p.mode).toBe('constrained');
      clock.slept += 3_600_000;
      idle = 10; // someone opened it; the check fired late
      vi.advanceTimersByTime(WAKE_RECHECK_MS);
      expect(p.mode).toBe('normal');
    });

    it('does not count use from before a sleep once a late check finds it slept', () => {
      vi.useFakeTimers();
      let idle = 30 * 86_400;
      const { p, clock, emit } = sleepyMac(() => idle);
      emit('suspend');
      vi.advanceTimersByTime(WAKE_RECHECK_MS); // on time; nobody there
      expect(p.mode).toBe('constrained');
      // Used a few minutes later, then slept ~an hour; the check fires in a dark wake.
      clock.slept += 58 * 60_000;
      idle = 55 * 60;
      vi.advanceTimersByTime(WAKE_RECHECK_MS);
      expect(p.mode).toBe('constrained');
    });

    it('is not held asleep by checks that App Nap delays a little', () => {
      vi.useFakeTimers();
      const { p, clock, emit } = sleepyMac();
      emit('suspend');
      // Awake all along, nobody at the keyboard, each check 6 s late.
      for (let i = 0; i < 5; i++) {
        clock.slept += 6_000; // the clocks run on while the timer waits
        vi.advanceTimersByTime(WAKE_RECHECK_MS);
      }
      expect(p.mode).toBe('normal');
    });

    it('wakes on use even when every check is delayed', () => {
      vi.useFakeTimers();
      let idle = 30 * 86_400; // a long weekend away
      const { p, clock, emit } = sleepyMac(() => idle);
      emit('suspend');
      clock.slept += 6_000;
      vi.advanceTimersByTime(WAKE_RECHECK_MS);
      expect(p.mode).toBe('constrained');
      idle = 20;
      clock.slept += 6_000;
      vi.advanceTimersByTime(WAKE_RECHECK_MS);
      expect(p.mode).toBe('normal');
    });
  });
});
