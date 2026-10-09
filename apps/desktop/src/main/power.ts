import { EventEmitter } from 'node:events';
import { availableParallelism, loadavg } from 'node:os';

/**
 * How much background work the Mac can take right now.
 * - `normal`: on power, not hot.
 * - `saving`: on battery. Periodic work runs 4× less often and optional AI
 *   work (the event classifier, rule reviews) waits.
 * - `constrained`: the Mac is hot or asleep. Only urgent work runs.
 *
 * Blocking and alerts never look at this: they run in every mode.
 */
export type PowerMode = 'normal' | 'saving' | 'constrained';

export type ThermalState = 'unknown' | 'nominal' | 'fair' | 'serious' | 'critical';

/** The slice of Electron's powerMonitor this uses, so tests can fake it. */
export interface PowerSource {
  isOnBatteryPower(): boolean;
  getCurrentThermalState?(): ThermalState;
  /** Seconds since the user last used the keyboard or mouse. */
  getSystemIdleTime?(): number;
  on(event: 'on-ac' | 'on-battery' | 'suspend' | 'resume', fn: () => void): unknown;
  on(event: 'thermal-state-change', fn: (e: { state: ThermalState }) => void): unknown;
}

export const BATTERY_SLOWDOWN = 4;
/**
 * Timers don't run while the Mac sleeps, so a check that fires this long
 * after "suspend" means the Mac has run since. That alone could be a dark
 * wake (Power Nap), so it counts as awake once someone has used it since it
 * woke, or once it has run without a break in sleep for AWAKE_UNBROKEN_MS
 * (dark wakes are short bursts between sleeps). Then the power state is read
 * afresh, in case "resume" (or a battery or heat change) was never announced.
 * Otherwise it checks again.
 *
 * A break in sleep shows as a check that fires late: both clocks keep
 * counting through sleep (on macOS, Node's monotonic clock is
 * mach_continuous_time), and the timer only fires once the Mac runs again.
 * Either clock running late counts, so a wall-clock step back can't hide a
 * sleep; a step forward only makes it wait longer.
 */
export const WAKE_RECHECK_MS = 2 * 60_000;
export const AWAKE_UNBROKEN_MS = 10 * 60_000;
/**
 * A check this much later than due means the Mac slept in between. App Nap
 * can hold a background app's timers back by several seconds, so only a
 * long delay counts.
 */
const LATE_MS = 60_000;

/** Wall-clock time and the monotonic clock; both keep counting during sleep. */
export interface PowerClocks {
  wall: () => number;
  monotonic: () => number;
}
/** System load per core above which optional work waits: the user is busy. */
export const BUSY_LOAD_PER_CORE = 0.8;

export class PowerPolicy extends EventEmitter<{ change: [PowerMode] }> {
  private battery: boolean;
  private thermal: ThermalState;
  private asleep = false;
  private current: PowerMode;
  private recheck?: ReturnType<typeof setTimeout>;
  private lastCheck = { wall: 0, monotonic: 0 };
  /** Monotonic time the Mac last came out of sleep (or "suspend" came). */
  private awakeSince = 0;
  private unbroken = 0;

  constructor(
    private readonly source: PowerSource,
    private readonly load: () => number = () => loadavg()[0]! / availableParallelism(),
    private readonly clocks: PowerClocks = {
      wall: Date.now,
      monotonic: () => performance.now(),
    },
  ) {
    super();
    this.battery = source.isOnBatteryPower();
    this.thermal = source.getCurrentThermalState?.() ?? 'unknown';
    this.current = this.compute();
    source.on('on-ac', () => this.update(() => (this.battery = false)));
    source.on('on-battery', () => this.update(() => (this.battery = true)));
    source.on('suspend', () => {
      this.update(() => (this.asleep = true));
      this.unbroken = 0;
      this.lastCheck = { wall: this.clocks.wall(), monotonic: this.clocks.monotonic() };
      this.awakeSince = this.lastCheck.monotonic;
      this.checkWakeLater();
    });
    source.on('resume', () => {
      clearTimeout(this.recheck);
      this.update(() => (this.asleep = false));
    });
    source.on('thermal-state-change', (e) => this.update(() => (this.thermal = e.state)));
  }

  get mode(): PowerMode {
    return this.current;
  }

  /**
   * True when optional background work (the local classifier, AI rule
   * reviews, feed refreshes that can wait) should hold off: on battery, hot,
   * asleep, or the Mac is already busy.
   */
  isBusy(): boolean {
    return this.busyReason() !== undefined;
  }

  /**
   * Why optional work should wait: 'power' (battery, heat, sleep: always
   * wait) or 'load' (the Mac is busy: work that has waited long may go).
   */
  busyReason(): 'power' | 'load' | undefined {
    if (this.current !== 'normal') return 'power';
    return this.load() > BUSY_LOAD_PER_CORE ? 'load' : undefined;
  }

  private compute(): PowerMode {
    if (this.asleep || this.thermal === 'serious' || this.thermal === 'critical')
      return 'constrained';
    return this.battery ? 'saving' : 'normal';
  }

  private checkWakeLater(): void {
    clearTimeout(this.recheck);
    this.recheck = setTimeout(() => this.checkWake(), WAKE_RECHECK_MS);
    this.recheck.unref?.();
  }

  private checkWake(): void {
    if (!this.asleep) return;
    const now = { wall: this.clocks.wall(), monotonic: this.clocks.monotonic() };
    const ran = now.monotonic - this.lastCheck.monotonic;
    const late = Math.max(ran, now.wall - this.lastCheck.wall) - WAKE_RECHECK_MS > LATE_MS;
    this.lastCheck = now;
    if (late) {
      this.unbroken = 0;
      this.awakeSince = now.monotonic;
    } else {
      this.unbroken += ran;
    }
    // Sleep and dark wakes that both fall between two checks still count as
    // running; that takes a dark wake every two minutes, which macOS doesn't do.
    const idle = this.source.getSystemIdleTime?.();
    // Someone used it within one check interval: it is awake, however late
    // the check. (Older use could have come before a sleep.)
    if (idle !== undefined && idle * 1000 < WAKE_RECHECK_MS) return this.reread();
    const used = idle === undefined || idle * 1000 < now.monotonic - this.awakeSince;
    if (used || this.unbroken >= AWAKE_UNBROKEN_MS) this.reread();
    else this.checkWakeLater();
  }

  /** Awake for sure: read battery and heat again rather than trusting missed events. */
  private reread(): void {
    this.update(() => {
      this.asleep = false;
      this.battery = this.source.isOnBatteryPower();
      this.thermal = this.source.getCurrentThermalState?.() ?? this.thermal;
    });
  }

  private update(apply: () => void): void {
    apply();
    const next = this.compute();
    if (next === this.current) return;
    this.current = next;
    this.emit('change', next);
  }
}
