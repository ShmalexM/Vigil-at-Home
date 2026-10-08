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
 * Timers don't run while the Mac sleeps, so one that fires this long after
 * "suspend" means the Mac has run since. That alone could be a dark wake
 * (Power Nap), so it counts as awake once someone has used it within that
 * time, or once it has run without a break in sleep for AWAKE_UNBROKEN_MS
 * (dark wakes are short bursts between sleeps). Then the power state is read
 * afresh, in case "resume" (or a battery or heat change) was never announced.
 * Otherwise it checks again.
 */
export const WAKE_RECHECK_MS = 2 * 60_000;
export const AWAKE_UNBROKEN_MS = 10 * 60_000;
/** More wall-clock time than running time between checks than this means it slept. */
const SLEPT_GAP_MS = 5_000;

/** Wall-clock time (runs on during sleep) and running time (stops during sleep). */
export interface PowerClocks {
  wall: () => number;
  running: () => number;
}
/** System load per core above which optional work waits: the user is busy. */
export const BUSY_LOAD_PER_CORE = 0.8;

export class PowerPolicy extends EventEmitter<{ change: [PowerMode] }> {
  private battery: boolean;
  private thermal: ThermalState;
  private asleep = false;
  private current: PowerMode;
  private recheck?: ReturnType<typeof setTimeout>;
  private lastCheck = { wall: 0, running: 0 };
  private unbroken = 0;

  constructor(
    private readonly source: PowerSource,
    private readonly load: () => number = () => loadavg()[0]! / availableParallelism(),
    private readonly clocks: PowerClocks = { wall: Date.now, running: () => performance.now() },
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
    return this.current !== 'normal' || this.load() > BUSY_LOAD_PER_CORE;
  }

  private compute(): PowerMode {
    if (this.asleep || this.thermal === 'serious' || this.thermal === 'critical')
      return 'constrained';
    return this.battery ? 'saving' : 'normal';
  }

  private checkWakeLater(): void {
    this.lastCheck = { wall: this.clocks.wall(), running: this.clocks.running() };
    clearTimeout(this.recheck);
    this.recheck = setTimeout(() => this.checkWake(), WAKE_RECHECK_MS);
    this.recheck.unref?.();
  }

  private checkWake(): void {
    if (!this.asleep) return;
    const ran = this.clocks.running() - this.lastCheck.running;
    const passed = this.clocks.wall() - this.lastCheck.wall;
    this.unbroken = passed - ran < SLEPT_GAP_MS ? this.unbroken + ran : 0;
    const idle = this.source.getSystemIdleTime?.();
    if (idle !== undefined && idle * 1000 >= WAKE_RECHECK_MS && this.unbroken < AWAKE_UNBROKEN_MS) {
      this.checkWakeLater();
      return;
    }
    this.reread();
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
