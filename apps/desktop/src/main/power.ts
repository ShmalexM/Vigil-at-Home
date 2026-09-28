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
  on(event: 'on-ac' | 'on-battery' | 'suspend' | 'resume', fn: () => void): unknown;
  on(event: 'thermal-state-change', fn: (e: { state: ThermalState }) => void): unknown;
}

export const BATTERY_SLOWDOWN = 4;
/** System load per core above which optional work waits: the user is busy. */
export const BUSY_LOAD_PER_CORE = 0.8;

export class PowerPolicy extends EventEmitter<{ change: [PowerMode] }> {
  private battery: boolean;
  private thermal: ThermalState;
  private asleep = false;
  private current: PowerMode;

  constructor(
    source: PowerSource,
    private readonly load: () => number = () => loadavg()[0]! / availableParallelism(),
  ) {
    super();
    this.battery = source.isOnBatteryPower();
    this.thermal = source.getCurrentThermalState?.() ?? 'unknown';
    this.current = this.compute();
    source.on('on-ac', () => this.update(() => (this.battery = false)));
    source.on('on-battery', () => this.update(() => (this.battery = true)));
    source.on('suspend', () => this.update(() => (this.asleep = true)));
    source.on('resume', () => this.update(() => (this.asleep = false)));
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

  private update(apply: () => void): void {
    apply();
    const next = this.compute();
    if (next === this.current) return;
    this.current = next;
    this.emit('change', next);
  }
}
