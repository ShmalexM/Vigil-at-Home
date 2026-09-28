import { canChangeMode, type Rule, type RuleMode } from '@vigil/core';
import { ThemePref, type AlertDetail, type RuleView, type StatusView } from '../shared/ipc.js';
import { AlertService } from './alerts.js';
import { EventLog } from './events.js';
import { BATTERY_SLOWDOWN, type PowerMode } from './power.js';
import type { Store } from './db/store.js';
import type { ActionExecutor } from './executor.js';
import { Scheduler } from './scheduler.js';
import { SensorRegistry } from './sensors.js';
import { computeStatus } from './status.js';
import { TEST_RULE } from './test-alert.js';

const HOUR = 60 * 60 * 1000;
const DAY = 24 * HOUR;
export const EVENT_RETENTION_DAYS = 30;
/**
 * Most disk the database may use (docs/performance.md). At a busy developer's
 * rate of about 100,000 events a day this still holds more than the 14 days
 * rule replay needs.
 */
export const DEFAULT_MAX_DB_BYTES = 1024 * 1024 * 1024;
/** Same window the detection engine replays AI-drafted rules over before approval. */
export const RULE_REVIEW_DAYS = 14;

/**
 * Everything the main process runs, minus Electron. Windows and IPC sit on
 * top of this; tests and the other packages can drive it directly.
 */
export class VigilCore {
  readonly alerts: AlertService;
  readonly scheduler: Scheduler;
  readonly sensors = new SensorRegistry();
  /** Sensors hand every event here after detection has seen it. */
  readonly events: EventLog;

  constructor(
    readonly store: Store,
    readonly executor: ActionExecutor,
    readonly dryRun: boolean,
    private readonly now: () => number = Date.now,
    private readonly maxDbBytes: number = DEFAULT_MAX_DB_BYTES,
  ) {
    this.alerts = new AlertService(store, executor, now);
    this.events = new EventLog(store, {
      onError: (err) => console.error('[events] write failed:', err),
    });
    this.scheduler = new Scheduler({
      onError: (name, err) => console.error(`[scheduler] ${name} failed:`, err),
    });
    store.upsertRule(TEST_RULE);
  }

  start(): void {
    this.scheduler.every(
      'prune-events',
      DAY,
      () => {
        this.store.pruneEvents(this.now() - EVENT_RETENTION_DAYS * DAY);
      },
      true,
    );
    this.scheduler.every('cap-disk', HOUR, () => {
      this.store.pruneEventsToSize(this.maxDbBytes);
    });
  }

  stop(): void {
    this.scheduler.stop();
    this.events.flush();
  }

  /** Slow or hold routine work to match the Mac's power state. */
  applyPower(mode: PowerMode): void {
    this.scheduler.setSlowdown(mode === 'saving' ? BATTERY_SLOWDOWN : 1);
    if (mode === 'constrained') this.scheduler.pause();
    else this.scheduler.resume();
  }

  status(): StatusView {
    const s = computeStatus(this.store.listAlerts({ status: 'open' }), this.sensors.list());
    return { ...s, sensors: this.sensors.list(), dryRun: this.dryRun };
  }

  alertDetail(id: string): AlertDetail | null {
    const alert = this.store.getAlert(id);
    if (!alert) return null;
    const rule = this.store.getRule(alert.ruleId);
    return {
      alert,
      events: this.store.getEvents(alert.eventIds),
      actions: this.store.listActions({ alertId: id }),
      proposals: this.store.listProposals({ alertId: id }),
      ...(rule ? { rule } : {}),
    };
  }

  rules(): RuleView[] {
    const counts = this.store.ruleMatchCounts(this.now() - RULE_REVIEW_DAYS * DAY);
    return this.store
      .listRules()
      .filter((r) => r.id !== TEST_RULE.id)
      .map((rule) => ({ rule, matches: counts.get(rule.id) ?? 0 }));
  }

  /** From the UI, so the actor is the user. */
  setRuleMode(id: string, mode: RuleMode): Rule {
    const rule = this.store.getRule(id);
    if (!rule) throw new Error(`No rule ${id}`);
    if (!canChangeMode('user', rule.mode, mode)) throw new Error('Not allowed');
    const next = { ...rule, mode, updatedAt: this.now() };
    this.store.upsertRule(next);
    return next;
  }

  theme(): ThemePref {
    return this.store.getSetting('theme', ThemePref, 'system');
  }

  setTheme(theme: ThemePref): void {
    this.store.setSetting('theme', ThemePref.parse(theme));
  }
}
