import { canChangeMode, type Rule, type RuleMode } from '@vigil/core';
import { ThemePref, type AlertDetail, type RuleView, type StatusView } from '../shared/ipc.js';
import { AlertService } from './alerts.js';
import type { Store } from './db/store.js';
import type { ActionExecutor } from './executor.js';
import { Scheduler } from './scheduler.js';
import { SensorRegistry } from './sensors.js';
import { computeStatus } from './status.js';
import { TEST_RULE } from './test-alert.js';

const DAY = 24 * 60 * 60 * 1000;
export const EVENT_RETENTION_DAYS = 30;

/**
 * Everything the main process runs, minus Electron. Windows and IPC sit on
 * top of this; tests and the other packages can drive it directly.
 */
export class VigilCore {
  readonly alerts: AlertService;
  readonly scheduler: Scheduler;
  readonly sensors = new SensorRegistry();

  constructor(
    readonly store: Store,
    readonly executor: ActionExecutor,
    readonly dryRun: boolean,
    private readonly now: () => number = Date.now,
  ) {
    this.alerts = new AlertService(store, executor, now);
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
  }

  stop(): void {
    this.scheduler.stop();
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
    const counts = this.store.ruleMatchCounts(this.now() - 7 * DAY);
    return this.store
      .listRules()
      .filter((r) => r.id !== TEST_RULE.id)
      .map((rule) => ({ rule, matches7d: counts.get(rule.id) ?? 0 }));
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
