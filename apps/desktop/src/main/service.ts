import { EventEmitter } from 'node:events';
import { z } from 'zod';
import { canChangeMode, type Rule, type RuleMode, type SensorEvent } from '@vigil/core';
import {
  ThemePref,
  type AlertDetail,
  type EventOutcome,
  type EventStats,
  type RuleView,
  type StatusView,
} from '../shared/ipc.js';
import { AlertService, type DecisionInput } from './alerts.js';
import { EventLog } from './events.js';
import { BATTERY_SLOWDOWN, type PowerMode } from './power.js';
import type { Store } from './db/store.js';
import { FEED_CHECK_MS, type Detector } from './detection.js';
import type { ActionExecutor } from './executor.js';
import { Scheduler } from './scheduler.js';
import { SensorRegistry } from './sensors.js';
import { computeStatus } from './status.js';
import { TEST_RULE } from './test-alert.js';

const HOUR = 60 * 60 * 1000;
const DAY = 24 * HOUR;
/** The feed hears about new events at most this often, however fast they arrive. */
const FEED_BATCH_MS = 1000;
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
  /** Set at startup when this build ships the helper. */
  helperInstallable = false;
  /** Emits `events` (count) at most once per FEED_BATCH_MS while events arrive. */
  readonly feed = new EventEmitter<{ events: [number] }>();
  /** The rule engine, once attached. Without it events are stored unanalysed. */
  detector: Detector | undefined;
  private feedPending = 0;
  private feedTimer: ReturnType<typeof setTimeout> | undefined;

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
    if (this.detector) {
      const feeds = this.detector.feeds;
      // Threat lists refresh in the background; the engine sees them on its next lookup.
      this.scheduler.every(
        'threat-feeds',
        FEED_CHECK_MS,
        async () => {
          for (const r of await feeds.run()) {
            if (r.status === 'failed')
              console.warn(`[feeds] ${r.sourceId}: ${r.error ?? 'failed'}`);
          }
        },
        true,
      );
    }
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
    clearTimeout(this.feedTimer);
    this.events.flush();
  }

  /** Slow or hold routine work to match the Mac's power state. */
  applyPower(mode: PowerMode): void {
    this.scheduler.setSlowdown(mode === 'saving' ? BATTERY_SLOWDOWN : 1);
    if (mode === 'constrained') this.scheduler.pause();
    else this.scheduler.resume();
  }

  /**
   * Store one sensor event and what detection made of it. Sensors and the
   * detection engine call this; the feed shows it. Writes are batched
   * (EventLog), so the feed ping below and the write land about together.
   */
  ingest(event: SensorEvent, outcome?: EventOutcome): void {
    this.events.add(event, outcome);
    this.feedPending++;
    this.feedTimer ??= setTimeout(() => {
      const n = this.feedPending;
      this.feedPending = 0;
      this.feedTimer = undefined;
      this.feed.emit('events', n);
    }, FEED_BATCH_MS);
  }

  /** Every sensor event enters here: rules first, then storage and alerts. */
  async handleEvent(event: SensorEvent): Promise<void> {
    if (this.detector) await this.detector.handle(event);
    else this.ingest(event);
  }

  /**
   * The user's verdict on an alert. Releases containment when asked, then
   * teaches the rule engine. Confirming it malicious adds a Santa rule, as
   * the user, so it can't run again.
   */
  async decide(alertId: string, input: DecisionInput) {
    const alert = await this.alerts.decide(alertId, input);
    if (this.detector && alert.decision) {
      const learned = this.detector.learn(alertId, alert.decision);
      if (learned.santa) {
        await this.alerts.run('user', learned.santa, {
          alertId,
          reason: 'You confirmed it as malicious',
        });
      }
      if (learned.demoted) console.info(`[detection] ${learned.demoted.message}`);
    }
    return this.store.getAlert(alertId) ?? alert;
  }

  eventStats(): EventStats {
    return {
      ...this.store.eventStats(this.now() - HOUR),
      retentionDays: EVENT_RETENTION_DAYS,
    };
  }

  status(): StatusView {
    const s = computeStatus(this.store.listAlerts({ status: 'open' }), this.sensors.list());
    return {
      ...s,
      sensors: this.sensors.list(),
      dryRun: this.executor.simulated ?? this.dryRun,
      helperInstallable: this.helperInstallable,
    };
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
    const engine = (this.detector?.rules() ?? []).map(({ rule, mode }) => ({
      rule: { ...rule, mode },
      matches: counts.get(rule.id) ?? 0,
    }));
    const own = this.store
      .listRules()
      .filter((r) => r.id !== TEST_RULE.id && !this.detector?.hasRule(r.id))
      .map((rule) => ({ rule, matches: counts.get(rule.id) ?? 0 }));
    return [...engine, ...own];
  }

  /** From the UI, so the actor is the user. */
  setRuleMode(id: string, mode: RuleMode): Rule {
    if (this.detector?.hasRule(id)) {
      this.detector.setMode(id, mode);
      const view = this.detector.rules().find((r) => r.rule.id === id);
      if (!view) throw new Error(`No rule ${id}`);
      return { ...view.rule, mode: view.mode };
    }
    const rule = this.store.getRule(id);
    if (!rule) throw new Error(`No rule ${id}`);
    if (!canChangeMode('user', rule.mode, mode)) throw new Error('Not allowed');
    const next = { ...rule, mode, updatedAt: this.now() };
    this.store.upsertRule(next);
    return next;
  }

  /** First launch on this Mac, recorded once. "First seen" rules learn for a week after it. */
  installedAt(): number {
    const saved = this.store.getSetting('installedAt', z.number().int().positive(), 0);
    if (saved) return saved;
    const now = this.now();
    this.store.setSetting('installedAt', now);
    return now;
  }

  theme(): ThemePref {
    return this.store.getSetting('theme', ThemePref, 'system');
  }

  setTheme(theme: ThemePref): void {
    this.store.setSetting('theme', ThemePref.parse(theme));
  }
}
