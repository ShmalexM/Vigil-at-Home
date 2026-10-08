import { EventEmitter } from 'node:events';
import { z } from 'zod';
import {
  canChangeMode,
  type Alert,
  type RuleMode,
  type SensorEvent,
  type UserDecision,
} from '@vigil/core';
import {
  AlertView,
  Appearance,
  ThemePref,
  type AlertDetail,
  type EventOutcome,
  type EventStats,
  type RuleModeResult,
  type RuleView,
  type StatusView,
} from '../shared/ipc.js';
import { isNoticed } from '../shared/attention.js';
import { DEFAULT_APPEARANCE, type AppearanceSettings } from '../shared/themes.js';
import { AlertService, type DecisionInput } from './alerts.js';
import { EventLog } from './events.js';
import { BATTERY_SLOWDOWN, type PowerMode } from './power.js';
import type { Store } from './db/store.js';
import { FEED_CHECK_MS, type Detector } from './detection.js';
import { RuleEditing } from './rule-editing.js';
import type { ActionExecutor } from './executor.js';
import { Scheduler } from './scheduler.js';
import { SensorRegistry } from './sensors.js';
import { computeStatus } from './status.js';
import { TEST_RULE } from './test-alert.js';
import { WORTH_A_LOOK_RULE } from './worth-a-look.js';
import { UsageService } from './usage.js';

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
/**
 * Also check the cap after this many stored events, not only hourly: a busy
 * Mac (900,000 events a day) passes the cap in hours, and the hourly job
 * waits on the scheduler, which holds routine work while the Mac is hot and
 * starts its hour again at every launch. A check is two PRAGMAs; only a
 * database over the cap pays for a prune.
 */
const CAP_CHECK_EVENTS = 10_000;
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
  /** Set when the installed helper isn't the one this build ships. */
  helperOutdated = false;
  /** Emits `events` (count) at most once per FEED_BATCH_MS while events arrive. */
  readonly feed = new EventEmitter<{ events: [number] }>();
  /** Vigil's AI runs and plan limits, for the Usage page. */
  readonly usage: UsageService;
  /** The rule engine, once attached. Without it events are stored unanalysed. */
  detector: Detector | undefined;
  /** Sees every stored event and its outcome (the AI picks ones to label). Must be cheap. */
  onIngest: ((event: SensorEvent, outcome: EventOutcome | undefined) => void) | undefined;
  private editing: RuleEditing | undefined;
  private feedPending = 0;
  private sinceCapCheck = 0;
  private stopped = false;
  private feedTimer: ReturnType<typeof setTimeout> | undefined;

  constructor(
    readonly store: Store,
    readonly executor: ActionExecutor,
    readonly dryRun: boolean,
    private readonly now: () => number = Date.now,
    private readonly maxDbBytes: number = DEFAULT_MAX_DB_BYTES,
  ) {
    this.alerts = new AlertService(store, executor, now);
    this.usage = new UsageService(store, now);
    this.events = new EventLog(store, {
      onError: (err) => console.error('[events] write failed:', err),
    });
    this.scheduler = new Scheduler({
      onError: (name, err) => console.error(`[scheduler] ${name} failed:`, err),
    });
    store.upsertRule(TEST_RULE);
    store.upsertRule(WORTH_A_LOOK_RULE);
  }

  start(): void {
    if (this.detector) {
      const detector = this.detector;
      // Threat lists refresh in the background; the engine sees them on its next lookup.
      this.scheduler.every(
        'threat-feeds',
        FEED_CHECK_MS,
        async () => {
          for (const r of await detector.refreshFeeds()) {
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
        const before = this.now() - EVENT_RETENTION_DAYS * DAY;
        this.store.pruneEvents(before);
        // Agent sessions go once their events have.
        this.store.pruneAgentSessions(before);
        this.usage.prune();
      },
      true,
    );
    this.scheduler.every('cap-disk', HOUR, () => {
      this.capDisk();
    });
  }

  stop(): void {
    this.stopped = true;
    this.scheduler.stop();
    clearTimeout(this.feedTimer);
    this.events.flush();
  }

  /** Drop the oldest events no alert needs until the database is under its cap. */
  capDisk(): number {
    return this.store.pruneEventsToSize(this.maxDbBytes);
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
    if (++this.sinceCapCheck >= CAP_CHECK_EVENTS) {
      this.sinceCapCheck = 0;
      // After this event's turn, so it never waits on a prune.
      setImmediate(() => {
        if (this.stopped) return; // the store may be closed by now
        try {
          this.capDisk();
        } catch (err) {
          console.error('[events] could not keep the database under its cap:', err);
        }
      });
    }
    this.onIngest?.(event, outcome);
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
    // Learning comes first and its rule change is held, so releasing the
    // block and remembering the exception take one password, not two.
    const decision: UserDecision = {
      at: this.now(),
      verdict: input.verdict,
      remember: input.remember ?? false,
      ...(input.scope ? { scope: input.scope } : {}),
      ...(input.note ? { note: input.note } : {}),
    };
    let held!: () => void;
    const waiting = new Promise<void>((resolve) => (held = resolve));
    const learning = this.detector?.learn(alertId, decision, { hold: true, onHeld: held });
    // Until the rule change is held (or needed no password), so a release's dialog includes it.
    if (learning) await Promise.race([waiting, learning]);
    let alert: Alert;
    try {
      alert = await this.alerts.decide(alertId, input);
    } catch (err) {
      this.executor.dropHeld?.();
      await learning;
      throw err;
    }
    // A release that failed or was cancelled leaves the alert undecided, so
    // nothing is remembered either: the held change is refused and the
    // detector puts its side back. Otherwise ask for anything still held.
    if (alert.decision) await this.executor.approveHeld?.();
    else this.executor.dropHeld?.();
    if (learning) {
      const learned = await learning;
      if (learned.santa) {
        await this.alerts.run('user', learned.santa, {
          alertId,
          reason: 'You confirmed it as malicious',
        });
      }
      if (learned.suggested && learned.suggestDemotion)
        console.info(`[detection] suggested: ${learned.suggestDemotion.message}`);
    }
    return this.store.getAlert(alertId) ?? alert;
  }

  /**
   * "Those were me" on the Noticed list. Only alerts that are still Noticed
   * (shared/attention.ts) are cleared, so this can never release a block or
   * dismiss something that asked for a decision. It doesn't teach the rules
   * either: one tap on a pile shouldn't quietly turn a rule off.
   */
  async clearNoticed(ids: readonly string[]): Promise<number> {
    let cleared = 0;
    for (const id of new Set(ids)) {
      const alert = this.store.getAlert(id);
      if (!alert || !isNoticed(alert)) continue;
      await this.alerts.decide(id, {
        verdict: 'expected',
        release: false,
        note: 'Cleared from Noticed',
      });
      cleared++;
    }
    return cleared;
  }

  eventStats(): EventStats {
    return {
      ...this.store.eventStats(this.now() - HOUR),
      retentionDays: EVENT_RETENTION_DAYS,
    };
  }

  status(): StatusView {
    const s = computeStatus(this.store.listAlerts({ status: 'open' }), this.sensors.list());
    const today = startOfDay(this.now());
    const alertView = this.alertView();
    return {
      ...s,
      alertView,
      badge: s.needsYou + (alertView === 'more' ? s.noticed : 0),
      watch: {
        checkedToday: this.store.countEventsSince(today),
        lastEventAt: this.store.newestEventAt(),
        blockedToday: this.store.countRuleBlocksSince(today),
      },
      sensors: this.sensors.list(),
      dryRun: this.executor.simulated ?? this.dryRun,
      helperInstallable: this.helperInstallable,
      helperOutdated: this.helperOutdated,
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
      .filter(
        (r) =>
          r.id !== TEST_RULE.id && r.id !== WORTH_A_LOOK_RULE.id && !this.detector?.hasRule(r.id),
      )
      .map((rule) => ({ rule, matches: counts.get(rule.id) ?? 0 }));
    return [...engine, ...own];
  }

  /** The rule editor, once detection is running. */
  ruleEditing(): RuleEditing | undefined {
    if (!this.detector) return undefined;
    this.editing ??= new RuleEditing(this.detector, this.store);
    return this.editing;
  }

  /** From the UI, so the actor is the user. */
  /**
   * Waits for the helper: turning a blocking rule down asks for the admin
   * password, and if the user cancels, the rule keeps its mode (`declined`).
   */
  async setRuleMode(id: string, mode: RuleMode): Promise<RuleModeResult> {
    if (this.detector?.hasRule(id)) {
      const helper = await this.detector.setMode(id, mode);
      const view = this.detector.rules().find((r) => r.rule.id === id);
      if (!view) throw new Error(`No rule ${id}`);
      return { rule: { ...view.rule, mode: view.mode }, helper };
    }
    const rule = this.store.getRule(id);
    if (!rule) throw new Error(`No rule ${id}`);
    if (!canChangeMode('user', rule.mode, mode)) throw new Error('Not allowed');
    const next = { ...rule, mode, updatedAt: this.now() };
    this.store.upsertRule(next);
    return { rule: next, helper: 'applied' };
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

  alertView(): AlertView {
    return this.store.getSetting('alertView', AlertView, 'less');
  }

  setAlertView(view: AlertView): void {
    this.store.setSetting('alertView', AlertView.parse(view));
  }

  /** Off by default: the sidebar shows only Home, History and Settings. */
  showAdvanced(): boolean {
    return this.store.getSetting('showAdvanced', z.boolean(), false);
  }

  setShowAdvanced(show: boolean): void {
    this.store.setSetting('showAdvanced', show);
  }

  appearance(): AppearanceSettings {
    return this.store.getSetting('appearance', Appearance, DEFAULT_APPEARANCE);
  }

  setAppearance(appearance: AppearanceSettings): void {
    this.store.setSetting('appearance', Appearance.parse(appearance));
  }
}

/** Local midnight before `ms`, so "today" matches the user's clock. */
function startOfDay(ms: number): number {
  const d = new Date(ms);
  d.setHours(0, 0, 0, 0);
  return d.getTime();
}
