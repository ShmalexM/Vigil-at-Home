import { randomUUID } from 'node:crypto';
import { EventEmitter } from 'node:events';
import { hostname, userInfo } from 'node:os';
import { z } from 'zod';
import {
  canChangeMode,
  type Alert,
  type Rule,
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
  type QuietRuleResult,
  type UndoQuietRuleResult,
  type RuleModeResult,
  type RuleView,
  type StatusView,
} from '../shared/ipc.js';
import { isNoticed } from '../shared/attention.js';
import { untouched } from '../shared/piles.js';
import { DEFAULT_APPEARANCE, type AppearanceSettings } from '../shared/themes.js';
import { AlertService, type DecisionInput } from './alerts.js';
import { evidenceOf } from './evidence-export.js';
import { redactEvidenceInSlices } from './evidence-redact.js';
import { EventLog } from './events.js';
import { BATTERY_SLOWDOWN, type PowerMode } from './power.js';
import type { Store } from './db/store.js';
import { FEED_CHECK_MS, type Detector } from './detection.js';
import { RuleEditing } from './rule-editing.js';
import type { ActionExecutor } from './executor.js';
import { Scheduler } from './scheduler.js';
import { reportFeedHealth } from './sensor-health.js';
import { ruleMatcherHealth, SensorRegistry } from './sensors.js';
import { computeStatus } from './status.js';
import { TEST_RULE } from './test-alert.js';
import { WORTH_A_LOOK_RULE } from './worth-a-look.js';
import { SLOW_RULE } from './slow-rule.js';
import { UsageService } from './usage.js';

/** Scheduled jobs as people know them, for a stuck-work note in the status. */
const JOB_NAMES: Record<string, string> = {
  'pack-dogs': 'pack dogs',
  'label-events': 'AI labels',
  'rule-review': 'rule reviews',
  'threat-feeds': 'threat feeds',
  'prune-events': 'clean-up',
  'cap-disk': 'clean-up',
  'sensor-health': 'sensor checks',
  'agent-discovery': 'finding AI agents',
};

/** How long staleAlerts' answer stands while no open alert changes. */
const STALE_TTL_MS = 60_000;
/** Open alerts looked at for staleAlerts, newest first. */
const STALE_SCAN_LIMIT = 2000;

/** How long the Activity strip's counts are reused (see eventStats). */
export const EVENT_STATS_TTL_MS = 5_000;
/** How long its distinct-programs number is reused: it reads every launch of the hour. */
export const EVENT_PROGRAMS_TTL_MS = 60_000;
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
  /** Why the AI can't work because of its switches (set by the app from AiBridge). */
  aiNotice: (() => string | undefined) | undefined;
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
      // Numbers that say there are no events must not outlive the first
      // ones: the page would show "Nothing to show yet" over a full feed.
      onStored: () => {
        if (this.statsCache?.stats.newest === null) this.statsCache = undefined;
        if (this.programsCache?.n === 0) this.programsCache = undefined;
      },
    });
    this.scheduler = new Scheduler({
      onError: (name, err) => console.error(`[scheduler] ${name} failed:`, err),
    });
    store.upsertRule(TEST_RULE);
    store.upsertRule(WORTH_A_LOOK_RULE);
    store.upsertRule(SLOW_RULE);
    const matcher = ruleMatcherHealth();
    if (matcher) this.sensors.report(matcher);
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
          // A feed whose update was refused shows as one quiet line under Protection.
          reportFeedHealth(this.sensors, detector.feeds.status());
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
   * Open alerts that a rule's exclusion, or the user's exception, now lets
   * off: raised before that exclusion existed (an update made the rule
   * quieter, or the user excluded the same thing from another alert). Only
   * alerts that can be closed without asking count (untouched: nothing
   * held back, no action taken or suggested, and no rule suggestion waiting
   * in the proposals table), and only when the rule excuses
   * every event the alert points to.
   */
  staleAlerts(): string[] {
    const engine = this.detector?.engine;
    if (!engine) return [];
    // The page asks on every change; recount only when an open alert changed,
    // or now and then for a rule or exclusion edited meanwhile.
    const mark = this.store.openAlertsMark();
    const now = this.now();
    const c = this.staleCache;
    if (c && c.mark === mark && now - c.at < STALE_TTL_MS) return c.ids;
    const out: string[] = [];
    for (const a of this.store.listAlerts({ status: 'open', limit: STALE_SCAN_LIMIT })) {
      if (!untouched(a) || this.store.hasPendingProposal(a.id)) continue;
      const events = this.store.getEvents(a.eventIds);
      if (events.length === 0) continue;
      if (events.every((e) => engine.excuses(a.ruleId, e))) out.push(a.id);
    }
    this.staleCache = { mark, at: now, ids: out };
    return out;
  }

  private staleCache: { mark: string; at: number; ids: string[] } | undefined;

  /**
   * Close the given alerts that {@link staleAlerts} still names. Like
   * clearNoticed it teaches the rules nothing: the exclusion already says it.
   */
  async clearStale(ids: readonly string[]): Promise<number> {
    this.staleCache = undefined;
    const stale = new Set(this.staleAlerts());
    let cleared = 0;
    for (const id of new Set(ids)) {
      if (!stale.has(id)) continue;
      await this.alerts.decide(id, {
        verdict: 'expected',
        release: false,
        note: 'Its rule no longer flags this',
      });
      cleared++;
    }
    return cleared;
  }

  /**
   * "Those were me" on the Noticed list. Only alerts that are still Noticed
   * (shared/attention.ts) are cleared, so this can never release a block or
   * dismiss something that asked for a decision. It doesn't teach the rules
   * either: one tap on a pile shouldn't quietly turn a rule off. With
   * `upTo`, an alert last seen after it is left too, checked again just
   * before each one is cleared, so a repeat folded in mid-clear keeps it.
   */
  async clearNoticed(ids: readonly string[], upTo?: number): Promise<number> {
    let cleared = 0;
    for (const id of new Set(ids)) {
      const alert = this.store.getAlert(id);
      // One with an action taken or a suggestion waiting (the AI's or a rule's) stays
      // for a look of its own, so a bulk tap never quietly expires a suggestion.
      if (!alert || !isNoticed(alert) || !untouched(alert)) continue;
      if (this.store.hasPendingProposal(id)) continue;
      if (upTo !== undefined && (alert.repeats?.lastAt ?? alert.createdAt) > upTo) continue;
      await this.alerts.decide(id, {
        verdict: 'expected',
        release: false,
        note: 'Cleared from Noticed',
      });
      cleared++;
    }
    return cleared;
  }

  /**
   * "Those were me" for every Noticed alert, not only the newest the lists
   * loaded. Only alerts last seen by `at`, when the user opened the confirm,
   * are cleared, so anything that turned up while they read it stays, a
   * repeat folded into an older alert included.
   */
  async clearNoticedUpTo(at: number): Promise<number> {
    const ids = this.store
      .listAlerts({ status: 'open', limit: -1 })
      .filter((a) => isNoticed(a) && untouched(a) && (a.repeats?.lastAt ?? a.createdAt) <= at)
      .map((a) => a.id);
    return this.clearNoticed(ids, at);
  }

  private statsCache: { at: number; stats: EventStats } | undefined;
  private programsCache: { at: number; n: number } | undefined;

  /**
   * The Activity strip's numbers. A busy Mac stores 200,000 events an hour
   * while the page asks again with every batch of events, about once a
   * second, so the counts are at most {@link EVENT_STATS_TTL_MS} old and the
   * costly distinct-programs number at most {@link EVENT_PROGRAMS_TTL_MS}.
   */
  eventStats(): EventStats {
    const now = this.now();
    if (this.statsCache && now - this.statsCache.at < EVENT_STATS_TTL_MS) {
      return this.statsCache.stats;
    }
    const since = now - HOUR;
    if (!this.programsCache || now - this.programsCache.at >= EVENT_PROGRAMS_TTL_MS) {
      this.programsCache = { at: now, n: this.store.programsSince(since) };
    }
    const stats = {
      ...this.store.eventCounts(since),
      programsLastHour: this.programsCache.n,
      retentionDays: EVENT_RETENTION_DAYS,
    };
    this.statsCache = { at: now, stats };
    return stats;
  }

  status(): StatusView {
    // Counted over every open alert, not the newest 200 the lists load, so Home,
    // the menu bar and the badge agree however many have piled up.
    const s = { ...computeStatus([], this.sensors.list()), ...this.store.openAlertCounts() };
    const today = startOfDay(this.now());
    const alertView = this.alertView();
    const stuck = this.scheduler
      .status()
      .filter((j) => j.stuck)
      .map((j) => JOB_NAMES[j.name] ?? j.name);
    const aiOff = this.aiNotice?.();
    return {
      ...s,
      // Work that stopped is said plainly; it doesn't lower the level.
      reasons: stuck.length
        ? [...s.reasons, `Background work stuck: ${stuck.join(', ')}`]
        : s.reasons,
      stuckJobs: stuck,
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
      ...(aiOff ? { aiOff } : {}),
    };
  }

  alertDetail(id: string): AlertDetail | null {
    const alert = this.store.getAlert(id);
    if (!alert) return null;
    // Pack rules live in the engine, not the rules table; its mode is the one in force.
    const rule = this.detector?.rule(alert.ruleId) ?? this.store.getRule(alert.ruleId);
    return {
      alert,
      events: this.store.getEvents(alert.eventIds),
      actions: this.store.listActions({ alertId: id }),
      proposals: this.store.listProposals({ alertId: id }),
      ...(rule ? { rule } : {}),
    };
  }

  /**
   * The alert as JSON for a bug report, a note or another tool. A command
   * line that might hold a secret is withheld whole; other text goes through
   * the same redaction as data sent to a model (home folders, keys, tokens,
   * emails); and this computer's user and host names are hidden at any
   * length (evidence-redact.ts).
   * It exports only the fields evidence-export.ts picks, so neither an event's
   * raw sensor record nor an internal key such as a repeat's goes out.
   */
  async alertEvidence(id: string): Promise<string | null> {
    const d = this.alertDetail(id);
    if (!d) return null;
    const out = await redactEvidenceInSlices(evidenceOf(d), this.evidenceRedaction());
    return JSON.stringify(out, null, 2);
  }

  /** Whose names the copied evidence hides. Overridable for tests. */
  evidenceRedaction = (): { username?: string; hostname?: string } => {
    try {
      return { username: userInfo().username, hostname: hostname() };
    } catch {
      return { hostname: hostname() };
    }
  };

  rules(): RuleView[] {
    const counts = this.store.ruleMatchCounts(this.now() - RULE_REVIEW_DAYS * DAY);
    const slow = this.detector?.slowRules() ?? new Set<string>();
    const legacy = this.detector?.legacyRules() ?? new Set<string>();
    const engine = (this.detector?.rules() ?? []).map(({ rule, mode, learningUntil }) => ({
      rule: { ...rule, mode },
      matches: counts.get(rule.id) ?? 0,
      ...(learningUntil !== undefined ? { learningUntil } : {}),
      ...(slow.has(rule.id) ? { slow: true } : {}),
      ...(legacy.has(rule.id) ? { legacy: true } : {}),
    }));
    const own = this.store
      .listRules()
      .filter(
        (r) =>
          r.id !== TEST_RULE.id &&
          r.id !== WORTH_A_LOOK_RULE.id &&
          r.id !== SLOW_RULE.id &&
          !this.detector?.hasRule(r.id),
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
      const { helper, reason } = await this.detector.changeMode(id, mode);
      const view = this.detector.rules().find((r) => r.rule.id === id);
      if (!view) throw new Error(`No rule ${id}`);
      const out: RuleModeResult = { rule: { ...view.rule, mode: view.mode }, helper };
      if (reason !== undefined) out.helperReason = reason;
      return out;
    }
    const rule = this.store.getRule(id);
    if (!rule) throw new Error(`No rule ${id}`);
    if (!canChangeMode('user', rule.mode, mode)) throw new Error('Not allowed');
    this.ownQuieted.delete(id);
    const next = { ...rule, mode, updatedAt: this.now() };
    this.store.upsertRule(next);
    return { rule: next, helper: 'applied' };
  }

  /**
   * "Only log this rule" from an alert: Alert to Shadow, only if the rule is
   * in Alert when the change applies. Refused, with the mode, in any other
   * mode (another change may have made it block since the card drew). The
   * result carries the override it replaced and a token for `undoQuietRule`.
   */
  async quietRule(id: string): Promise<QuietRuleResult> {
    if (this.detector?.hasRule(id)) {
      const { value, helper, reason } = await this.detector.quiet(id);
      if (!value.ok) return value;
      const rule = this.ruleNow(id);
      return {
        ok: true,
        prior: value.prior,
        token: value.token,
        rule,
        helper,
        ...(reason === undefined ? {} : { reason }),
      };
    }
    const rule = this.store.getRule(id);
    if (!rule) throw new Error(`No rule ${id}`);
    if (rule.mode !== 'alert') return { ok: false, mode: rule.mode };
    this.store.upsertRule({ ...rule, mode: 'shadow', updatedAt: this.now() });
    const after = this.store.getRule(id)!;
    const token = randomUUID();
    this.ownQuieted.set(id, { token, after: JSON.stringify(after) });
    return { ok: true, prior: 'alert', token, rule: after, helper: 'applied' };
  }

  /** Undo `quietRule`, only while nothing about the rule has changed since. */
  async undoQuietRule(id: string, token: string): Promise<UndoQuietRuleResult> {
    if (this.detector?.hasRule(id)) {
      const { value, helper, reason } = await this.detector.undoQuiet(id, token);
      if (!value.ok) return value;
      return {
        ok: true,
        rule: this.ruleNow(id),
        helper,
        ...(reason === undefined ? {} : { reason }),
      };
    }
    const rule = this.store.getRule(id);
    if (!rule) throw new Error(`No rule ${id}`);
    const done = this.ownQuieted.get(id);
    if (!done || done.token !== token || done.after !== JSON.stringify(rule)) {
      return { ok: false, mode: rule.mode };
    }
    this.ownQuieted.delete(id);
    // A rule of the user's own has no override: its mode is the rule's, and it was Alert.
    this.store.upsertRule({ ...rule, mode: 'alert', updatedAt: this.now() });
    return { ok: true, rule: this.store.getRule(id)!, helper: 'applied' };
  }

  /** The user's own rules' last quiet: its token and the rule as it left it. */
  private readonly ownQuieted = new Map<string, { token: string; after: string }>();

  /** An engine rule in the mode it runs in. */
  private ruleNow(id: string): Rule {
    const view = this.detector?.rules().find((r) => r.rule.id === id);
    if (!view) throw new Error(`No rule ${id}`);
    return { ...view.rule, mode: view.mode };
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
