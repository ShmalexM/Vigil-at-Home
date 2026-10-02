import type { DatabaseSync } from 'node:sqlite';
import { z } from 'zod';
import type { Rule, RuleMode, SensorEvent, UserDecision } from '@vigil/core';
import {
  DEFAULT_FEEDS,
  DetectionEngine,
  FeedImporter,
  Feedback,
  RuleEditor,
  RulePipeline,
  RuleReviewer,
  macosCoreRules,
  mergeRules,
  sqliteStores,
  type DecisionResult,
  type Detection,
  type DetectionRule,
  type EventHistory,
  type FeedImporterOptions,
  type AnalyzeRunner,
  type FeedStatus,
  type FlaggedEvent,
  type ReviewState,
  type SqliteDetectionStores,
} from '@vigil/detection';
import { fastPathRules } from '@vigil/detection/fastpath';
import { userOrigin } from '@vigil/detection/user';
import type { EventOutcome } from '../shared/ipc.js';
import type { AlertService } from './alerts.js';
import type { Store } from './db/store.js';
import type { HelperRuleSet } from './helper.js';

const KEY_REVIEW = 'detection.review';

const DAY = 24 * 60 * 60 * 1000;
/** "First seen" rules only record for this long after install: everything is new at first. */
export const LEARNING_DAYS = 7;
/** How often to check whether a threat feed is due. Each feed has its own interval. */
export const FEED_CHECK_MS = 30 * 60 * 1000;

export interface DetectorOptions {
  /** When Vigil was first installed on this Mac. */
  installedAt: number;
  /** Vigil's own executable, which the safety floor never touches. */
  selfPaths: string[];
  feeds?: FeedImporterOptions;
  now?: () => number;
}

/**
 * Runs every sensor event through the deterministic engine, then stores it
 * with what the rules made of it, raises alerts, runs block-mode responses
 * and records shadow matches. No AI anywhere on this path.
 */
export class Detector {
  readonly engine: DetectionEngine;
  readonly stores: SqliteDetectionStores;
  readonly feedback: Feedback;
  readonly feeds: FeedImporter;
  /** The user's rule editor (Rules screen and "exclude" on alerts). */
  readonly editor: RuleEditor;
  /** AI proposals: checked, replayed on 14 days, then waiting for the user. */
  readonly pipeline: RulePipeline;
  private reviewer: RuleReviewer | undefined;
  private checkedByKind = new Map<string, number>();
  private readonly now: () => number;
  private readonly selfPaths: string[];
  /** Called after rules, modes or exceptions change, so the helper's copy can follow. */
  onRulesChanged: (() => void) | undefined;

  constructor(
    private readonly db: DatabaseSync,
    private readonly store: Store,
    private readonly alerts: AlertService,
    private readonly ingest: (e: SensorEvent, outcome: EventOutcome) => void,
    opts: DetectorOptions,
  ) {
    this.now = opts.now ?? Date.now;
    this.selfPaths = opts.selfPaths;
    // Detection keeps its state in det_* tables in the same database. Replay
    // history reads the app's own event table rather than keeping a second copy.
    this.stores = { ...sqliteStores(db), history: appHistory(store) };
    this.engine = new DetectionEngine(
      mergeRules(macosCoreRules, this.stores.rules.list()),
      this.stores,
      {
        learningUntil: opts.installedAt + LEARNING_DAYS * DAY,
        safety: { selfPaths: opts.selfPaths },
        recordHistory: false,
      },
    );
    this.feedback = new Feedback(this.engine, undefined, this.now);
    this.feeds = new FeedImporter(DEFAULT_FEEDS, this.stores.lists, this.stores.feeds, {
      now: this.now,
      ...opts.feeds,
    });
    this.editor = new RuleEditor(
      this.engine,
      macosCoreRules,
      this.stores.rules,
      this.stores.history,
      {
        now: this.now,
      },
    );
    this.pipeline = new RulePipeline(this.engine, this.stores.history, this.stores.proposals, {
      now: this.now,
      repository: this.stores.rules,
    });
    this.recount();
  }

  /**
   * Turn on the daily rule review. `runner` gives the signed-in AI, or
   * undefined when none is set up. The scheduler calls `reviewRules` often;
   * the reviewer decides when a run is due.
   */
  attachReviewer(runner: () => AnalyzeRunner | undefined, isBusy?: () => boolean): void {
    this.reviewer = new RuleReviewer(
      runner,
      {
        engine: this.engine,
        pipeline: this.pipeline,
        history: this.stores.history,
        flagged: (from, to) => this.flagged(from, to),
        now: this.now,
      },
      {
        get: () => this.store.getSetting(KEY_REVIEW, ReviewStateSchema, {}) as ReviewState,
        put: (s) => this.store.setSetting(KEY_REVIEW, s),
      },
      {
        countEvents: (from, to) => this.countEvents(from, to),
        ...(isBusy ? { isBusy } : {}),
        now: this.now,
      },
    );
  }

  async reviewRules(opts: { force?: boolean } = {}) {
    if (!this.reviewer) return { ran: false as const, reason: 'no_runner' as const };
    const out = await this.reviewer.maybeRun(opts);
    return out;
  }

  reviewStatus(): (ReviewState & { nextDueAt: number }) | undefined {
    return this.reviewer?.status();
  }

  /** The user approves an AI proposal. New rules go live in alert mode unless they choose. */
  approveProposal(id: string, mode?: RuleMode): void {
    this.pipeline.approve(id, userOrigin('rules-screen'), mode ? { mode } : {});
    this.recount();
  }

  rejectProposal(id: string, note?: string): void {
    this.pipeline.reject(id, userOrigin('rules-screen'), note);
  }

  private countEvents(from: number, to: number): number {
    const r = this.db
      .prepare('SELECT COUNT(*) AS n FROM events WHERE ts >= ? AND ts <= ?')
      .get(from, to) as { n: number };
    return Number(r.n);
  }

  /** Events the classifier found unusual or suspicious that no rule matched. */
  private *flagged(from: number, to: number): Iterable<FlaggedEvent> {
    const rows = this.db
      .prepare(
        `SELECT body, label FROM events
         WHERE ts >= ? AND ts <= ? AND matched = 0 AND label IS NOT NULL
           AND json_extract(label, '$.label') IN ('unusual', 'suspicious')
         ORDER BY ts DESC LIMIT 2000`,
      )
      .iterate(from, to) as Iterable<{ body: string; label: string }>;
    for (const r of rows) {
      const e = JSON.parse(r.body) as SensorEvent;
      const l = JSON.parse(r.label) as { label: 'unusual' | 'suspicious'; reason?: string };
      const f: FlaggedEvent = { kind: e.kind, subject: flaggedSubject(e), label: l.label };
      if (l.reason) f.reason = l.reason;
      const args = 'process' in e ? e.process?.args : undefined;
      if (args?.length) f.commandLine = args.join(' ');
      yield f;
    }
  }

  /** Call after the rule set changes outside setMode (the editor), so event counts stay right. */
  rulesChanged(): void {
    this.recount();
  }

  /** The inline path for one event. Microseconds of rule work, then storage and alerts. */
  async handle(event: SensorEvent): Promise<void> {
    const detections = this.engine.evaluate(event);
    this.ingest(event, {
      checked: this.checkedByKind.get(event.kind) ?? 0,
      matches: detections.map((d) => ({
        ruleId: d.match.ruleId,
        ruleName: this.engine.getRule(d.match.ruleId)?.name ?? d.match.ruleId,
        mode: d.mode,
      })),
    });
    for (const d of detections) await this.apply(d);
  }

  private async apply(d: Detection): Promise<void> {
    const rule = this.engine.getRule(d.match.ruleId);
    if (!rule) return;
    if (d.alert && (d.mode === 'alert' || d.mode === 'block')) {
      const alert = await this.alerts.raise({
        rule: { ...coreRule(rule), mode: d.mode },
        events: [d.event],
        actions: d.mode === 'block' ? d.execute : d.propose,
        title: d.alert.title,
        summary: d.alert.summary,
        ...(d.alert.subject ? { subject: d.alert.subject } : {}),
      });
      this.store.saveAlertDetection(alert.id, d);
      return;
    }
    // Shadow, or a repeat inside the rule's dedupe window.
    this.store.insertRuleMatch({ ...d.match, mode: d.mode });
    if (d.mode === 'block') {
      // Containment still runs on a repeat; only the alert is deduplicated.
      for (const action of d.execute) {
        await this.alerts.run('rule', action, { ruleId: rule.id, reason: rule.name });
      }
    }
  }

  /**
   * Teach the engine from the user's verdict on an alert: exceptions, the
   * user-blocked list, and demotion of rules that keep being wrong. Returns
   * the Santa rule to add when the user confirmed it as malicious.
   */
  learn(alertId: string, decision: UserDecision): DecisionResult & { suggested?: boolean } {
    const d = this.store.getAlertDetection(alertId) as Detection | undefined;
    if (!d) return {};
    const result = this.feedback.recordDecision(d, decision, userOrigin('alert'));
    // A rule that keeps being wrong is only suggested for a quieter mode; the
    // user approves it in Rules like any other suggested change.
    const suggested = result.suggestDemotion
      ? this.pipeline.suggestDemotion(result.suggestDemotion, [alertId])
      : undefined;
    this.recount();
    return { ...result, suggested: suggested?.ok === true };
  }

  /** Every rule the engine runs, with the mode it actually applies. */
  rules(): Array<{ rule: Rule; mode: RuleMode }> {
    return this.engine.listRules().map(({ effectiveMode, ...r }) => ({
      rule: coreRule(r as DetectionRule),
      mode: effectiveMode,
    }));
  }

  /**
   * The blocking rules the helper can run on its own (fastPathRules), with
   * the user's exceptions, Vigil's own paths and the lists the rules look up.
   * The helper runs them on the sensor stream and hands Santa the ones it can
   * stop before launch; this engine keeps running all of them either way.
   */
  helperRules(): HelperRuleSet {
    const { rules, lists } = fastPathRules(this.engine.listRules());
    return {
      rules,
      exceptions: this.stores.exceptions.all(),
      selfPaths: this.selfPaths,
      lists: Object.fromEntries(lists.map((l) => [l, this.stores.lists.entries(l)])),
    };
  }

  hasRule(id: string): boolean {
    return this.engine.getRule(id) !== undefined;
  }

  /** From the Rules screen, so the actor is the user. */
  setMode(id: string, mode: RuleMode): void {
    this.feedback.setMode(id, mode, userOrigin('rules-screen'));
    this.recount();
  }

  feedStatus(): FeedStatus[] {
    return this.feeds.status();
  }

  /** How many active rules look at each kind of event, for the feed. */
  private recount(): void {
    const counts = new Map<string, number>();
    for (const r of this.engine.listRules()) {
      if (r.effectiveMode === 'disabled') continue;
      for (const k of r.eventKinds) counts.set(k, (counts.get(k) ?? 0) + 1);
    }
    this.checkedByKind = counts;
    this.onRulesChanged?.();
  }
}

/** A detection rule as the core Rule the app stores and shows. */
function coreRule(r: DetectionRule): Rule {
  const { santa: _santa, ...rule } = r as DetectionRule & { santa?: unknown };
  return rule as Rule;
}

const ReviewStateSchema = z
  .object({
    lastRunAt: z.number(),
    lastOkAt: z.number(),
    lastError: z.string(),
    lastSummary: z.string(),
    lastProvider: z.string(),
    lastQueued: z.number(),
    lastRefused: z.number(),
  })
  .partial();

/** What a classifier label is about, in a form the review can group by. */
function flaggedSubject(e: SensorEvent): string {
  const prog = 'process' in e && e.process ? e.process.path : undefined;
  switch (e.kind) {
    case 'network.connection':
      return `${prog ?? 'unknown'} -> ${e.remoteHost ?? e.remoteAddress}`;
    case 'persistence':
    case 'file':
      return e.path;
    default:
      return prog ?? e.kind;
  }
}

function appHistory(store: Store): EventHistory {
  return {
    // core.ingest already stores every event.
    append: () => {},
    range: (from, to) => store.eventsBetween(from, to),
    // The app prunes its own events.
    prune: () => 0,
  };
}
