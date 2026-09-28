import type { DatabaseSync } from 'node:sqlite';
import type { Rule, RuleMode, SensorEvent, UserDecision } from '@vigil/core';
import {
  DEFAULT_FEEDS,
  DetectionEngine,
  FeedImporter,
  Feedback,
  RuleEditor,
  macosCoreRules,
  mergeRules,
  sqliteStores,
  type Detection,
  type DetectionRule,
  type EventHistory,
  type FeedImporterOptions,
  type FeedStatus,
  type SqliteDetectionStores,
} from '@vigil/detection';
import { userOrigin } from '@vigil/detection/user';
import type { EventOutcome } from '../shared/ipc.js';
import type { AlertService } from './alerts.js';
import type { Store } from './db/store.js';

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
  private checkedByKind = new Map<string, number>();
  private readonly now: () => number;

  constructor(
    db: DatabaseSync,
    private readonly store: Store,
    private readonly alerts: AlertService,
    private readonly ingest: (e: SensorEvent, outcome: EventOutcome) => void,
    opts: DetectorOptions,
  ) {
    this.now = opts.now ?? Date.now;
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
    this.recount();
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
  learn(alertId: string, decision: UserDecision) {
    const d = this.store.getAlertDetection(alertId) as Detection | undefined;
    if (!d) return {};
    const result = this.feedback.recordDecision(d, decision, userOrigin('alert'));
    this.recount();
    return result;
  }

  /** Every rule the engine runs, with the mode it actually applies. */
  rules(): Array<{ rule: Rule; mode: RuleMode }> {
    return this.engine.listRules().map(({ effectiveMode, ...r }) => ({
      rule: coreRule(r as DetectionRule),
      mode: effectiveMode,
    }));
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
  }
}

/** A detection rule as the core Rule the app stores and shows. */
function coreRule(r: DetectionRule): Rule {
  const { santa: _santa, ...rule } = r as DetectionRule & { santa?: unknown };
  return rule as Rule;
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
