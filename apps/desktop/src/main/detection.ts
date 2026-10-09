import { randomUUID } from 'node:crypto';
import type { DatabaseSync } from 'node:sqlite';
import { z } from 'zod';
import {
  newId,
  type AgentTag,
  type AgentToolRequestEvent,
  type PreflightReply,
  type PreflightRequest,
  type Rule,
  type RuleMode,
  type SensorEvent,
  type UserDecision,
} from '@vigil/core';
import {
  AgentRegistry,
  AgentTracker,
  DEFAULT_FEEDS,
  DetectionEngine,
  FeedImporter,
  Feedback,
  RuleEditor,
  RulePipeline,
  RuleReviewer,
  builtinRulesFor,
  compileRule,
  decide,
  mergeRules,
  sqliteStores,
  toolRequestEvent,
  type DecisionResult,
  type Detection,
  type DetectionRule,
  type EventHistory,
  type FeedImporterOptions,
  type AnalyzeRunner,
  type CheckOptions,
  type FeedStatus,
  type FlaggedEvent,
  type Proposal,
  type PsRow,
  type ReviewState,
  type RuleException,
  type SqliteDetectionStores,
  type TrackerOptions,
} from '@vigil/detection';
import { fastPathRules, isAppOnlyField } from '@vigil/detection/fastpath';
import { userOrigin } from '@vigil/detection/user';
import type { EventOutcome } from '../shared/ipc.js';
import type { AlertService } from './alerts.js';
import type { EventBodyRow, Store } from './db/store.js';
import type { HelperRuleSet } from './helper.js';
import type { HelperSelf } from './self-path.js';

const KEY_REVIEW = 'detection.review';

const DAY = 24 * 60 * 60 * 1000;
/** "First seen" rules only record for this long after install: everything is new at first. */
export const LEARNING_DAYS = 7;
/** How often to check whether a threat feed is due. Each feed has its own interval. */
export const FEED_CHECK_MS = 30 * 60 * 1000;

/**
 * What became of a rule change on the helper's copy. `declined`: it loosened
 * the rules, the user cancelled the password, and the change was undone here
 * too. `unavailable`: the helper isn't connected or failed; it gets the change
 * on the next sync.
 */
export type HelperSyncOutcome = 'applied' | 'declined' | 'unavailable';

/** A checked mode change: done (with the override it replaced) or refused in this mode. */
export type QuietOutcome =
  { ok: true; prior: RuleMode | null; token: string } | { ok: false; mode: RuleMode };
export type UndoQuietOutcome = { ok: true } | { ok: false; mode: RuleMode };

/**
 * How to send the helper its rules. `hold`: let the next password dialog ask
 * for it, and call `onHeld` once it waits on that. `byUser`: the user just
 * made this change, so ask even if they declined the same rules before.
 */
export interface HelperSyncOptions {
  hold?: boolean;
  onHeld?: () => void;
  byUser?: boolean;
}

/** Sends the helper the current rules. */
export type HelperSync = (opts?: HelperSyncOptions) => Promise<HelperSyncOutcome>;

/** Everything a user change can touch that the helper's copy follows. */
interface Snapshot {
  rules: Map<string, DetectionRule>;
  modes: Map<string, RuleMode | undefined>;
  saved: Map<string, DetectionRule>;
  exceptions: RuleException[];
  proposals: Map<string, Proposal>;
}

export interface DetectorOptions {
  /** When Vigil was first installed on this Mac. */
  installedAt: number;
  /** Vigil's own executable, which the safety floor never touches. */
  selfPaths: string[];
  /** What the helper is told instead, when it differs (an AppImage's mount changes every launch). */
  helperSelf?: HelperSelf;
  feeds?: FeedImporterOptions;
  now?: () => number;
  /** Vigil's own pid: its process tree is tagged `vigil-self` (its AI helpers). */
  selfPid?: number;
  /** What the agent service hears from the process tracker. */
  agentHooks?: Pick<TrackerOptions, 'onSession' | 'onMiss' | 'onCandidate'>;
  /** Which built-in rule pack to load; defaults to this machine's platform. */
  platform?: string;
}

/** What the pre-flight hook gets back, and what is recorded after it has its answer. */
export interface PreflightResult {
  reply: PreflightReply;
  event: AgentToolRequestEvent;
  detections: Detection[];
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
  /** The watched AI agents: the catalogue merged with the user's own. Changes need a UserOrigin. */
  readonly registry: AgentRegistry;
  /** Which processes run under a watched agent; tags events before rules see them. */
  readonly tracker: AgentTracker;
  private reviewer: RuleReviewer | undefined;
  private checkedByKind = new Map<string, number>();
  private readonly now: () => number;
  /** What is Vigil's own, as the helper's safety floor sees it. */
  private readonly helperSelf: HelperSelf;
  /** Set by the app: sends the helper its copy after rules, modes or exceptions change. */
  syncHelper: HelperSync | undefined;
  /** User changes one at a time, so undoing a declined one can't undo another. */
  private changing: Promise<unknown> = Promise.resolve();
  private waiting = 0;
  /** The last quiet of each rule: what undoing it puts back, and the state it left. */
  private readonly quieted = new Map<
    string,
    { token: string; stamp: string; prior: RuleMode | null }
  >();

  constructor(
    private readonly db: DatabaseSync,
    private readonly store: Store,
    private readonly alerts: AlertService,
    private readonly ingest: (e: SensorEvent, outcome: EventOutcome) => void,
    opts: DetectorOptions,
  ) {
    this.now = opts.now ?? Date.now;
    this.helperSelf = opts.helperSelf ?? { paths: opts.selfPaths, images: [], hashes: [] };
    // Detection keeps its state in det_* tables in the same database. Replay
    // history reads the app's own event table rather than keeping a second copy.
    this.stores = { ...sqliteStores(db), history: appHistory(store) };
    this.registry = new AgentRegistry(this.stores.agents);
    this.tracker = new AgentTracker({
      matcher: () => this.registry.matcher(),
      ...(opts.selfPid ? { self: { pid: opts.selfPid, path: process.execPath } } : {}),
      ...opts.agentHooks,
    });
    // An agent added, edited or switched off changes the tags of what is running now.
    this.registry.onChange(() => this.tracker.retag());
    const builtins = builtinRulesFor(opts.platform ?? process.platform);
    // A saved rule that no longer compiles (a newer release checks regexes and
    // globs more strictly) is left out, rather than keeping every rule from loading.
    const saved = this.stores.rules.list().filter((r) => {
      try {
        compileRule(r);
        return true;
      } catch {
        return false;
      }
    });
    this.engine = new DetectionEngine(mergeRules(builtins, saved), this.stores, {
      learningUntil: opts.installedAt + LEARNING_DAYS * DAY,
      safety: { selfPaths: opts.selfPaths },
      recordHistory: false,
    });
    this.feedback = new Feedback(this.engine, undefined, this.now);
    this.feeds = new FeedImporter(DEFAULT_FEEDS, this.stores.lists, this.stores.feeds, {
      now: this.now,
      ...opts.feeds,
    });
    this.editor = new RuleEditor(this.engine, builtins, this.stores.rules, this.stores.history, {
      now: this.now,
    });
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

  /**
   * The user approves an AI proposal. New rules go live in alert mode unless
   * they choose. If it loosens a blocking rule and the user cancels the
   * password, nothing changes (`declined`).
   */
  approveProposal(id: string, mode?: RuleMode): Promise<HelperSyncOutcome> {
    return this.change(() => {
      this.pipeline.approve(id, userOrigin('rules-screen'), mode ? { mode } : {});
    }).then((r) => r.helper);
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
        `SELECT body, args, label FROM events
         WHERE ts >= ? AND ts <= ? AND matched = 0 AND label IS NOT NULL
           AND json_extract(label, '$.label') IN ('unusual', 'suspicious')
         ORDER BY ts DESC LIMIT 2000`,
      )
      .iterate(from, to) as Iterable<EventBodyRow & { label: string }>;
    for (const r of rows) {
      const e = this.store.event(r);
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

  /**
   * The inline path for one event. The tracker tags it with its agent first,
   * so rules see `process.agent`; then microseconds of rule work, then
   * storage and alerts.
   */
  async handle(event: SensorEvent): Promise<void> {
    const tagged = this.tracker.observe(event);
    const detections = this.engine.evaluate(tagged);
    this.ingest(tagged, this.outcome(tagged.kind, detections));
    for (const d of detections) await this.apply(d);
  }

  /**
   * An agent's hook asks about one tool call. Synchronous and side-effect
   * free: the tracker only says which agent session asked (attribution), and
   * `engine.check` leaves no trace. Rules decide deny, ask or nothing; never allow.
   */
  preflight(req: PreflightRequest, opts?: CheckOptions): PreflightResult {
    const ts = this.now();
    const found = req.ppid !== undefined ? this.tracker.lookup(req.ppid) : undefined;
    const event = toolRequestEvent(req, {
      id: newId(ts),
      ts,
      ...(found?.tag ? { tag: found.tag } : {}),
    });
    const detections = this.engine.check(event, opts);
    const reply = decide(detections, (id) => this.engine.getRule(id)?.name ?? id);
    return { reply, event, detections };
  }

  /** The agent session a running process belongs to, if the tracker knows it. */
  agentOf(pid: number): AgentTag | undefined {
    return this.tracker.lookup(pid)?.tag;
  }

  /**
   * Store a tool request after its answer went out, with a rule match per
   * detection. Nothing runs: tool-request rules have no actions, and this
   * never goes through `apply`. `alerted` are rules whose match an alert
   * already recorded (the agent service raises those itself).
   */
  recordToolRequest(
    event: AgentToolRequestEvent,
    detections: Detection[],
    alerted: ReadonlySet<string> = new Set(),
  ): void {
    this.ingest(event, this.outcome(event.kind, detections));
    for (const d of detections) {
      if (!alerted.has(d.match.ruleId)) this.store.insertRuleMatch({ ...d.match, mode: d.mode });
    }
  }

  /** Take before reading `ps`, and pass to seedProcesses: launches seen meanwhile are newer. */
  processMark(): number {
    return this.tracker.mark();
  }

  /** Processes `ps` listed (those running before Vigil, or missed): the tracker learns them. */
  seedProcesses(rows: PsRow[], since?: number): void {
    this.tracker.seed(rows, since);
  }

  private outcome(kind: SensorEvent['kind'], detections: Detection[]): EventOutcome {
    return {
      checked: this.checkedByKind.get(kind) ?? 0,
      matches: detections.map((d) => ({
        ruleId: d.match.ruleId,
        ruleName: this.engine.getRule(d.match.ruleId)?.name ?? d.match.ruleId,
        mode: d.mode,
      })),
    };
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
      // A folded repeat keeps the first detection here; its own events and match are stored.
      if (alert.repeats?.count !== undefined && alert.repeats.count > 1) return;
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
  async learn(
    alertId: string,
    decision: UserDecision,
    opts: Omit<HelperSyncOptions, 'byUser'> = {},
  ): Promise<DecisionResult & { suggested?: boolean; helper?: HelperSyncOutcome }> {
    const d = this.store.getAlertDetection(alertId) as Detection | undefined;
    if (!d) return {};
    const { value, helper } = await this.change(() => {
      const result = this.feedback.recordDecision(d, decision, userOrigin('alert'));
      // A rule that keeps being wrong is only suggested for a quieter mode; the
      // user approves it in Rules like any other suggested change.
      const suggested = result.suggestDemotion
        ? this.pipeline.suggestDemotion(result.suggestDemotion, [alertId])
        : undefined;
      return { ...result, suggested: suggested?.ok === true };
    }, opts);
    return { ...value, helper };
  }

  /** One rule the engine runs, with the mode it actually applies (the user's choice included). */
  rule(id: string): Rule | undefined {
    const r = this.engine.getRule(id);
    return r ? { ...coreRule(r), mode: this.engine.modeOf(r) } : undefined;
  }

  /** Every rule the engine runs, with the mode it actually applies. */
  rules(): Array<{ rule: Rule; mode: RuleMode; learningUntil?: number }> {
    const now = this.now();
    return this.engine.listRules().map(({ effectiveMode, ...r }) => {
      const learningUntil = this.engine.learningEnds(r.id, now);
      return {
        rule: coreRule(r as DetectionRule),
        mode: effectiveMode,
        ...(learningUntil !== undefined ? { learningUntil } : {}),
      };
    });
  }

  /**
   * The blocking rules the helper can run on its own (fastPathRules), with
   * the user's exceptions, Vigil's own paths and the lists the rules look up.
   * The helper runs them on the sensor stream and hands Santa the ones it can
   * stop before launch; this engine keeps running all of them either way.
   */
  helperRules(): HelperRuleSet {
    const exceptions = this.stores.exceptions.all();
    // The helper can't honour an exception on a field only the app fills in
    // (an agent's tag), so it would block what the app lets through.
    const needApp = new Set(
      exceptions
        .filter((x) => Object.keys(x.match).some((f) => isAppOnlyField(f)))
        .map((x) => x.ruleId),
    );
    const { rules, lists } = fastPathRules(
      this.engine.listRules().filter((r) => !needApp.has(r.id)),
    );
    return {
      rules,
      exceptions,
      selfPaths: this.helperSelf.paths,
      selfImages: this.helperSelf.images,
      selfHashes: this.helperSelf.hashes,
      lists: Object.fromEntries(lists.map((l) => [l, this.stores.lists.entries(l)])),
    };
  }

  /**
   * The sha256 of the programs inside Vigil's AppImage, hashed after
   * start-up: no rule here or in the helper may block one of them.
   */
  setSelfHashes(hashes: readonly string[]): void {
    this.helperSelf.hashes = [...hashes];
    this.engine.setSelfHashes(hashes);
  }

  hasRule(id: string): boolean {
    return this.engine.getRule(id) !== undefined;
  }

  /**
   * From the Rules screen, so the actor is the user. Turning a blocking rule
   * down needs the password; if the user cancels, the mode stays (`declined`).
   */
  setMode(id: string, mode: RuleMode): Promise<HelperSyncOutcome> {
    return this.change(() => this.feedback.setMode(id, mode, userOrigin('rules-screen'))).then(
      (r) => r.helper,
    );
  }

  /**
   * "Only log this rule" from an alert: Alert to Shadow, checked against the
   * mode in force when the change applies (after any change still waiting on
   * the password), not the one the screen showed. Any other mode is refused
   * unchanged, so this never turns a blocking rule down. On success it gives
   * the override the rule had before (null: none) and a token for `undoQuiet`,
   * which keeps that override here rather than taking it back from the screen.
   */
  async quiet(id: string): Promise<{ value: QuietOutcome; helper: HelperSyncOutcome }> {
    return this.change((): QuietOutcome => {
      const rule = this.engine.getRule(id);
      if (!rule) throw new Error(`No rule ${id}`);
      const mode = this.engine.modeOf(rule);
      if (mode !== 'alert') return { ok: false, mode };
      const prior = this.engine.modeOverride(id) ?? null;
      this.feedback.setMode(id, 'shadow', userOrigin('alert'));
      // Bound to this rule and this one quiet, so it undoes nothing else.
      const token = `${id}:${randomUUID()}`;
      this.quieted.set(id, { token, stamp: this.stamp(id), prior });
      return { ok: true, prior, token };
    });
  }

  /**
   * Undo `quiet`: put back exactly the override it replaced, or none. Only
   * while nothing about the rule has changed since, not even a change and
   * back or a new version: otherwise refused, so it can't overwrite (or
   * weaken) a newer choice.
   */
  async undoQuiet(
    id: string,
    token: string,
  ): Promise<{ value: UndoQuietOutcome; helper: HelperSyncOutcome }> {
    return this.change((): UndoQuietOutcome => {
      const rule = this.engine.getRule(id);
      if (!rule) throw new Error(`No rule ${id}`);
      const done = this.quieted.get(id);
      if (!done || done.token !== token || done.stamp !== this.stamp(id)) {
        return { ok: false, mode: this.engine.modeOf(rule) };
      }
      this.quieted.delete(id);
      if (done.prior === null) this.feedback.clearMode(id, userOrigin('alert'));
      else this.feedback.setMode(id, done.prior, userOrigin('alert'));
      return { ok: true };
    });
  }

  /** Which state of a rule a quiet left: its revision in the engine and its version. */
  private stamp(id: string): string {
    return `${this.engine.revision(id)}:${this.engine.getRule(id)?.version ?? 'gone'}`;
  }

  /**
   * Make a user change, then wait for the helper to take it. A change that
   * loosens the helper's rules needs the admin password there; if the user
   * cancels, everything the change touched goes back, so the app never shows
   * a rule as off or excepted while the helper still blocks with it.
   */
  private change<T>(
    fn: () => T,
    opts: HelperSyncOptions = {},
  ): Promise<{ value: T; helper: HelperSyncOutcome }> {
    // Applied at once, so the screens show it straight away, unless an earlier
    // change still waits on the password: then after it, so undoing one can
    // never undo the other.
    const apply = () => {
      const before = this.snapshot();
      const value = fn();
      this.recount(false);
      return { before, value };
    };
    const settle = async ({ before, value }: { before: Snapshot; value: T }) => {
      const helper = this.syncHelper
        ? await this.syncHelper({ ...opts, byUser: true })
        : ('unavailable' as const);
      if (helper === 'declined') {
        this.restore(before);
        this.recount(false);
      }
      return { value, helper };
    };
    let next: Promise<{ value: T; helper: HelperSyncOutcome }>;
    if (this.waiting === 0) {
      next = settle(apply());
    } else {
      next = this.changing.then(() => settle(apply()));
    }
    this.waiting++;
    const done = next.finally(() => this.waiting--);
    this.changing = done.catch(() => undefined);
    return done;
  }

  private snapshot(): Snapshot {
    const rules = new Map(this.engine.allRules().map((r) => [r.id, structuredClone(r)]));
    return {
      rules,
      modes: new Map([...rules.keys()].map((id) => [id, this.stores.ruleState.get(id)?.mode])),
      saved: new Map(this.stores.rules.list().map((r) => [r.id, structuredClone(r)])),
      exceptions: this.stores.exceptions.all().map((e) => structuredClone(e)),
      proposals: new Map(this.stores.proposals.list().map((p) => [p.id, structuredClone(p)])),
    };
  }

  private restore(s: Snapshot): void {
    const same = (a: unknown, b: unknown) => JSON.stringify(a) === JSON.stringify(b);
    for (const r of this.engine.allRules()) if (!s.rules.has(r.id)) this.engine.removeRule(r.id);
    for (const [id, r] of s.rules) if (!same(this.engine.getRule(id), r)) this.engine.upsertRule(r);
    // Through the engine, so its revision counts the rollback as a change.
    for (const [id, mode] of s.modes) {
      if (this.stores.ruleState.get(id)?.mode === mode) continue;
      if (mode === undefined) this.engine._clearMode(id);
      else this.engine._setMode(id, mode);
    }
    const ts = this.now();
    const saved = new Map(this.stores.rules.list().map((r) => [r.id, r]));
    for (const id of saved.keys()) if (!s.saved.has(id)) this.stores.rules.remove(id);
    for (const [id, r] of s.saved) if (!same(saved.get(id), r)) this.stores.rules.save(r, ts);
    const had = new Set(s.exceptions.map((e) => e.id));
    for (const e of this.stores.exceptions.all())
      if (!had.has(e.id)) this.stores.exceptions.remove(e.id);
    const now = new Set(this.stores.exceptions.all().map((e) => e.id));
    for (const e of s.exceptions) if (!now.has(e.id)) this.stores.exceptions.add(e);
    for (const [, p] of s.proposals)
      if (!same(this.stores.proposals.get(p.id), p)) this.stores.proposals.put(p);
  }

  feedStatus(): FeedStatus[] {
    return this.feeds.status();
  }

  /** How many active rules look at each kind of event, for the feed. Then the helper's copy follows. */
  private recount(sync = true): void {
    const counts = new Map<string, number>();
    for (const r of this.engine.listRules()) {
      if (r.effectiveMode === 'disabled') continue;
      for (const k of r.eventKinds) counts.set(k, (counts.get(k) ?? 0) + 1);
    }
    this.checkedByKind = counts;
    if (sync) void this.syncHelper?.();
  }
}

/** A detection rule as the core Rule the app stores and shows. */
export function coreRule(r: DetectionRule): Rule {
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
