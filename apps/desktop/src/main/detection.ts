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
  BLOCKED_EXCLUSION,
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
  type FeedStatus,
  type FlaggedEvent,
  type Proposal,
  type PsRow,
  type ReviewState,
  type RuleException,
  type SqliteDetectionStores,
  type TrackerOptions,
} from '@vigil/detection';
import { appBlockingRules, fastPathRules, isAppOnlyField } from '@vigil/detection/fastpath';
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

/**
 * What became of a rule change on the helper's copy. `declined`: it loosened
 * the rules and the user cancelled the password. `failed`: the helper refused
 * it for another reason. Either way the change was not made here either.
 * `unavailable`: the helper isn't connected or didn't answer; the change is
 * made here and the helper gets it on the next sync.
 */
export type HelperSyncOutcome = 'applied' | 'declined' | 'failed' | 'unavailable';

/**
 * How to send the helper its rules. `hold`: let the next password dialog ask
 * for it, and call `onHeld` once it waits on that. `byUser`: the user just
 * made this change, so ask even if they declined the same rules before.
 * `set`: send this set instead of the rules in force (a change not yet made
 * here). `settle`: called with the outcome before the next sync starts, so the
 * change lands here before anything else reads the rules. `onError`: the
 * helper's reason when it refuses (`failed`).
 */
export interface HelperSyncOptions {
  hold?: boolean;
  onHeld?: () => void;
  byUser?: boolean;
  set?: HelperRuleSet;
  settle?: (outcome: HelperSyncOutcome) => void;
  onError?: (reason: string) => void;
}

/** A user change and what the helper made of it; `reason` is the helper's, when it refused. */
export interface ChangeResult<T> {
  value: T;
  helper: HelperSyncOutcome;
  reason?: string;
}

/** True when the helper turned a change down, so the app left everything as it was. */
export function notApplied(helper: HelperSyncOutcome): boolean {
  return helper === 'declined' || helper === 'failed';
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
  private readonly selfPaths: string[];
  /** Set by the app: sends the helper its copy after rules, modes or exceptions change. */
  syncHelper: HelperSync | undefined;
  /** User changes one at a time, so one waiting on the password can't mix with another. */
  private changing: Promise<unknown> = Promise.resolve();

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
    return this.acceptProposal(id, mode).then((r) => r.helper);
  }

  /** approveProposal, with the helper's reason when it refused. */
  acceptProposal(id: string, mode?: RuleMode): Promise<ChangeResult<void>> {
    return this.change(
      () => {
        this.pipeline.approve(id, userOrigin('rules-screen'), mode ? { mode } : {});
      },
      {},
      // Again once the password is in: it must still be waiting and still pass.
      () => this.pipeline.commitProblem(id),
    );
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
  preflight(req: PreflightRequest): PreflightResult {
    const ts = this.now();
    const found = req.ppid !== undefined ? this.tracker.lookup(req.ppid) : undefined;
    const event = toolRequestEvent(req, {
      id: newId(ts),
      ts,
      ...(found?.tag ? { tag: found.tag } : {}),
    });
    const detections = this.engine.check(event);
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
      // A program just confirmed malicious: no waiting suggestion may hide it.
      if (decision.verdict === 'malicious') this.pipeline.withdrawAffected();
      // A rule that keeps being wrong is only suggested for a quieter mode; the
      // user approves it in Rules like any other suggested change.
      const suggested = result.suggestDemotion
        ? this.pipeline.suggestDemotion(result.suggestDemotion, [alertId])
        : undefined;
      return { ...result, suggested: suggested?.ok === true };
    }, opts);
    return { ...value, helper };
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
    const exceptions = this.stores.exceptions.all();
    // The helper can't honour an exception on a field only the app fills in
    // (an agent's tag), so it would block what the app lets through.
    const needApp = new Set(
      exceptions
        .filter((x) => Object.keys(x.match).some((f) => isAppOnlyField(f)))
        .map((x) => x.ruleId),
    );
    const all = this.engine.listRules();
    const { rules, lists } = fastPathRules(all.filter((r) => !needApp.has(r.id)));
    return {
      rules,
      appRules: appBlockingRules(
        all,
        rules.map((r) => r.id),
      ),
      exceptions,
      selfPaths: this.selfPaths,
      lists: Object.fromEntries(lists.map((l) => [l, this.stores.lists.entries(l)])),
    };
  }

  hasRule(id: string): boolean {
    return this.engine.getRule(id) !== undefined;
  }

  /**
   * From the Rules screen, so the actor is the user. Turning a blocking rule
   * down needs the password; if the user cancels, the mode stays (`declined`).
   */
  setMode(id: string, mode: RuleMode): Promise<HelperSyncOutcome> {
    return this.changeMode(id, mode).then((r) => r.helper);
  }

  /** setMode, with the helper's reason when it refused. */
  changeMode(id: string, mode: RuleMode): Promise<ChangeResult<void>> {
    return this.change(() => this.feedback.setMode(id, mode, userOrigin('rules-screen')));
  }

  /**
   * A change from the rule editor (save, exclusions, exceptions, revert,
   * delete), made only once the helper takes it.
   */
  userChange<T>(fn: () => T): Promise<ChangeResult<T>> {
    return this.change(fn);
  }

  /**
   * Make a user change only once the helper takes it. The change is worked
   * out, the helper is sent the rules as they would be, and the app goes on
   * running the rules as they were until it answers. A change that loosens
   * the helper's rules, or a blocking rule only the app runs, needs the admin
   * password there; if the user cancels or the helper refuses, nothing
   * changes, so the app never runs a rule as off or excepted while the helper
   * still blocks with it. Changes go one at a time, in order.
   *
   * Once the helper says yes, every check runs again before anything is made
   * (`recheck`, plus the ones every change gets): the threat lists may have
   * changed while the password dialog was open. Only what the change itself
   * touched is then made, so nothing else that happened meanwhile (a
   * suggestion withdrawn, say) is undone.
   */
  private change<T>(
    fn: () => T,
    opts: HelperSyncOptions = {},
    recheck?: () => string | undefined,
  ): Promise<ChangeResult<T>> {
    const run = async (): Promise<ChangeResult<T>> => {
      const before = this.snapshot();
      // A change refused outright (a proposal that no longer passes its checks) throws here.
      const value = fn();
      if (!this.syncHelper) {
        // No helper link at all (tests, or a platform without the helper):
        // the app is the only thing enforcing, so there is nobody to ask.
        this.recount(false);
        return { value, helper: 'unavailable' };
      }
      const after = this.snapshot();
      const set = this.helperRules();
      const hashes = namedHashes(before, after);
      const blockedAtStart = new Set(hashes.filter((h) => this.pipeline.isBlockedHash(h)));
      this.applyDelta(after, before);
      this.recount(false);
      let outcome: HelperSyncOutcome | undefined;
      let reason: string | undefined;
      const settle = (helper: HelperSyncOutcome) => {
        if (outcome) return;
        outcome = helper;
        if (notApplied(helper)) return;
        const problem =
          recheck?.() ??
          this.commitConflict(before, after) ??
          (hashes.some((h) => !blockedAtStart.has(h) && this.pipeline.isBlockedHash(h))
            ? BLOCKED_EXCLUSION
            : undefined);
        if (problem) {
          outcome = 'failed';
          reason = problem;
          // The helper may already have the change: send it the rules in force again.
          void this.syncHelper?.();
          return;
        }
        // `unavailable` is made too: with the helper not installed or not
        // connected (known before anything is sent) there is no password to
        // ask for and the app is what enforces; the helper gets the change
        // when it connects, and asks then.
        this.applyDelta(before, after);
        this.recount(false);
      };
      const helper = await this.syncHelper({
        ...opts,
        byUser: true,
        set,
        settle,
        onError: (r) => (reason = r),
      });
      settle(helper);
      const final = outcome ?? helper;
      return reason === undefined ? { value, helper: final } : { value, helper: final, reason };
    };
    const done = this.changing.then(run);
    this.changing = done.catch(() => undefined);
    return done;
  }

  /** A suggestion the change touched that something else changed while it waited. */
  private commitConflict(before: Snapshot, after: Snapshot): string | undefined {
    const same = (a: unknown, b: unknown) => JSON.stringify(a) === JSON.stringify(b);
    for (const [id, p] of after.proposals) {
      const was = before.proposals.get(id);
      if (same(was, p)) continue;
      if (!same(this.stores.proposals.get(id), was))
        return 'The suggestion changed while waiting for your password.';
    }
    return undefined;
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

  /** Make what changed from `from` to `to`, and only that. */
  private applyDelta(from: Snapshot, to: Snapshot): void {
    const same = (a: unknown, b: unknown) => JSON.stringify(a) === JSON.stringify(b);
    const ids = <V>(a: Map<string, V>, b: Map<string, V>) => new Set([...a.keys(), ...b.keys()]);
    for (const id of ids(from.rules, to.rules)) {
      const r = to.rules.get(id);
      if (same(from.rules.get(id), r)) continue;
      if (r) this.engine.upsertRule(r);
      else this.engine.removeRule(id);
    }
    for (const id of ids(from.modes, to.modes)) {
      const mode = to.modes.get(id);
      if (from.modes.get(id) === mode) continue;
      const st = this.stores.ruleState.get(id);
      const { mode: _m, ...rest } = st ?? { ruleId: id, fired: 0 };
      this.stores.ruleState.put(mode === undefined ? rest : { ...rest, mode });
    }
    const ts = this.now();
    for (const id of ids(from.saved, to.saved)) {
      const r = to.saved.get(id);
      if (same(from.saved.get(id), r)) continue;
      if (r) this.stores.rules.save(r, ts);
      else this.stores.rules.remove(id);
    }
    const had = new Map(from.exceptions.map((e) => [e.id, e]));
    const has = new Map(to.exceptions.map((e) => [e.id, e]));
    for (const id of had.keys()) if (!has.has(id)) this.stores.exceptions.remove(id);
    for (const [id, e] of has) if (!had.has(id)) this.stores.exceptions.add(e);
    for (const [id, p] of to.proposals)
      if (!same(from.proposals.get(id), p)) this.stores.proposals.put(p);
  }

  /**
   * Fetch the threat feeds that are due. Suggested rule changes that would
   * now hide a program a feed lists as bad are withdrawn.
   */
  async refreshFeeds(opts: { force?: boolean } = {}): ReturnType<FeedImporter['run']> {
    const results = await this.feeds.run(opts);
    this.pipeline.withdrawAffected();
    return results;
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

/**
 * The program hashes a change newly names in an exclusion or exception, so
 * the change can be refused if one is blocked while it waits for the password.
 */
function namedHashes(before: Snapshot, after: Snapshot): string[] {
  const out = new Set<string>();
  const walk = (v: unknown): void => {
    if (Array.isArray(v)) return v.forEach(walk);
    if (!v || typeof v !== 'object') return;
    const o = v as Record<string, unknown>;
    if (o.field === 'process.sha256')
      for (const x of Array.isArray(o.value) ? o.value : [o.value])
        if (typeof x === 'string') out.add(x.toLowerCase());
    Object.values(o).forEach(walk);
  };
  for (const [id, r] of after.rules) {
    const old = new Set((before.rules.get(id)?.exclusions ?? []).map((x) => JSON.stringify(x)));
    walk(r.exclusions.filter((x) => !old.has(JSON.stringify(x))));
  }
  const had = new Set(before.exceptions.map((e) => e.id));
  for (const e of after.exceptions) {
    if (had.has(e.id)) continue;
    const h = (e.match as Record<string, unknown>)['process.sha256'];
    if (typeof h === 'string') out.add(h.toLowerCase());
  }
  return [...out];
}
