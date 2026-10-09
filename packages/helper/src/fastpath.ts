// Blocking rules run inside the helper, on the sensor stream itself.
//
//   Santa / osquery ─► SensorHub ─► FastPath.check(event) ─► Executor (kill, block...)
//                                        │                      │ journaled, so undo works
//                                        └──── event + what ran ┴─► app (alert, popup)
//
// Before this, every block made two trips over the socket and waited on the
// app's event loop, and nothing was blocked while the app was closed. The app
// still runs every rule; it raises the alert and, for actions the helper
// already ran, records the helper's result instead of running them again.
//
// The rules, exceptions and lists come from the app (detection.sync) and are
// kept on disk, so blocking resumes at boot before anyone logs in. Only
// containment runs here: the helper never releases anything on its own.
//
// Anything running as the user can reach the helper's socket, so a sync may
// not weaken this policy on its own say-so. With the app closed, this policy
// and Santa's pre-launch rules are all that block. A sync that turns a rule
// off or changes it, adds an exception, or adds one of Vigil's own paths
// needs the admin password (loosening(), checked by the executor). Indicator
// lists change every day as feeds age entries out, so an entry a list drops
// keeps blocking for RETIRE_MS instead, and a list cannot drop more than
// RETIRED_MAX entries in that time. The saved policy and its revision live in
// a root-owned file the user's account cannot write.

import { readFileSync, renameSync, writeFileSync } from 'node:fs';
import { isRelease, type Action, type SensorEvent } from '@vigil/core';
import {
  compileRule,
  DetectionEngine,
  DetectionRule,
  memoryStores,
  type RuleException,
  type Stores,
} from '@vigil/detection';
import { listDigest } from '@vigil/detection/fastpath';
import { z } from 'zod';
import type { ActionOutcome } from './executor.js';
import {
  HelperAction,
  RuleExceptionSchema,
  type DetectionListSet,
  type DetectionSync,
} from './protocol.js';

/** An action the helper ran for a rule, sent to the app with the event. */
export interface HelperRan {
  ruleId: string;
  action: Action;
  /** When it finished (ms). */
  at: number;
  outcome?: ActionOutcome;
  error?: string;
}

export interface FastPathOptions {
  /** Where the synced rules are kept between restarts. */
  file: string;
  run: (action: HelperAction) => Promise<ActionOutcome>;
  log?: (msg: string) => void;
  /** For tests. */
  now?: () => number;
  /** For tests: a smaller RETIRED_MAX. */
  retiredMax?: number;
}

/** How long an entry a list drops keeps blocking. */
export const RETIRE_MS = 7 * 24 * 60 * 60 * 1000;
/** Most entries one list may have dropped within RETIRE_MS. */
export const RETIRED_MAX = 100_000;

/** A sync or list the helper won't take from the user's account. */
export class PolicyRefused extends Error {}

const Saved = z.object({
  /** Goes up by one with every change, so the app can show which policy is in force. */
  rev: z.number().int().min(0).default(0),
  rules: z.array(DetectionRule),
  exceptions: z.array(RuleExceptionSchema),
  selfPaths: z.array(z.string()),
  lists: z.record(z.string(), z.array(z.string())),
  /** Entries lists dropped, by list, with when (ms). Still blocking until RETIRE_MS later. */
  retired: z.record(z.string(), z.record(z.string(), z.number())).default({}),
  /** The app's id for the sync in force, so it can tell whether a sync it lost track of went in. */
  syncId: z.string().optional(),
  /** The app's own blocking rules, by fingerprint (DetectionSync.appRules). */
  appRules: z.array(z.object({ id: z.string(), name: z.string(), digest: z.string() })).default([]),
});
type Saved = z.infer<typeof Saved>;

const EMPTY: Saved = {
  rev: 0,
  rules: [],
  exceptions: [],
  selfPaths: [],
  lists: {},
  retired: {},
  appRules: [],
};

/** Rule fields that change what an alert says, not what gets blocked. */
const WORDING = new Set([
  'version',
  'name',
  'description',
  'severity',
  'fidelity',
  'reasons',
  'tags',
  'createdAt',
  'updatedAt',
  'origin',
  'editedFrom',
  'dedupe',
]);

export class FastPath {
  private state: Saved = EMPTY;
  private engine: DetectionEngine | undefined;
  private digests = new Map<string, string>();
  /** Lists arriving in parts: name → digest and the parts so far. */
  private incoming = new Map<string, { digest: string; parts: (string[] | undefined)[] }>();
  private readonly now: () => number;

  constructor(private readonly opts: FastPathOptions) {
    this.now = opts.now ?? Date.now;
  }

  /** Pick up the rules saved by the last sync. A missing or damaged file means none. */
  load(): void {
    let raw: string;
    try {
      raw = readFileSync(this.opts.file, 'utf8');
    } catch {
      return;
    }
    const parsed = Saved.safeParse(safeJson(raw));
    if (!parsed.success) {
      this.opts.log?.('fast path: ignoring saved rules that do not parse');
      return;
    }
    // A rule a newer release no longer compiles (stricter regex and glob
    // checks) is dropped on its own; the rest keep blocking.
    const rules = parsed.data.rules.filter((r) => {
      try {
        compileRule(r);
        return true;
      } catch (err) {
        this.opts.log?.(`fast path: dropping saved rule: ${(err as Error).message}`);
        return false;
      }
    });
    try {
      this.apply({ ...parsed.data, rules });
    } catch (err) {
      this.opts.log?.(`fast path: saved rules did not load: ${(err as Error).message}`);
    }
  }

  /**
   * What this sync would weaken, in words for the password prompt; empty when
   * it only adds. Lists are not counted: dropped entries retire instead.
   */
  loosening(cmd: DetectionSync): string[] {
    // With no rules nothing is blocked yet, so there is nothing to weaken.
    if (this.state.rules.length === 0 && this.state.appRules.length === 0) return [];
    const out: string[] = [];
    // The app's own blocking rules: dropping one or changing what it blocks.
    const nextApp = new Map((cmd.appRules ?? []).map((r) => [r.id, r.digest]));
    for (const r of this.state.appRules) {
      const d = nextApp.get(r.id);
      if (d === undefined) out.push(`stop blocking with “${r.name}”`);
      else if (d !== r.digest) out.push(`change what “${r.name}” blocks`);
    }
    const next = new Map(cmd.rules.map((r) => [r.id, r]));
    for (const r of this.state.rules) {
      const n = next.get(r.id);
      if (!n) out.push(`stop blocking with “${r.name}”`);
      else if (enforced(n) !== enforced(r)) out.push(`change what “${r.name}” blocks`);
    }
    const had = new Set(this.state.exceptions.map(canonical));
    const added = cmd.exceptions.filter((e) => !had.has(canonical(e)));
    if (added.length === 1) out.push(`add an exception to ${added[0]!.ruleId}`);
    else if (added.length) out.push(`add ${added.length} exceptions`);
    const paths = new Set(this.state.selfPaths);
    for (const p of cmd.selfPaths) if (!paths.has(p)) out.push(`never block ${p}`);
    return out;
  }

  /**
   * The lists a sync names whose contents neither it carries nor the helper
   * already has. A sync missing any is not applied (sync() says which), so
   * the app can send it again with them; nothing is held in between.
   */
  missingLists(cmd: DetectionSync): string[] {
    return Object.keys(cmd.lists).filter(
      (n) => cmd.entries?.[n] === undefined && this.digests.get(n) !== cmd.lists[n],
    );
  }

  /**
   * Throws RuleCompileError if a rule doesn't compile. That includes a regex or
   * glob that could take too long to match (regexProblem, globProblem): adding
   * rules needs no password, so the same checks as the app's keep one rule
   * from stalling every check here.
   */
  checkRules(cmd: DetectionSync): void {
    for (const r of cmd.rules) compileRule({ ...r, mode: 'block' });
  }

  /**
   * Replace the rules and the lists they read, in one step: every rule must
   * compile, every list it carries must match its digest, and no list may
   * drop more than it may in a week; then all of it goes in force and is
   * saved, or none of it does. Lists it names but doesn't carry keep their
   * current contents, which must match the named digest; if any doesn't,
   * nothing changes and `needLists` says which to send.
   */
  sync(cmd: DetectionSync): { applied: boolean; needLists: string[]; rev: number } {
    this.checkRules(cmd);
    const needLists = this.missingLists(cmd);
    if (needLists.length) return { applied: false, needLists, rev: this.state.rev };
    const lists: Saved['lists'] = {};
    for (const name of Object.keys(cmd.lists)) {
      const sent = cmd.entries?.[name];
      if (sent !== undefined) {
        if (listDigest(sent) !== cmd.lists[name]) throw new Error(`list ${name} arrived damaged`);
        lists[name] = [...new Set(sent)];
        continue;
      }
      const have = this.state.lists[name];
      if (have) lists[name] = have;
    }
    const retired = this.retire(lists);
    const next: Saved = {
      rev: this.state.rev + 1,
      rules: cmd.rules,
      appRules: cmd.appRules ?? [],
      exceptions: cmd.exceptions,
      selfPaths: cmd.selfPaths,
      lists,
      retired,
    };
    if (cmd.syncId) next.syncId = cmd.syncId;
    this.apply(next);
    this.save();
    return { applied: true, needLists: [], rev: this.state.rev };
  }

  /** The rules in force. */
  rules(): DetectionRule[] {
    return this.state.rules;
  }

  /** Which sync is in force: the app's id for it, if it gave one. */
  syncId(): string | undefined {
    return this.state.syncId;
  }

  /**
   * One part of a list, on its own (a feed refresh). The list changes only
   * once every part is in and the digest matches.
   */
  putList(cmd: DetectionListSet): { complete: boolean } {
    let inc = this.incoming.get(cmd.list);
    if (!inc || inc.digest !== cmd.digest || inc.parts.length !== cmd.parts) {
      inc = { digest: cmd.digest, parts: Array.from({ length: cmd.parts }, () => undefined) };
      // Bounded: anything running as the user can reach the socket.
      if (this.incoming.size >= 8) this.incoming.delete(this.incoming.keys().next().value!);
      this.incoming.set(cmd.list, inc);
    }
    if (cmd.part >= cmd.parts) throw new Error('part is past the last one');
    inc.parts[cmd.part] = cmd.entries;
    if (inc.parts.some((p) => p === undefined)) return { complete: false };
    this.incoming.delete(cmd.list);
    const entries = inc.parts.flat() as string[];
    if (listDigest(entries) !== cmd.digest) throw new Error(`list ${cmd.list} arrived damaged`);
    const lists = { ...this.state.lists, [cmd.list]: entries };
    this.apply({ ...this.state, rev: this.state.rev + 1, lists, retired: this.retire(lists) });
    this.save();
    return { complete: true };
  }

  status(): { rev: number; rules: number; lists: Record<string, number>; retired: number } {
    const lists: Record<string, number> = {};
    for (const [n, e] of Object.entries(this.state.lists)) lists[n] = e.length;
    let retired = 0;
    for (const r of Object.values(this.state.retired)) retired += Object.keys(r).length;
    return { rev: this.state.rev, rules: this.state.rules.length, lists, retired };
  }

  /**
   * Run the rules on one event and carry out what block-mode rules ask for.
   * Never throws: a failed action is reported to the app like any other.
   */
  async check(e: SensorEvent): Promise<HelperRan[]> {
    if (!this.engine) return [];
    let detections;
    try {
      detections = this.engine.evaluate(e as Parameters<DetectionEngine['evaluate']>[0]);
    } catch (err) {
      this.opts.log?.(`fast path: ${(err as Error).message}`);
      return [];
    }
    const ran: HelperRan[] = [];
    for (const d of detections) {
      if (d.mode !== 'block') continue;
      for (const action of d.execute) {
        const parsed = HelperAction.safeParse(action);
        // Containment only. Rules never carry releases, but the helper checks.
        if (!parsed.success || isRelease(action)) continue;
        try {
          const outcome = await this.opts.run(parsed.data);
          ran.push({ ruleId: d.match.ruleId, action, at: Date.now(), outcome });
        } catch (err) {
          ran.push({
            ruleId: d.match.ruleId,
            action,
            at: Date.now(),
            error: (err as Error).message,
          });
        }
      }
    }
    return ran;
  }

  /**
   * The retired entries once the lists become `next`: what they dropped joins,
   * what they have again leaves, and anything older than RETIRE_MS goes.
   */
  private retire(next: Saved['lists']): Saved['retired'] {
    const now = this.now();
    const out: Saved['retired'] = {};
    const names = new Set([...Object.keys(this.state.lists), ...Object.keys(this.state.retired)]);
    for (const name of names) {
      const keep = new Set(next[name] ?? []);
      // No prototype: entries are data and could be "__proto__".
      const r: Record<string, number> = Object.create(null) as Record<string, number>;
      for (const [e, at] of Object.entries(this.state.retired[name] ?? {}))
        if (!keep.has(e) && now - at < RETIRE_MS) r[e] = at;
      for (const e of this.state.lists[name] ?? []) if (!keep.has(e) && !(e in r)) r[e] = now;
      const n = Object.keys(r).length;
      const max = this.opts.retiredMax ?? RETIRED_MAX;
      if (n > max) throw new PolicyRefused(`list ${name} would drop ${n} entries; at most ${max}`);
      if (n) out[name] = r;
    }
    return out;
  }

  private apply(next: Saved): void {
    const stores: Stores = memoryStores();
    for (const name of new Set([...Object.keys(next.lists), ...Object.keys(next.retired)])) {
      const entries = [...(next.lists[name] ?? []), ...Object.keys(next.retired[name] ?? {})];
      stores.lists.replace(name, entries, { source: 'app', updatedAt: 0 });
    }
    for (const ex of next.exceptions) stores.exceptions.add(ex as RuleException);
    const engine = next.rules.length
      ? new DetectionEngine(
          next.rules.map((r) => ({ ...r, mode: 'block' as const })),
          stores,
          { safety: { selfPaths: next.selfPaths }, recordHistory: false },
        )
      : undefined;
    this.engine = engine;
    this.state = next;
    this.digests = new Map(Object.entries(next.lists).map(([n, e]) => [n, listDigest(e)]));
  }

  private save(): void {
    const tmp = `${this.opts.file}.tmp`;
    try {
      writeFileSync(tmp, JSON.stringify(this.state), { mode: 0o600 });
      renameSync(tmp, this.opts.file);
    } catch (err) {
      this.opts.log?.(`fast path: could not save rules: ${(err as Error).message}`);
    }
  }
}

/** A rule as the helper enforces it, without its wording. */
function enforced(rule: DetectionRule): string {
  return canonical(Object.fromEntries(Object.entries(rule).filter(([k]) => !WORDING.has(k))));
}

/** JSON with object keys sorted, so equal values compare equal. */
function canonical(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(canonical).join(',')}]`;
  if (v && typeof v === 'object')
    return `{${Object.keys(v)
      .sort()
      .filter((k) => (v as Record<string, unknown>)[k] !== undefined)
      .map((k) => `${JSON.stringify(k)}:${canonical((v as Record<string, unknown>)[k])}`)
      .join(',')}}`;
  return JSON.stringify(v) ?? 'null';
}

function safeJson(raw: string): unknown {
  try {
    return JSON.parse(raw) as unknown;
  } catch {
    return undefined;
  }
}
