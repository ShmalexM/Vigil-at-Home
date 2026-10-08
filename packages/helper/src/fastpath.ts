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
// off or changes it, or adds an exception, needs the admin password
// (loosening(), checked by the executor). So does naming anything new as
// Vigil's own (a path, an AppImage, a program hash): the app sends that
// apart from the rules (self.grant, selfLoosening()), so the rules never wait
// on that password. Until that grant is approved, an app running from
// outside the installer's folder is not Vigil's own to these rules, so a rule
// that matches it may act on it like any other program. Indicator lists change every day as
// feeds age entries out, so an entry a list drops keeps blocking for
// RETIRE_MS instead, and a list cannot drop more than RETIRED_MAX entries in
// that time. The saved policy and its revision live in a root-owned file the
// user's account cannot write.

import { readFileSync, renameSync, writeFileSync } from 'node:fs';
import { isRelease, type Action, type SensorEvent } from '@vigil/core';
import { selfKey, selfRoots, underSelfRoot, type SelfImage } from '@vigil/core/self';
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
  type SelfGrant,
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
  /** A file's device and inode (`fileId`), to check an AppImage the app names is that file. */
  fileId?: (path: string) => string | undefined;
  /**
   * Vigil's own folders as the installer put them in place (root-owned).
   * Until the helper takes its first self grant, it may name these without
   * the password.
   */
  installed?: readonly string[];
}

/** What the helper never pauses, kills or blocks, as the app last sent it. */
export interface SelfSet {
  paths: readonly string[];
  /** File ids of approved AppImages. */
  images: readonly string[];
  /** sha256 of the programs inside them. */
  hashes: readonly string[];
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
  selfImages: z.array(z.object({ path: z.string(), id: z.string() })).default([]),
  selfHashes: z.array(z.string()).default([]),
  lists: z.record(z.string(), z.array(z.string())),
  /** Entries lists dropped, by list, with when (ms). Still blocking until RETIRE_MS later. */
  retired: z.record(z.string(), z.record(z.string(), z.number())).default({}),
  /**
   * Whether a self grant was ever taken. Files from before self.grant only
   * ever came from syncs that carried one.
   */
  selfGranted: z.boolean().default(true),
});
type Saved = z.infer<typeof Saved>;

const EMPTY: Saved = {
  rev: 0,
  rules: [],
  exceptions: [],
  selfPaths: [],
  selfImages: [],
  selfHashes: [],
  lists: {},
  retired: {},
  selfGranted: false,
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
  /** Whether the installer's folders may still be named as Vigil without the password. */
  private selfGrace = true;
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
    // A damaged file may have held a self grant: no grace.
    this.selfGrace = parsed.success && !parsed.data.selfGranted;
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
   * it only adds or tightens. Lists are not counted: dropped entries retire
   * instead. This holds whether or not any rule is saved yet: an exception
   * taken while no rule blocks would outlast the rules that follow. A sync
   * from an app before self.grant also carries the self set, which counts as
   * selfLoosening() does.
   *
   * Throws PolicyRefused for an AppImage that isn't the file at its path,
   * before anyone is asked for a password for it.
   */
  loosening(cmd: DetectionSync): string[] {
    const self = carriedSelf(cmd);
    const out = self ? this.selfLoosening(self) : [];
    const next = new Map(cmd.rules.map((r) => [r.id, r]));
    const rules: string[] = [];
    for (const r of this.state.rules) {
      const n = next.get(r.id);
      if (!n) rules.push(`stop blocking with “${r.name}”`);
      else if (enforced(n) !== enforced(r)) rules.push(`change what “${r.name}” blocks`);
    }
    const had = new Set(this.state.exceptions.map(canonical));
    const added = cmd.exceptions.filter((e) => !had.has(canonical(e)));
    if (added.length === 1) rules.push(`add an exception to ${added[0]!.ruleId}`);
    else if (added.length) rules.push(`add ${added.length} exceptions`);
    return [...rules, ...out];
  }

  /**
   * What a self grant would newly name as Vigil's own, in words for the
   * password prompt; empty when it names nothing new. Anything not named
   * before counts, even a file inside a folder already named: being Vigil
   * exempts a program from every block. The one exemption is the installer's
   * own folders (see `installed`), until the helper takes its first self
   * grant; a self path outside them, an AppImage or a program hash still
   * asks.
   *
   * Throws PolicyRefused for an AppImage that isn't the file at its path,
   * before anyone is asked for a password for it.
   */
  selfLoosening(cmd: SelfFields): string[] {
    this.checkImages(cmd.selfImages ?? []);
    const out: string[] = [];
    const paths = new Set(this.state.selfPaths.map((p) => selfKey(p)));
    const installed = this.selfGrace ? selfRoots(this.opts.installed ?? []) : [];
    for (const p of ownPaths(cmd.selfPaths, cmd.selfImages ?? []))
      if (!paths.has(selfKey(p)) && !underSelfRoot(installed, selfKey(p)))
        out.push(`never block ${p}`);
    const images = new Set(this.state.selfImages.map((i) => i.id));
    for (const i of cmd.selfImages ?? []) if (!images.has(i.id)) out.push(`never block ${i.path}`);
    const hashes = new Set(this.state.selfHashes);
    const newHashes = (cmd.selfHashes ?? []).filter((h) => !hashes.has(h)).length;
    if (newHashes) out.push(`never block ${newHashes} of Vigil’s programs by hash`);
    return out;
  }

  /** Replace what is Vigil's own. The executor asks for the password first (selfLoosening()). */
  grantSelf(cmd: SelfFields): { rev: number } {
    this.apply({ ...this.state, rev: this.state.rev + 1, ...this.selfFrom(cmd) });
    this.save();
    return { rev: this.state.rev };
  }

  /**
   * Replace the rules. Returns the lists whose contents the app should send;
   * until they arrive the current contents stay in force.
   */
  sync(cmd: DetectionSync): { needLists: string[]; rev: number } {
    const lists: Saved['lists'] = {};
    for (const name of Object.keys(cmd.lists)) {
      const have = this.state.lists[name];
      if (have) lists[name] = have;
    }
    const retired = this.retire(lists);
    // Only an app from before self.grant sends the self set with the rules.
    const self = carriedSelf(cmd);
    const selfFields = self ? this.selfFrom(self) : {};
    // Throws RuleCompileError before anything changes. That includes a regex or
    // glob that could take too long to match (regexProblem, globProblem): adding
    // rules needs no password, so the same checks as the app's keep one rule
    // from stalling every check here.
    this.apply({
      rev: this.state.rev + 1,
      rules: cmd.rules,
      exceptions: cmd.exceptions,
      selfPaths: this.state.selfPaths,
      selfImages: this.state.selfImages,
      selfHashes: this.state.selfHashes,
      selfGranted: this.state.selfGranted,
      ...selfFields,
      lists,
      retired,
    });
    this.save();
    return {
      needLists: Object.keys(cmd.lists).filter((n) => this.digests.get(n) !== cmd.lists[n]),
      rev: this.state.rev,
    };
  }

  /** One part of a list. The list changes only once every part is in and the digest matches. */
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

  /** What is Vigil's own, as the app last sent it. */
  self(): SelfSet {
    return {
      paths: ownPaths(this.state.selfPaths, this.state.selfImages),
      images: this.state.selfImages.map((i) => i.id),
      hashes: this.state.selfHashes,
    };
  }

  /** The saved fields for a self grant; throws PolicyRefused for an AppImage that isn't its file. */
  private selfFrom(
    cmd: SelfFields,
  ): Pick<Saved, 'selfPaths' | 'selfImages' | 'selfHashes' | 'selfGranted'> {
    const selfImages = cmd.selfImages ?? [];
    this.checkImages(selfImages);
    return {
      selfPaths: ownPaths(cmd.selfPaths, selfImages),
      selfImages,
      selfHashes: cmd.selfHashes ?? [],
      selfGranted: true,
    };
  }

  /**
   * A newly named AppImage must be the file at the path the password prompt
   * showed. One already approved matches by id alone, so it still counts
   * after the image is renamed while Vigil runs.
   */
  private checkImages(images: readonly SelfImage[]): void {
    const known = new Set(this.state.selfImages.map((i) => i.id));
    for (const i of images) {
      if (known.has(i.id)) continue;
      if (!this.opts.fileId || this.opts.fileId(i.path) !== i.id)
        throw new PolicyRefused(`${i.path} is not the AppImage Vigil runs from`);
    }
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
          {
            safety: {
              selfPaths: ownPaths(next.selfPaths, next.selfImages),
              selfHashes: next.selfHashes,
            },
            recordHistory: false,
          },
        )
      : undefined;
    this.engine = engine;
    this.state = next;
    this.digests = new Map(Object.entries(next.lists).map(([n, e]) => [n, listDigest(e)]));
  }

  private save(): void {
    if (this.state.selfGranted) this.selfGrace = false;
    const tmp = `${this.opts.file}.tmp`;
    try {
      writeFileSync(tmp, JSON.stringify(this.state), { mode: 0o600 });
      renameSync(tmp, this.opts.file);
    } catch (err) {
      this.opts.log?.(`fast path: could not save rules: ${(err as Error).message}`);
    }
  }
}

/** A self grant, as self.grant or an older app's detection.sync carries it. */
export type SelfFields = Pick<SelfGrant, 'selfPaths' | 'selfImages' | 'selfHashes'>;

/** The self set a sync carries, if any: only apps from before self.grant send one. */
function carriedSelf(cmd: DetectionSync): SelfFields | undefined {
  if (cmd.selfPaths === undefined && cmd.selfImages === undefined && cmd.selfHashes === undefined)
    return undefined;
  return {
    selfPaths: cmd.selfPaths ?? [],
    ...(cmd.selfImages ? { selfImages: cmd.selfImages } : {}),
    ...(cmd.selfHashes ? { selfHashes: cmd.selfHashes } : {}),
  };
}

/**
 * Self paths without the AppImages' own paths. An image counts by device and
 * inode alone (selfImage.ts): trusting its path too would make whatever file
 * later sits at that path Vigil, after the image is moved or replaced.
 */
function ownPaths(paths: readonly string[], images: readonly SelfImage[]): string[] {
  const named = new Set(images.map((i) => selfKey(i.path)));
  return paths.filter((p) => !named.has(selfKey(p)));
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
