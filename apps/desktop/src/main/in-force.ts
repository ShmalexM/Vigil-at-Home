import { createHash } from 'node:crypto';
import { readdir, readFile, stat } from 'node:fs/promises';
import { join } from 'node:path';
import { undoOf, type Action, type ActionRecord } from '@vigil/core';
import { RETIRE_MS, type JournalEntry } from '@vigil/helper';
import {
  LONG_IN_FORCE_DAYS,
  type InForceCheck,
  type InForceFlag,
  type InForceItem,
  type InForceKind,
  type InForceReleaseResult,
  type InForceView,
} from '../shared/in-force.js';
import type { HelperInForce } from './helper.js';
import type { VigilCore } from './service.js';

const DAY = 24 * 60 * 60 * 1000;
export const LONG_IN_FORCE_MS = LONG_IN_FORCE_DAYS * DAY;

/** Folders whose programs are part of the system: blocking one can break the computer. */
const SYSTEM_DIRS = ['/bin/', '/sbin/', '/usr/bin/', '/usr/sbin/', '/usr/libexec/', '/System/'];
/** Paths only Vigil's own tests use. Anything aimed there is left over from a test run. */
const TEST_PATHS = [/^(\/private)?\/tmp\/vigil-e2e/, /^(\/private)?\/tmp\/vigil-helper-test/];

export function isSystemPath(path: string): boolean {
  return SYSTEM_DIRS.some((d) => path.startsWith(d));
}

export function isTestPath(path: string): boolean {
  return TEST_PATHS.some((re) => re.test(path));
}

/** A program as the app saw it: where it ran from, and whether Apple signed it as part of macOS. */
export interface KnownProgram {
  path?: string;
  apple?: boolean;
}

export interface InForceInput {
  /** What the helper reports, or null while it isn't connected. */
  helper: HelperInForce | null;
  /** The app's action log, status done only. */
  done: readonly ActionRecord[];
  /** The user's block lists as the app has them. */
  appUserBlocks: readonly { list: string; entry: string }[];
  alertTitle: (id: string) => string | undefined;
  ruleName: (id: string) => string | undefined;
  /** What the app knows of a program by its sha256 (lower case). */
  program: (sha256: string) => KnownProgram | undefined;
  now: number;
}

/** Which app action a helper journal entry carried out: same kind, same target. */
function targetKey(a: Action): string | undefined {
  switch (a.kind) {
    case 'process.suspend':
      return `${a.kind}:${a.pid}`;
    case 'network.block':
      return `${a.kind}:${a.address}:${a.port ?? ''}`;
    case 'file.quarantine':
    case 'persistence.disable':
      return `${a.kind}:${a.path}`;
    case 'santa.rule.set':
      return `${a.kind}:${a.ruleType}:${a.identifier.toLowerCase()}`;
    default:
      return undefined;
  }
}

/** Every path a journal entry names: what was asked, and what the helper resolved it to. */
function pathsOf(e: JournalEntry): string[] {
  const out: string[] = [];
  const c = e.command as Action;
  if ('path' in c && typeof c.path === 'string') out.push(c.path);
  const u = e.undo as
    | {
        process?: { path?: string };
        quarantine?: { originalPath?: string };
        persistence?: { quarantine?: { originalPath?: string } };
      }
    | undefined;
  for (const p of [
    u?.process?.path,
    u?.quarantine?.originalPath,
    u?.persistence?.quarantine?.originalPath,
  ])
    if (p) out.push(p);
  return out;
}

const KIND: Partial<Record<Action['kind'], InForceKind>> = {
  'process.suspend': 'paused',
  'network.block': 'network',
  'file.quarantine': 'quarantine',
  'santa.rule.set': 'program',
  'persistence.disable': 'startup',
};

function shortHash(sha: string): string {
  return `${sha.slice(0, 12)}…`;
}

/** The program a hash names, in words: its path when known. */
function programWords(sha: string, known: KnownProgram | undefined): string {
  return known?.path ?? `the program with hash ${shortHash(sha)}`;
}

function describe(
  e: JournalEntry,
  program: InForceInput['program'],
): Pick<InForceItem, 'title' | 'detail'> {
  const c = e.command as Action;
  switch (c.kind) {
    case 'process.suspend': {
      const path = (e.undo?.process as { path?: string } | undefined)?.path ?? c.path;
      return { title: `Paused ${path ?? 'a process'}`, detail: `Process ${c.pid}` };
    }
    case 'network.block':
      return {
        title: `Blocks connections to ${c.address}`,
        ...(c.port !== undefined ? { detail: `Port ${c.port}` } : {}),
      };
    case 'file.quarantine':
      return { title: `Moved ${c.path} to quarantine` };
    case 'persistence.disable':
      return { title: `Turned off the startup item ${c.path}` };
    case 'santa.rule.set': {
      const verb = c.policy === 'allow' ? 'Always allows' : 'Blocks';
      if (c.ruleType === 'binary') {
        const sha = c.identifier.toLowerCase();
        return { title: `${verb} ${programWords(sha, program(sha))}`, detail: sha };
      }
      return { title: `${verb} programs with ${c.ruleType} ${c.identifier}` };
    }
    default:
      return { title: e.summary };
  }
}

/** Whether a Santa rule or block-list entry stops a program that is part of the system. */
function blocksSystem(c: Action, program: InForceInput['program']): boolean {
  if (c.kind !== 'santa.rule.set' || c.policy === 'allow') return false;
  if (c.ruleType === 'signingid' && c.identifier.startsWith('platform:')) return true;
  if (c.ruleType !== 'binary') return false;
  return programIsSystem(program(c.identifier.toLowerCase()));
}

function programIsSystem(p: KnownProgram | undefined): boolean {
  return !!p && (p.apple === true || (p.path !== undefined && isSystemPath(p.path)));
}

function flagsFor(
  item: Pick<InForceItem, 'since' | 'cause' | 'until'>,
  opts: { system: boolean; test: boolean; deliberate: boolean },
  now: number,
): InForceFlag[] {
  const out: InForceFlag[] = [];
  if (opts.system) out.push('apple-program');
  if (opts.test) out.push('test-leftover');
  const old = item.since !== undefined && now - item.since > LONG_IN_FORCE_MS;
  if (old && !opts.deliberate && item.until === undefined) out.push('long-running');
  return out;
}

/**
 * Everything Vigil enforces now, from the helper's journal and block lists
 * matched to the app's own action log for the alert or rule behind each.
 * Without the helper the app's log stands in, marked by the caller as
 * possibly out of date.
 */
export function buildInForce(input: InForceInput): InForceItem[] {
  const { helper, now, program } = input;
  const byTarget = new Map<string, ActionRecord>();
  const byQuarantine = new Map<string, ActionRecord>();
  // Oldest first, so the latest record for a target wins.
  for (const r of input.done) {
    const k = targetKey(r.action);
    if (k) byTarget.set(k, r);
    if (r.result?.quarantineId) byQuarantine.set(r.result.quarantineId, r);
  }
  const causeOf = (r: ActionRecord | undefined): InForceItem['cause'] | undefined => {
    if (!r) return undefined;
    const alertTitle = r.alertId ? input.alertTitle(r.alertId) : undefined;
    const ruleName = r.ruleId ? input.ruleName(r.ruleId) : undefined;
    return {
      ...(r.alertId ? { alertId: r.alertId } : {}),
      ...(alertTitle ? { alertTitle } : {}),
      ...(r.ruleId ? { ruleId: r.ruleId } : {}),
      ...(ruleName ? { ruleName } : {}),
      ...(r.actor === 'user' ? { byYou: true } : {}),
    };
  };

  const items: InForceItem[] = [];
  const userBlocks: readonly { list: string; entry: string; retiredAt?: number }[] =
    helper?.userBlocks ?? input.appUserBlocks;
  const blockedHashes = new Set(userBlocks.map((b) => b.entry.toLowerCase()));

  // The user's block list. A Santa rule on the same program folds in: the
  // fast path would only set it again while the list entry stands.
  const santaFor = (sha: string) =>
    (helper?.journal ?? []).filter((e) => {
      const c = e.command as Action;
      return (
        c.kind === 'santa.rule.set' &&
        c.ruleType === 'binary' &&
        c.policy !== 'allow' &&
        c.identifier.toLowerCase() === sha
      );
    });
  for (const b of userBlocks) {
    const sha = b.entry.toLowerCase();
    const santa = santaFor(sha);
    const record = santa
      .map((e) => byTarget.get(targetKey(e.command as Action)!))
      .find((r) => r !== undefined);
    const until = b.retiredAt !== undefined ? b.retiredAt + RETIRE_MS : undefined;
    const since = santa.length ? Math.min(...santa.map((e) => e.createdAt)) : record?.requestedAt;
    const known = program(sha);
    const cause = causeOf(record) ?? { byYou: true };
    const item: InForceItem = {
      key: `u:${b.list}:${sha}`,
      kind: 'block-list',
      title: `${until ? 'Still blocks' : 'Blocks'} ${programWords(sha, known)}`,
      detail: sha,
      ...(since !== undefined ? { since } : {}),
      ...(until !== undefined ? { until } : {}),
      cause: { ...cause, byYou: true },
      release: 'release',
      flags: [],
    };
    item.flags = flagsFor(
      item,
      {
        system: programIsSystem(known),
        test: !!known?.path && isTestPath(known.path),
        deliberate: true,
      },
      now,
    );
    items.push(item);
  }

  if (helper) {
    for (const e of helper.journal) {
      if (e.state !== 'active') continue;
      const c = e.command as Action;
      const kind = KIND[c.kind];
      if (!kind) continue;
      if (
        c.kind === 'santa.rule.set' &&
        c.ruleType === 'binary' &&
        c.policy !== 'allow' &&
        blockedHashes.has(c.identifier.toLowerCase())
      )
        continue;
      const k = targetKey(c);
      const record = byQuarantine.get(e.id) ?? (k ? byTarget.get(k) : undefined);
      const cause = causeOf(record);
      const item: InForceItem = {
        key: `j:${e.id}`,
        kind,
        ...describe(e, program),
        since: e.createdAt,
        ...(cause ? { cause } : {}),
        release: 'release',
        flags: [],
      };
      item.flags = flagsFor(
        item,
        {
          system:
            blocksSystem(c, program) ||
            (kind === 'paused' && pathsOf(e).some(isSystemPath)) ||
            (kind === 'startup' && pathsOf(e).some((p) => p.startsWith('/System/'))),
          test: pathsOf(e).some(isTestPath),
          deliberate: record?.actor === 'user',
        },
        now,
      );
      items.push(item);
    }
    for (const p of helper.preexec ?? []) {
      const ruleId = p.ruleIds[0];
      const ruleName = ruleId ? input.ruleName(ruleId) : undefined;
      items.push({
        key: `p:${p.identifier}`,
        kind: 'prelaunch',
        title: `Stops ${p.program} before it starts, when ${ruleName ? `“${ruleName}”` : 'a blocking rule'} matches`,
        detail: p.identifier,
        ...(ruleId ? { cause: { ruleId, ...(ruleName ? { ruleName } : {}) } } : {}),
        release: 'rule',
        flags: [],
      });
    }
  } else {
    // No helper to ask: what the app last did and never undid. Simulated
    // actions changed nothing, so they are left out.
    for (const r of input.done) {
      const kind = KIND[r.action.kind];
      if (!kind || r.result?.simulated !== false || !undoOf(r.action, r.result)) continue;
      const c = r.action;
      if (
        c.kind === 'santa.rule.set' &&
        c.ruleType === 'binary' &&
        blockedHashes.has(c.identifier.toLowerCase())
      )
        continue;
      const e: JournalEntry = {
        id: r.id,
        kind: c.kind,
        command: c,
        state: 'active',
        createdAt: r.requestedAt,
        summary: r.reason,
      };
      const cause = causeOf(r);
      const item: InForceItem = {
        key: `a:${r.id}`,
        kind,
        ...describe(e, program),
        since: r.requestedAt,
        ...(cause ? { cause } : {}),
        release: 'release',
        flags: [],
      };
      item.flags = flagsFor(
        item,
        {
          system: blocksSystem(c, program),
          test: pathsOf(e).some(isTestPath),
          deliberate: r.actor === 'user',
        },
        now,
      );
      items.push(item);
    }
  }
  // Called out first, then newest first.
  return items.sort(
    (a, b) =>
      Number(b.flags.length > 0) - Number(a.flags.length > 0) || (b.since ?? 0) - (a.since ?? 0),
  );
}

const FLAG_ORDER: InForceFlag[] = ['apple-program', 'test-leftover', 'long-running'];

/** What the startup check says about the items, or null when nothing looks wrong. */
export function checkInForce(items: readonly InForceItem[], now: number): InForceCheck | null {
  const rank = (i: InForceItem) => Math.min(...i.flags.map((f) => FLAG_ORDER.indexOf(f)));
  const flagged = items.filter((i) => i.flags.length > 0).sort((a, b) => rank(a) - rank(b));
  const first = flagged[0];
  if (!first) return null;
  const what = first.title.charAt(0).toLowerCase() + first.title.slice(1);
  const worst = FLAG_ORDER[rank(first)];
  const lead =
    worst === 'apple-program'
      ? `Vigil ${what}, which is part of the system. That can stop apps and scripts from working`
      : worst === 'test-leftover'
        ? `Vigil still ${what}, left over from a test run`
        : `Vigil ${what} and has for ${Math.floor((now - (first.since ?? now)) / DAY)} days`;
  const more = flagged.length - 1;
  return {
    message:
      more > 0
        ? `${lead}, and ${more} more ${more === 1 ? 'thing looks' : 'things look'} wrong.`
        : `${lead}.`,
    keys: flagged.map((i) => i.key),
  };
}

/** What In force needs from the helper link (HelperLink). */
export interface InForceHelper {
  inForce(): Promise<HelperInForce | null>;
  unblock(
    list: string,
    entry: string,
    opts?: { hold?: boolean; onHeld?: () => void },
  ): Promise<{ unblocked: boolean }>;
  approveHeld(): Promise<void>;
  dropHeld(): void;
}

/** How long a program lookup by hash stands. */
const PROGRAMS_TTL_MS = 60_000;

/**
 * The In force page and the startup check. Every release goes through the
 * helper's admin password: an action's own undo (AlertService.undo), the
 * reverse of an action the app has no record of (AlertService.run as the
 * user, which the helper treats as a release), or taking an entry off the
 * user's block list (detection.list.unblock).
 */
export class InForce {
  private programs: { at: number; map: Map<string, KnownProgram> } | undefined;

  constructor(
    private readonly core: VigilCore,
    private readonly helper: InForceHelper,
    /** sha256 of the programs in the system's own folders, to name a block by hash. */
    private readonly systemHashes: () => Promise<Map<string, string>> = () =>
      Promise.resolve(new Map()),
    private readonly now: () => number = Date.now,
  ) {}

  async view(): Promise<InForceView> {
    let helper: HelperInForce | null = null;
    try {
      helper = await this.helper.inForce();
    } catch (err) {
      console.warn('[in-force] the helper could not say what is in force:', err);
    }
    const programs = await this.programMap();
    const now = this.now();
    const items = buildInForce({
      helper,
      done: this.core.store.listActionsByStatus('done'),
      appUserBlocks: this.core.detector?.userBlocks() ?? [],
      alertTitle: (id) => this.core.store.getAlert(id)?.title,
      ruleName: (id) => (this.core.detector?.rule(id) ?? this.core.store.getRule(id))?.name,
      program: (sha) => programs.get(sha),
      now,
    });
    return {
      helper: helper ? 'connected' : 'unavailable',
      items,
      check: checkInForce(items, now),
    };
  }

  /** Release one item. Resolves, never throws, with what happened. */
  async release(key: string): Promise<InForceReleaseResult> {
    try {
      const out = await this.releaseOne(key);
      this.programs = undefined;
      return out;
    } catch (err) {
      return { ok: false, error: err instanceof Error ? err.message : String(err) };
    }
  }

  private async releaseOne(key: string): Promise<InForceReleaseResult> {
    const [tag] = key.split(':', 1);
    const rest = key.slice((tag?.length ?? 0) + 1);
    if (tag === 'a') return this.undoRecord(rest);
    if (tag === 'p')
      return {
        ok: false,
        error: 'Change the rule to stop this. Releasing it here would not last.',
      };
    const helper = await this.helper.inForce();
    if (!helper)
      return { ok: false, error: 'Vigil’s helper isn’t running, so nothing can be released now.' };
    if (tag === 'j') {
      const entry = helper.journal.find((e) => e.id === rest && e.state === 'active');
      if (!entry) return { ok: false, error: 'It is no longer in force.' };
      return this.releaseEntry(entry);
    }
    if (tag === 'u') {
      const sep = rest.indexOf(':');
      return this.unblock(rest.slice(0, sep), rest.slice(sep + 1), helper);
    }
    return { ok: false, error: 'Unknown item' };
  }

  /** The action's own undo when the app has its record; otherwise its reverse, as the user. */
  private async releaseEntry(entry: JournalEntry): Promise<InForceReleaseResult> {
    const record = this.recordFor(entry);
    if (record) return this.undoRecord(record.id);
    const reverse = undoOf(entry.command as Action, {
      at: entry.createdAt,
      quarantineId: entry.id,
    });
    if (!reverse) return { ok: false, error: 'This can’t be undone.' };
    const out = await this.core.alerts.run('user', reverse, {
      reason: 'Released from In force',
    });
    return outcome(out);
  }

  private async undoRecord(id: string): Promise<InForceReleaseResult> {
    return outcome(await this.core.alerts.undo(id));
  }

  private recordFor(entry: JournalEntry): ActionRecord | undefined {
    const done = this.core.store.listActionsByStatus('done');
    const byId = done.find((r) => r.result?.quarantineId === entry.id);
    if (byId) return byId;
    const k = targetKey(entry.command as Action);
    return k ? done.filter((r) => targetKey(r.action) === k).at(-1) : undefined;
  }

  /**
   * Take a hash off the user's block list everywhere, with any Santa rule on
   * it, for one password: the helper's unblock is held while the Santa rule
   * is released, and that release's dialog asks for both. The app's list
   * changes first and is put back if the user says no, so the app never
   * syncs the entry away (which would only retire it for a week) unasked.
   */
  private async unblock(
    list: string,
    sha: string,
    helper: HelperInForce,
  ): Promise<InForceReleaseResult> {
    if (!helper.userBlocks)
      return {
        ok: false,
        error: 'Update the Vigil helper first: this one can’t take a program off your block list.',
      };
    if (!helper.userBlocks.some((b) => b.list === list && b.entry.toLowerCase() === sha))
      return { ok: false, error: 'It is no longer on your block list.' };
    const dropped = this.core.detector?.dropUserBlock(list, sha) ?? false;
    const putBack = () => {
      if (dropped) this.core.detector?.restoreUserBlock(list, sha);
    };
    const santa = helper.journal.filter((e) => {
      const c = e.command as Action;
      return (
        e.state === 'active' &&
        c.kind === 'santa.rule.set' &&
        c.ruleType === 'binary' &&
        c.policy !== 'allow' &&
        c.identifier.toLowerCase() === sha
      );
    });
    try {
      if (!santa.length) {
        await this.helper.unblock(list, sha);
      } else {
        let unblocking!: Promise<{ unblocked: boolean }>;
        await new Promise<void>((held) => {
          unblocking = this.helper.unblock(list, sha, { hold: true, onHeld: held });
          unblocking.then(
            () => held(),
            () => held(),
          );
        });
        let released: InForceReleaseResult = { ok: true };
        for (const e of santa) {
          released = await this.releaseEntry(e);
          if (!released.ok) break;
        }
        if (released.ok) await this.helper.approveHeld();
        else this.helper.dropHeld();
        await unblocking.catch((err: unknown) => {
          if (released.ok) throw err;
        });
        if (!released.ok) {
          putBack();
          return released;
        }
      }
    } catch (err) {
      putBack();
      return { ok: false, error: refusedWords(err) };
    }
    // The helper no longer has it, so this sync drops nothing there.
    if (dropped) void this.core.detector?.syncHelper?.();
    return { ok: true };
  }

  /**
   * Programs by hash: from the alerts behind Vigil's own actions and the
   * ones the user confirmed as threats, then the system's own folders.
   */
  private async programMap(): Promise<Map<string, KnownProgram>> {
    const now = this.now();
    if (this.programs && now - this.programs.at < PROGRAMS_TTL_MS) return this.programs.map;
    const map = new Map<string, KnownProgram>();
    const store = this.core.store;
    const alertIds = new Set<string>();
    for (const r of store.listActionsByStatus('done')) if (r.alertId) alertIds.add(r.alertId);
    for (const a of store.listAlerts({ status: 'resolved', limit: 2000 }))
      if (a.decision?.verdict === 'malicious') alertIds.add(a.id);
    for (const id of alertIds) {
      const alert = store.getAlert(id);
      if (!alert) continue;
      for (const e of store.getEvents(alert.eventIds)) {
        const p = 'process' in e ? e.process : undefined;
        if (!p?.sha256) continue;
        map.set(p.sha256.toLowerCase(), {
          path: p.path,
          ...(p.signing === 'apple' ? { apple: true } : {}),
        });
      }
    }
    try {
      for (const [sha, path] of await this.systemHashes())
        if (!map.has(sha)) map.set(sha, { path, apple: true });
    } catch (err) {
      console.warn('[in-force] could not hash the system’s programs:', err);
    }
    this.programs = { at: now, map };
    return map;
  }
}

function outcome(r: ActionRecord): InForceReleaseResult {
  if (r.status === 'done') return { ok: true };
  return { ok: false, error: r.result?.error ?? 'Not released' };
}

function refusedWords(err: unknown): string {
  const code = (err as { code?: string } | undefined)?.code;
  if (code === 'refused') return 'Not released: the password was not given.';
  return err instanceof Error ? err.message : String(err);
}

/** Most programs hashed in each system folder, and the largest one. */
const SYSTEM_HASH_MAX_FILES = 200;
const SYSTEM_HASH_MAX_BYTES = 8 * 1024 * 1024;

/**
 * sha256 of the programs in the system's smallest program folders (/bin and
 * /sbin), so a block by hash on one of them, /bin/sh say, is named and
 * called out even when no alert recorded its path. Hashed once per launch.
 */
export function systemHashes(dirs = ['/bin', '/sbin']): () => Promise<Map<string, string>> {
  let done: Promise<Map<string, string>> | undefined;
  return () =>
    (done ??= (async () => {
      const out = new Map<string, string>();
      for (const dir of dirs) {
        let names: string[];
        try {
          names = (await readdir(dir)).slice(0, SYSTEM_HASH_MAX_FILES);
        } catch {
          continue;
        }
        for (const name of names) {
          const path = join(dir, name);
          try {
            const s = await stat(path);
            if (!s.isFile() || s.size > SYSTEM_HASH_MAX_BYTES) continue;
            out.set(
              createHash('sha256')
                .update(await readFile(path))
                .digest('hex'),
              path,
            );
          } catch {
            // Unreadable: leave it out.
          }
        }
      }
      return out;
    })());
}
