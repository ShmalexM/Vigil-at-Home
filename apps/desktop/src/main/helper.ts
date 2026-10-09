import { EventEmitter } from 'node:events';
import { existsSync } from 'node:fs';
import { isRelease, type Action, type ActionResult, type SensorEvent } from '@vigil/core';
import type { SelfImage } from '@vigil/core/self';
import {
  LIST_PART_MAX,
  defaultPaths,
  type HelperRan,
  type PreexecOutcome,
  type RuleExceptionSchema,
} from '@vigil/helper';
import type { DetectionRule } from '@vigil/detection';
import { listDigest, type AppBlockingRule } from '@vigil/detection/fastpath';
import { HelperCallError, HelperClient } from '@vigil/helper/client';
import type { z } from 'zod';
import { DryRunExecutor, type ActionExecutor } from './executor.js';

export type HelperState = 'not_installed' | 'not_running' | 'connected';

/** How often to look for the helper while it isn't connected. */
export const HELPER_RETRY_MS = 15_000;
const QUERY_TIMEOUT_MS = 5_000;
const ACTION_TIMEOUT_MS = 15_000;
export const RELEASE_TIMEOUT_MS = 3 * 60_000;
/** A sync's deadline on the helper falls this long before the app stops waiting. */
const SYNC_DEADLINE_MARGIN_MS = 5_000;
/** The helper keeps its last 2000 events; remember a little more than that. */
const SEEN_EVENT_IDS = 4000;
/** How long an action the helper already ran waits for the app's engine to ask for it. */
const HELPER_RAN_MS = 60_000;

/** The blocking rules the helper runs itself, and what they need. */
export interface HelperRuleSet {
  rules: DetectionRule[];
  /** Blocking rules only the app runs: weakening one needs the password too. */
  appRules: AppBlockingRule[];
  exceptions: z.infer<typeof RuleExceptionSchema>[];
  selfPaths: string[];
  /** Linux AppImage: the image by device and inode, and its programs' sha256. */
  selfImages?: SelfImage[];
  selfHashes?: string[];
  lists: Record<string, string[]>;
}

/** What is Vigil's own, as the helper takes it in a self grant. */
export type HelperSelfSet = Pick<HelperRuleSet, 'selfPaths' | 'selfImages' | 'selfHashes'>;

/** The self set within a rule set. */
export function selfOf(set: HelperSelfSet): HelperSelfSet {
  return {
    selfPaths: set.selfPaths,
    ...(set.selfImages?.length ? { selfImages: set.selfImages } : {}),
    ...(set.selfHashes?.length ? { selfHashes: set.selfHashes } : {}),
  };
}

/**
 * Whether `err` is a helper from before self.grant refusing a command it
 * doesn't know: self.grant itself (`kind`), or rules sent without the self
 * set it still requires (`selfPaths`).
 */
export function fromOlderHelper(err: unknown, field: 'kind' | 'selfPaths'): boolean {
  return (
    err instanceof HelperCallError &&
    err.code === 'invalid' &&
    err.message.startsWith(`bad command: ${field} `)
  );
}

export interface HelperRulesOutcome {
  /** False when the helper lacked a list's contents and changed nothing. */
  applied: boolean;
  needLists: string[];
  /** Santa's pre-launch rules follow in the background (`pending`); detection.status says how. */
  preexec: 'pending' | PreexecOutcome | null;
}

function withTimeout<T>(p: Promise<T>, ms: number): Promise<T> {
  return new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error('The Vigil helper did not answer')), ms);
    p.then(
      (v) => (clearTimeout(t), resolve(v)),
      (e: unknown) => (clearTimeout(t), reject(e instanceof Error ? e : new Error(String(e)))),
    );
  });
}

interface Outcome {
  actionId: string;
  summary: string;
  undoable: boolean;
  quarantineId?: string;
}

/**
 * The app's side of the privileged helper: one connection over its Unix
 * socket, reconnected whenever it drops. Sensor events stream in through it,
 * and response actions go out through it. Until it connects, actions are
 * simulated and labelled that way, so nothing ever waits on it.
 */
export class HelperLink
  extends EventEmitter<{ state: [HelperState]; event: [SensorEvent] }>
  implements ActionExecutor
{
  private client: HelperClient | undefined;
  /** What the connected helper is known to have, so unchanged lists are not sent again. */
  private confirmedFor: HelperClient | undefined;
  private confirmedRules: string | undefined;
  private confirmedLists = new Map<string, string>();
  private timer: ReturnType<typeof setTimeout> | undefined;
  private stopped = false;
  private connecting = false;
  state: HelperState = 'not_installed';
  /** The last event received, so a reconnect only replays what was missed. */
  private lastEventId: string | undefined;
  /** Recent event ids. After a helper restart it replays its whole buffer. */
  private seen = new Set<string>();
  readonly dryRun = new DryRunExecutor();
  /**
   * Results of actions the helper's own rules ran, by action, until the app's
   * engine reaches the same rule on the same event and asks for them.
   */
  private helperRan = new Map<string, { results: ActionResult[]; at: number }>();

  constructor(
    private readonly socket = defaultPaths().socket,
    private readonly connect: (socket: string) => Promise<HelperClient> = (s) =>
      HelperClient.connect(s),
  ) {
    super();
  }

  /** True while actions are only simulated. */
  get simulated(): boolean {
    return !this.client;
  }

  start(): void {
    this.stopped = false;
    void this.tryConnect();
  }

  /** Drop any connection and look again now, e.g. right after installing or removing the helper. */
  async reconnect(): Promise<void> {
    const client = this.client;
    this.client = undefined;
    client?.close();
    this.stopped = false;
    await this.tryConnect();
  }

  stop(): void {
    this.stopped = true;
    clearTimeout(this.timer);
    this.client?.close();
    this.client = undefined;
  }

  async execute(action: Action): Promise<ActionResult> {
    const already = this.takeHelperRan(action);
    if (already) return already;
    const client = this.client;
    if (!client) return this.dryRun.execute(action);
    try {
      // Releases make the helper ask for the admin password; call() shows the dialog.
      // A release waits on the user typing their password; containment must be quick.
      const out = await withTimeout(
        client.call<Outcome>(action),
        isRelease(action) ? RELEASE_TIMEOUT_MS : ACTION_TIMEOUT_MS,
      );
      if (!out) throw new Error('No answer from the Vigil helper');
      return { at: Date.now(), ...(out.quarantineId ? { quarantineId: out.quarantineId } : {}) };
    } catch (err) {
      if (!(err instanceof HelperCallError) || /connection closed/.test(err.message)) {
        this.dropped(client);
      }
      const error =
        err instanceof HelperCallError && err.code === 'refused'
          ? `Not done: ${err.message}`
          : err instanceof Error
            ? err.message
            : String(err);
      return { at: Date.now(), error };
    }
  }

  /** Ask the helper for something read-only (status, journal, the Santa profile). */
  async query<T>(
    kind: 'helper.status' | 'helper.journal' | 'santa.profile' | 'detection.status',
  ): Promise<T | null> {
    const client = this.client;
    if (!client) return null;
    try {
      return await withTimeout(client.call<T>({ kind }), QUERY_TIMEOUT_MS);
    } catch (err) {
      // A closed or hung connection: drop it and start reconnecting.
      this.dropped(client);
      throw err;
    }
  }

  /**
   * Hand the helper the blocking rules it can run itself (and Santa before
   * launch). Null while unconnected, before anything is sent.
   *
   * A change to the rules goes as one detection.sync carrying the contents of
   * every list the helper may not have, which the helper puts in force whole
   * or not at all. If it still lacks one (it says so and changes nothing), the
   * sync is sent again with it. When only list contents changed (a feed
   * refresh, a newly blocked program), the lists go on their own, in parts.
   *
   * If the rules turn something off or add an exception, the helper asks for
   * the admin password first; a cancelled dialog throws a HelperCallError
   * with code refused and leaves the helper's rules as they were. With
   * `hold`, that password is asked for by the next dialog instead (a
   * release's) or by approveHeld(). With `ask: false` no dialog is shown:
   * a sync that needs the password resolves 'needs_password' and changes
   * nothing. `syncId` names the sync, so rulesState() can tell whether it
   * went in after the app stopped waiting.
   *
   * Vigil's own programs go to the helper apart from the rules (grantSelf).
   * `withSelf` sends them with the rules instead, for a helper from before
   * self.grant.
   */
  async syncRules(
    set: HelperRuleSet,
    opts: {
      hold?: boolean;
      onHeld?: () => void;
      ask?: boolean;
      withSelf?: boolean;
      syncId?: string;
    } = {},
  ): Promise<HelperRulesOutcome | 'needs_password' | null> {
    const client = this.client;
    if (!client) return null;
    if (client !== this.confirmedFor) {
      this.confirmedFor = client;
      this.confirmedRules = undefined;
      this.confirmedLists = new Map();
    }
    try {
      const digests = Object.fromEntries(
        Object.entries(set.lists).map(([name, entries]) => [name, listDigest(entries)]),
      );
      const changed = Object.keys(digests).filter((n) => this.confirmedLists.get(n) !== digests[n]);
      const rulesKey = JSON.stringify({
        rules: set.rules,
        appRules: set.appRules,
        exceptions: set.exceptions,
        self: opts.withSelf ? selfOf(set) : null,
        lists: Object.keys(digests).sort(),
      });
      if (rulesKey === this.confirmedRules && !opts.hold) {
        await this.sendLists(client, set, digests, changed);
        return { applied: true, needLists: [], preexec: null };
      }
      const base = {
        kind: 'detection.sync' as const,
        rules: set.rules,
        appRules: set.appRules,
        exceptions: set.exceptions,
        // Only an AppImage names images and hashes; a helper from before them refuses unknown fields.
        ...(opts.withSelf ? selfOf(set) : {}),
        lists: digests,
        ...(opts.syncId ? { syncId: opts.syncId } : {}),
      };
      let carry = changed;
      // Without a dialog the helper answers at once; with one it waits on the password.
      const wait = opts.ask === false ? ACTION_TIMEOUT_MS : RELEASE_TIMEOUT_MS;
      for (let attempt = 0; attempt < 2; attempt++) {
        // The helper refuses this sync once the app has stopped waiting for
        // it, so a password typed after the timeout can't put it in force
        // after rulesState() said it wasn't.
        const notAfter = Date.now() + wait - SYNC_DEADLINE_MARGIN_MS;
        const sync = {
          ...base,
          notAfter,
          ...(carry.length
            ? {
                entries: Object.fromEntries(
                  carry.map((n) => [n, [...new Set(set.lists[n] ?? [])]]),
                ),
              }
            : {}),
        };
        let out: HelperRulesOutcome;
        if (opts.ask === false) {
          const tried = await withTimeout(client.attempt<HelperRulesOutcome>(sync), wait);
          if (tried === 'needsApproval') return 'needs_password';
          out = tried.result;
        } else {
          out = await withTimeout(
          opts.hold
            ? client.hold<HelperRulesOutcome>(sync, opts.onHeld)
            : client.call<HelperRulesOutcome>(sync),
          // A sync that loosens the rules waits on the admin password, like a release.
          RELEASE_TIMEOUT_MS,
        );
        }
        if (out.applied) {
          this.confirmedRules = rulesKey;
          this.confirmedLists = new Map(Object.entries(digests));
          return out;
        }
        carry = [...new Set([...carry, ...out.needLists])];
      }
      throw new HelperCallError('the helper kept asking for its lists', 'failed');
    } catch (err) {
      // A timeout is not a dead connection (a password dialog can stay open):
      // keep it, so the app can ask the helper what is in force.
      if (err instanceof HelperCallError && /connection closed/.test(err.message))
        this.dropped(client);
      throw err;
    }
  }

  /** Lists on their own, in parts: each goes in once all its parts are in. */
  private async sendLists(
    client: HelperClient,
    set: HelperRuleSet,
    digests: Record<string, string>,
    names: string[],
  ): Promise<void> {
    for (const name of names) {
      const entries = [...new Set(set.lists[name] ?? [])];
      const parts = Math.max(1, Math.ceil(entries.length / LIST_PART_MAX));
      for (let part = 0; part < parts; part++) {
        await withTimeout(
          client.call({
            kind: 'detection.list.set',
            list: name,
            digest: digests[name]!,
            part,
            parts,
            entries: entries.slice(part * LIST_PART_MAX, (part + 1) * LIST_PART_MAX),
          }),
          QUERY_TIMEOUT_MS,
        );
      }
      this.confirmedLists.set(name, digests[name]!);
    }
  }

  /** Which sync is in force on the helper (the app's id for it), or null if it can't say. */
  async rulesState(): Promise<{ syncId: string | null } | null> {
    try {
      return await this.query<{ syncId: string | null }>('detection.status');
    } catch {
      return null;
    }
  }

  /**
   * Tell the helper what is Vigil's own, so its rules never pause, kill or
   * block it. Anything new needs the admin password, so this can wait on the
   * dialog for as long as it stays open; nothing else waits on it. Resolves
   * 'unsupported' from a helper from before self.grant, null while unconnected.
   */
  async grantSelf(set: HelperSelfSet): Promise<'applied' | 'declined' | 'unsupported' | null> {
    const client = this.client;
    if (!client) return null;
    try {
      // No timeout: the dialog may stay open, and a lost connection settles it.
      await client.call({ kind: 'self.grant', ...selfOf(set) });
      return 'applied';
    } catch (err) {
      if (fromOlderHelper(err, 'kind')) return 'unsupported';
      if (err instanceof HelperCallError && err.code === 'refused') return 'declined';
      throw err;
    }
  }

  /** Ask for the password for anything syncRules held, once, and send it. */
  async approveHeld(): Promise<void> {
    await this.client?.approveHeld();
  }

  /** Refuse anything syncRules held, so the app puts its side back. */
  dropHeld(): void {
    this.client?.dropHeld();
  }

  /** Check the connection is alive. Called on the health timer. */
  async ping(): Promise<boolean> {
    if (!this.client) {
      void this.tryConnect();
      return false;
    }
    try {
      await this.query('helper.status');
      return true;
    } catch {
      return false;
    }
  }

  private setState(s: HelperState): void {
    if (s === this.state) return;
    this.state = s;
    this.emit('state', s);
  }

  /** Try once now; on failure, try again after HELPER_RETRY_MS. */
  async tryConnect(): Promise<void> {
    if (this.stopped || this.client || this.connecting) return;
    clearTimeout(this.timer);
    if (!existsSync(this.socket)) {
      this.setState('not_installed');
      this.retry();
      return;
    }
    this.connecting = true;
    try {
      const client = await this.connect(this.socket);
      if (this.stopped) {
        client.close();
        return;
      }
      this.client = client;
      client.onEvent((e, ran) => this.received(e, ran));
      await client.subscribe(this.lastEventId);
      this.setState('connected');
    } catch {
      this.client = undefined;
      this.setState('not_running');
      this.retry();
    } finally {
      this.connecting = false;
    }
  }

  private received(e: SensorEvent, ran: HelperRan[] = []): void {
    if (this.seen.has(e.id)) return;
    if (ran.length) this.rememberHelperRan(ran);
    this.seen.add(e.id);
    if (this.seen.size > SEEN_EVENT_IDS) {
      // Sets iterate oldest first.
      for (const id of this.seen) {
        this.seen.delete(id);
        if (this.seen.size <= SEEN_EVENT_IDS / 2) break;
      }
    }
    this.lastEventId = e.id;
    this.emit('event', e);
  }

  private rememberHelperRan(ran: HelperRan[]): void {
    const now = Date.now();
    for (const [k, v] of this.helperRan) if (now - v.at > HELPER_RAN_MS) this.helperRan.delete(k);
    for (const r of ran) {
      const at = typeof r.at === 'number' ? r.at : now;
      const result: ActionResult = r.outcome
        ? { at, ...(r.outcome.quarantineId ? { quarantineId: r.outcome.quarantineId } : {}) }
        : { at, error: r.error ?? 'The Vigil helper could not do this' };
      const key = JSON.stringify(r.action);
      const entry = this.helperRan.get(key);
      if (entry) entry.results.push(result);
      else this.helperRan.set(key, { results: [result], at: now });
    }
  }

  private takeHelperRan(action: Action): ActionResult | undefined {
    const key = JSON.stringify(action);
    const entry = this.helperRan.get(key);
    if (!entry || Date.now() - entry.at > HELPER_RAN_MS) return undefined;
    const result = entry.results.shift();
    if (!entry.results.length) this.helperRan.delete(key);
    return result;
  }

  private dropped(client: HelperClient): void {
    if (this.client !== client) return;
    this.client = undefined;
    client.close();
    this.setState(existsSync(this.socket) ? 'not_running' : 'not_installed');
    this.retry();
  }

  private retry(): void {
    if (this.stopped) return;
    clearTimeout(this.timer);
    this.timer = setTimeout(() => void this.tryConnect(), HELPER_RETRY_MS);
    this.timer.unref?.();
  }
}
