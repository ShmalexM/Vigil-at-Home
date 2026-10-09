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
import { listDigest } from '@vigil/detection/fastpath';
import { HelperCallError, HelperClient } from '@vigil/helper/client';
import type { z } from 'zod';
import { DryRunExecutor, type ActionExecutor } from './executor.js';

export type HelperState = 'not_installed' | 'not_running' | 'connected';

/** How often to look for the helper while it isn't connected. */
export const HELPER_RETRY_MS = 15_000;
/** The longest wait between tries while the helper keeps failing. */
export const HELPER_RETRY_MAX_MS = 2 * 60_000;
/**
 * A second drop this soon after the last one is a helper that keeps failing
 * (crash-looping, or answering some calls and not others), not a blip: it
 * shows as not running and is retried with backoff.
 */
export const HELPER_FLAP_WINDOW_MS = 3 * 60_000;
const QUERY_TIMEOUT_MS = 5_000;
const ACTION_TIMEOUT_MS = 15_000;
const RELEASE_TIMEOUT_MS = 3 * 60_000;
/** The helper keeps its last 2000 events; remember a little more than that. */
const SEEN_EVENT_IDS = 4000;
/** How long an action the helper already ran waits for the app's engine to ask for it. */
const HELPER_RAN_MS = 60_000;

/** The blocking rules the helper runs itself, and what they need. */
export interface HelperRuleSet {
  rules: DetectionRule[];
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
  needLists: string[];
  preexec: PreexecOutcome | null;
}

/** The helper's socket is open but it didn't answer in time. */
class HelperTimeout extends Error {}

function withTimeout<T>(p: Promise<T>, ms: number): Promise<T> {
  return new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new HelperTimeout('The Vigil helper did not answer')), ms);
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
  private timer: ReturnType<typeof setTimeout> | undefined;
  private stopped = false;
  private connecting = false;
  /** When the connection last dropped, and how many drops came close together since. */
  private lastDropAt = -Infinity;
  private failures = 0;
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
      return {
        at: Date.now(),
        simulated: false,
        ...(out.quarantineId ? { quarantineId: out.quarantineId } : {}),
      };
    } catch (err) {
      if (!(err instanceof HelperCallError) || /connection closed/.test(err.message)) {
        this.dropped(client, err);
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
  async query<T>(kind: 'helper.status' | 'helper.journal' | 'santa.profile'): Promise<T | null> {
    const client = this.client;
    if (!client) return null;
    try {
      return await withTimeout(client.call<T>({ kind }), QUERY_TIMEOUT_MS);
    } catch (err) {
      // A closed or hung connection: drop it and start reconnecting.
      this.dropped(client, err);
      throw err;
    }
  }

  /**
   * Hand the helper the blocking rules it can run itself (and Santa before
   * launch), then any indicator list it says it doesn't have yet. Null while
   * unconnected. If the rules turn something off or add an exception, the
   * helper asks for the admin password first; a cancelled dialog throws a
   * HelperCallError with code refused and leaves the helper's rules as they were.
   * With `hold`, that password is asked for by the next dialog instead (a
   * release's) or by approveHeld(). With `ask: false` no dialog is shown:
   * a sync that needs the password resolves 'needs_password' and changes nothing.
   *
   * Vigil's own programs go to the helper apart from the rules (grantSelf).
   * `withSelf` sends them with the rules instead, for a helper from before
   * self.grant.
   */
  async syncRules(
    set: HelperRuleSet,
    opts: { hold?: boolean; onHeld?: () => void; ask?: boolean; withSelf?: boolean } = {},
  ): Promise<HelperRulesOutcome | 'needs_password' | null> {
    const client = this.client;
    if (!client) return null;
    try {
      const digests = Object.fromEntries(
        Object.entries(set.lists).map(([name, entries]) => [name, listDigest(entries)]),
      );
      const sync = {
        kind: 'detection.sync' as const,
        rules: set.rules,
        exceptions: set.exceptions,
        // Only an AppImage names images and hashes; a helper from before them refuses unknown fields.
        ...(opts.withSelf ? selfOf(set) : {}),
        lists: digests,
      };
      let out: HelperRulesOutcome;
      if (opts.ask === false) {
        const tried = await withTimeout(
          client.attempt<HelperRulesOutcome>(sync),
          ACTION_TIMEOUT_MS,
        );
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
      for (const name of out.needLists) {
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
      }
      return out;
    } catch (err) {
      if (!(err instanceof HelperCallError)) this.dropped(client, err);
      throw err;
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

  /** Try once now; on failure, try again after HELPER_RETRY_MS (longer while it keeps failing). */
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
      client.onEvent((e, ran) => this.received(e, ran));
      // A helper that accepts the connection but never answers counts as not
      // running, rather than leaving the link stuck mid-connect.
      try {
        await withTimeout(client.subscribe(this.lastEventId), QUERY_TIMEOUT_MS);
      } catch (err) {
        client.close();
        throw err;
      }
      this.client = client;
      // After a quiet reconnect the state hasn't changed, but listeners still
      // need to hear of the new connection (to send the rules again).
      if (this.state === 'connected') this.emit('state', 'connected');
      else this.setState('connected');
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
        ? {
            at,
            simulated: false,
            ...(r.outcome.quarantineId ? { quarantineId: r.outcome.quarantineId } : {}),
          }
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

  /**
   * A connection that closed once is tried again at once before anything
   * changes on screen, so a one-off blip (a helper restart) never shows the
   * helper as stopped. A helper that didn't answer, or a second drop within
   * HELPER_FLAP_WINDOW_MS, is not a blip: it shows as not running and is
   * retried with backoff, so a wedged or crash-looping helper never reads as
   * fine and isn't hammered with reconnects.
   */
  private dropped(client: HelperClient, why?: unknown): void {
    if (this.client !== client) return;
    this.client = undefined;
    client.close();
    const now = Date.now();
    const again = now - this.lastDropAt < HELPER_FLAP_WINDOW_MS;
    this.lastDropAt = now;
    if (!again) this.failures = 0;
    if (!again && !(why instanceof HelperTimeout)) {
      void this.tryConnect();
      return;
    }
    this.failures++;
    this.setState(existsSync(this.socket) ? 'not_running' : 'not_installed');
    this.retry();
  }

  private retry(): void {
    if (this.stopped) return;
    clearTimeout(this.timer);
    const wait = Math.min(
      HELPER_RETRY_MS * 2 ** Math.max(0, this.failures - 1),
      HELPER_RETRY_MAX_MS,
    );
    this.timer = setTimeout(() => void this.tryConnect(), wait);
    this.timer.unref?.();
  }
}
