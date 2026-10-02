import { EventEmitter } from 'node:events';
import { existsSync } from 'node:fs';
import { isRelease, type Action, type ActionResult, type SensorEvent } from '@vigil/core';
import { defaultPaths, type PreexecOutcome } from '@vigil/helper';
import type { DetectionRule } from '@vigil/detection';
import { HelperCallError, HelperClient } from '@vigil/helper/client';
import { DryRunExecutor, type ActionExecutor } from './executor.js';

export type HelperState = 'not_installed' | 'not_running' | 'connected';

/** How often to look for the helper while it isn't connected. */
export const HELPER_RETRY_MS = 15_000;
const QUERY_TIMEOUT_MS = 5_000;
const ACTION_TIMEOUT_MS = 15_000;
const RELEASE_TIMEOUT_MS = 3 * 60_000;
/** The helper keeps its last 2000 events; remember a little more than that. */
const SEEN_EVENT_IDS = 4000;

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
  private timer: ReturnType<typeof setTimeout> | undefined;
  private stopped = false;
  private connecting = false;
  state: HelperState = 'not_installed';
  /** The last event received, so a reconnect only replays what was missed. */
  private lastEventId: string | undefined;
  /** Recent event ids. After a helper restart it replays its whole buffer. */
  private seen = new Set<string>();
  readonly dryRun = new DryRunExecutor();

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
  async query<T>(kind: 'helper.status' | 'helper.journal' | 'santa.profile'): Promise<T | null> {
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
   * Hand the helper the rules Vigil enforces in block mode, so Santa can stop
   * the ones it can express before the program runs. Null while unconnected.
   */
  async setPreexecRules(rules: DetectionRule[]): Promise<PreexecOutcome | null> {
    const client = this.client;
    if (!client) return null;
    try {
      return await withTimeout(
        client.call<PreexecOutcome>({ kind: 'santa.preexec.set', rules }),
        ACTION_TIMEOUT_MS,
      );
    } catch (err) {
      if (!(err instanceof HelperCallError)) this.dropped(client);
      throw err;
    }
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
      client.onEvent((e) => this.received(e));
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

  private received(e: SensorEvent): void {
    if (this.seen.has(e.id)) return;
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
