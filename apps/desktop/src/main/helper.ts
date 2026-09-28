import { EventEmitter } from 'node:events';
import { existsSync } from 'node:fs';
import { isRelease, type Action, type ActionResult, type SensorEvent } from '@vigil/core';
import { defaultPaths } from '@vigil/helper';
import { HelperCallError, HelperClient } from '@vigil/helper/client';
import { DryRunExecutor, type ActionExecutor } from './executor.js';

export type HelperState = 'not_installed' | 'not_running' | 'connected';

/** How often to look for the helper while it isn't connected. */
export const HELPER_RETRY_MS = 15_000;
const QUERY_TIMEOUT_MS = 5_000;
const ACTION_TIMEOUT_MS = 15_000;
const RELEASE_TIMEOUT_MS = 3 * 60_000;

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
      client.onEvent((e) => this.emit('event', e));
      await client.subscribe();
      this.setState('connected');
    } catch {
      this.client = undefined;
      this.setState('not_running');
      this.retry();
    } finally {
      this.connecting = false;
    }
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
