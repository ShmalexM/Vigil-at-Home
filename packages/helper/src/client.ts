// Client used by the Vigil app (running as the user) to talk to the helper.
//
//   const helper = await HelperClient.connect();
//   await helper.call({ kind: 'process.suspend', pid, path });
//   await helper.call({ kind: 'process.resume', pid });   // shows the macOS password dialog
//   helper.onEvent((e) => ...); await helper.subscribe();

import { connect, type Socket } from 'node:net';
import { execFile } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import type { SensorEvent } from '@vigil/sensors';
import type { HelperCommand, HelperResponse } from './protocol.js';
import type { HelperRan } from './fastpath.js';
import { approvalAppleScript } from './approval.js';
import { defaultPaths } from './config.js';

export class HelperCallError extends Error {
  constructor(
    message: string,
    readonly code?: string,
  ) {
    super(message);
  }
}

/**
 * Shows macOS's admin password dialog; resolves true if the user approved.
 * `also` are more commands' nonces the same password approves.
 */
export type Approver = (nonce: string, prompt: string, also?: string[]) => Promise<boolean>;

export function osascriptApprover(helperExecutable = defaultPaths().helperExecutable): Approver {
  return (nonce, prompt, also = []) =>
    new Promise((resolve) => {
      execFile(
        '/usr/bin/osascript',
        ['-e', approvalAppleScript(helperExecutable, [nonce, ...also], prompt)],
        (err) => resolve(!err),
      );
    });
}

/** A command waiting on approval that the next password dialog also asks for. */
interface Held {
  command: HelperCommand;
  nonce: string;
  prompt: string;
  approved: boolean;
  settle: (r: HelperResponse | HelperCallError) => void;
}

function result<T>(resp: HelperResponse): T {
  if (resp.ok) return resp.result as T;
  if ('needsApproval' in resp) throw new HelperCallError('approval was not accepted', 'refused');
  throw new HelperCallError(resp.error, resp.code);
}

export class HelperClient {
  private buf = '';
  private readonly pending = new Map<string, (r: HelperResponse) => void>();
  private readonly listeners = new Set<(e: SensorEvent, ran: HelperRan[]) => void>();
  private held: Held[] = [];

  private constructor(
    private readonly sock: Socket,
    private readonly approver: Approver,
  ) {
    sock.setEncoding('utf8');
    sock.on('data', (chunk: string) => this.onData(chunk));
    sock.on('close', () => {
      for (const resolve of this.pending.values())
        resolve({ id: '', ok: false, error: 'helper connection closed', code: 'failed' });
      this.pending.clear();
      for (const h of this.held)
        h.settle(new HelperCallError('helper connection closed', 'failed'));
      this.held = [];
    });
  }

  static connect(
    socketPath = defaultPaths().socket,
    approver: Approver = osascriptApprover(),
  ): Promise<HelperClient> {
    return new Promise((resolve, reject) => {
      const sock = connect(socketPath);
      sock.once('connect', () => resolve(new HelperClient(sock, approver)));
      sock.once('error', reject);
    });
  }

  close(): void {
    this.sock.end();
  }

  /** `ran` lists what the helper's own rules already did about the event. */
  onEvent(fn: (e: SensorEvent, ran: HelperRan[]) => void): () => void {
    this.listeners.add(fn);
    return () => this.listeners.delete(fn);
  }

  async subscribe(since?: string): Promise<void> {
    await this.call(since ? { kind: 'events.subscribe', since } : { kind: 'events.subscribe' });
  }

  /**
   * Send a command; if it needs approval, show the password dialog once and
   * retry. The dialog also approves any held commands (hold()).
   */
  async call<T = unknown>(command: HelperCommand): Promise<T> {
    let resp = await this.send(command);
    if (!resp.ok && 'needsApproval' in resp) {
      const waiting = this.held.filter((h) => !h.approved);
      const prompt = [resp.prompt, ...waiting.map((h) => h.prompt)].join(' ');
      const approved = await this.approver(
        resp.nonce,
        prompt,
        waiting.map((h) => h.nonce),
      );
      if (!approved) {
        // A "no" covers the held commands it asked about too: never ask twice.
        this.held = this.held.filter((h) => !waiting.includes(h));
        for (const h of waiting) h.settle(new HelperCallError('not approved', 'refused'));
        throw new HelperCallError('not approved', 'refused');
      }
      for (const h of waiting) h.approved = true;
      resp = await this.send(command, resp.nonce);
    }
    return result<T>(resp);
  }

  /**
   * Send a command that may need approval without asking yet. If it needs
   * none, it settles now. Otherwise it waits: the next password dialog, from
   * call() or approveHeld(), asks for it too, so a release and the rule
   * change that comes with it take one password. `onHeld` says when it is
   * waiting, so the caller knows the next dialog will include it. Call
   * approveHeld() after.
   */
  async hold<T = unknown>(command: HelperCommand, onHeld?: () => void): Promise<T> {
    const resp = await this.send(command);
    if (resp.ok || !('needsApproval' in resp)) return result<T>(resp);
    const settled = await new Promise<HelperResponse | HelperCallError>((settle) => {
      this.held.push({ command, nonce: resp.nonce, prompt: resp.prompt, approved: false, settle });
      onHeld?.();
    });
    if (settled instanceof HelperCallError) throw settled;
    return result<T>(settled);
  }

  /** Ask once for every held command not yet approved, then send them all. */
  async approveHeld(): Promise<void> {
    const held = this.held;
    this.held = [];
    const waiting = held.filter((h) => !h.approved);
    let approved = true;
    if (waiting.length) {
      const [first, ...rest] = waiting;
      approved = await this.approver(
        first!.nonce,
        waiting.map((h) => h.prompt).join(' '),
        rest.map((h) => h.nonce),
      ).catch(() => false);
    }
    for (const h of held) {
      if (!h.approved && !approved) h.settle(new HelperCallError('not approved', 'refused'));
      else h.settle(await this.send(h.command, h.nonce));
    }
  }

  /** Refuse every held command without asking, approved or not. */
  dropHeld(): void {
    const held = this.held;
    this.held = [];
    for (const h of held) h.settle(new HelperCallError('not sent', 'refused'));
  }

  private send(command: HelperCommand, approval?: string): Promise<HelperResponse> {
    const id = randomBytes(8).toString('hex');
    return new Promise((resolve) => {
      this.pending.set(id, resolve);
      this.sock.write(JSON.stringify({ id, command, ...(approval ? { approval } : {}) }) + '\n');
    });
  }

  private onData(chunk: string): void {
    this.buf += chunk;
    let nl: number;
    while ((nl = this.buf.indexOf('\n')) >= 0) {
      const line = this.buf.slice(0, nl);
      this.buf = this.buf.slice(nl + 1);
      let msg: { type?: string; event?: SensorEvent; ran?: HelperRan[]; id?: string } | undefined;
      try {
        msg = JSON.parse(line);
      } catch {
        continue;
      }
      if (msg?.type === 'event') {
        const ran = Array.isArray(msg.ran) ? msg.ran : [];
        for (const fn of this.listeners) fn(msg.event as SensorEvent, ran);
        continue;
      }
      const id = msg?.id;
      const resolve = id === undefined ? undefined : this.pending.get(id);
      if (id !== undefined && resolve) {
        this.pending.delete(id);
        resolve(msg as HelperResponse);
      }
    }
  }
}
