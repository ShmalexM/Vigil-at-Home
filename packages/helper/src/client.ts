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

/** Shows macOS's admin password dialog; resolves true if the user approved. */
export type Approver = (nonce: string, prompt: string) => Promise<boolean>;

export function osascriptApprover(helperExecutable = defaultPaths().helperExecutable): Approver {
  return (nonce, prompt) =>
    new Promise((resolve) => {
      execFile(
        '/usr/bin/osascript',
        ['-e', approvalAppleScript(helperExecutable, nonce, prompt)],
        (err) => resolve(!err),
      );
    });
}

export class HelperClient {
  private buf = '';
  private readonly pending = new Map<string, (r: HelperResponse) => void>();
  private readonly listeners = new Set<(e: SensorEvent) => void>();

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

  onEvent(fn: (e: SensorEvent) => void): () => void {
    this.listeners.add(fn);
    return () => this.listeners.delete(fn);
  }

  async subscribe(since?: string): Promise<void> {
    await this.call(since ? { kind: 'events.subscribe', since } : { kind: 'events.subscribe' });
  }

  /** Send a command; if it needs approval, show the password dialog once and retry. */
  async call<T = unknown>(command: HelperCommand): Promise<T> {
    let resp = await this.send(command);
    if (!resp.ok && 'needsApproval' in resp) {
      const approved = await this.approver(resp.nonce, resp.prompt);
      if (!approved) throw new HelperCallError('not approved', 'refused');
      resp = await this.send(command, resp.nonce);
    }
    if (resp.ok) return resp.result as T;
    if ('needsApproval' in resp) throw new HelperCallError('approval was not accepted', 'refused');
    throw new HelperCallError(resp.error, resp.code);
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
      let msg: { type?: string; event?: SensorEvent; id?: string } | undefined;
      try {
        msg = JSON.parse(line);
      } catch {
        continue;
      }
      if (msg?.type === 'event') {
        for (const fn of this.listeners) fn(msg.event as SensorEvent);
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
