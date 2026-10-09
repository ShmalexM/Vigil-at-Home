// The helper's local socket. Newline-delimited JSON: one HelperRequest per
// line in, one HelperResponse per line out, plus {"type":"event"} lines on
// connections that subscribed to sensor events.
//
// The socket file is owned by the logged-in user with mode 0600, so other
// accounts on the Mac cannot talk to the helper. Anything running as that
// user can, which is why releasing actions need the admin password.

import { createServer, type Server, type Socket } from 'node:net';
import { chmodSync, chownSync, rmSync } from 'node:fs';
import type { SensorEvent } from '@vigil/sensors';
import { parseRequest, type HelperResponse } from './protocol.js';
import type { Executor } from './executor.js';
import type { HelperRan } from './fastpath.js';
import { ActionError } from './commands/errors.js';

// Large enough for any command but detection.sync; still bounded.
const MAX_LINE = 1024 * 1024;
// detection.sync carries its lists' contents (up to LIST_ENTRIES_MAX each),
// so rules and lists go in force together; it alone may be this long.
const MAX_SYNC_LINE = 64 * 1024 * 1024;
const SYNC_PREFIX = /^\{"id":"[^"\\]{1,200}","command":\{"kind":"detection\.sync"/;
const RECENT_EVENTS = 2000;

export interface HelperServerOptions {
  socketPath: string;
  executor: Executor;
  /** Owner for the socket file (the console user). Skipped when undefined. */
  ownerUid?: number | undefined;
  log?: ((msg: string) => void) | undefined;
}

export class HelperServer {
  private server: Server | undefined;
  private readonly subscribers = new Set<Socket>();
  private readonly connections = new Set<Socket>();
  private readonly recent: string[] = [];
  private readonly recentIds: string[] = [];

  constructor(private readonly opts: HelperServerOptions) {}

  async listen(): Promise<void> {
    rmSync(this.opts.socketPath, { force: true });
    this.server = createServer((sock) => this.onConnection(sock));
    await new Promise<void>((resolve, reject) => {
      this.server!.once('error', reject);
      this.server!.listen(this.opts.socketPath, () => resolve());
    });
    chmodSync(this.opts.socketPath, 0o600);
    if (this.opts.ownerUid !== undefined) chownSync(this.opts.socketPath, this.opts.ownerUid, 0);
  }

  async close(): Promise<void> {
    for (const s of this.connections) s.destroy();
    await new Promise<void>((resolve) =>
      this.server ? this.server.close(() => resolve()) : resolve(),
    );
    rmSync(this.opts.socketPath, { force: true });
  }

  /**
   * Fan a sensor event out to subscribed connections and keep it for late
   * subscribers, with whatever the helper's own rules already did about it.
   */
  publish(event: SensorEvent, ran: HelperRan[] = []): void {
    const line =
      JSON.stringify(ran.length ? { type: 'event', event, ran } : { type: 'event', event }) + '\n';
    this.recent.push(line);
    this.recentIds.push(event.id);
    if (this.recent.length > RECENT_EVENTS) {
      this.recent.shift();
      this.recentIds.shift();
    }
    for (const s of this.subscribers) {
      // A subscriber that stops reading must not make the helper buffer forever.
      if (s.writableLength > 8 * 1024 * 1024) s.destroy();
      else s.write(line);
    }
  }

  private onConnection(sock: Socket): void {
    let buf = '';
    this.connections.add(sock);
    sock.setEncoding('utf8');
    sock.on('data', (chunk: string) => {
      buf += chunk;
      // Only the new chunk can end the line, so a long sync isn't rescanned per chunk.
      if (!chunk.includes('\n')) {
        if (buf.length > MAX_LINE) {
          const max = SYNC_PREFIX.test(buf.slice(0, 400)) ? MAX_SYNC_LINE : MAX_LINE;
          if (buf.length > max) sock.destroy();
        }
        return;
      }
      let nl: number;
      while ((nl = buf.indexOf('\n')) >= 0) {
        const line = buf.slice(0, nl);
        buf = buf.slice(nl + 1);
        if (line.trim()) void this.onLine(sock, line);
      }
    });
    const forget = () => {
      this.subscribers.delete(sock);
      this.connections.delete(sock);
    };
    sock.on('close', forget);
    sock.on('error', forget);
  }

  private send(sock: Socket, resp: HelperResponse): void {
    if (!sock.destroyed) sock.write(JSON.stringify(resp) + '\n');
  }

  private async onLine(sock: Socket, line: string): Promise<void> {
    const req = parseRequest(line);
    if ('error' in req) {
      this.send(sock, { id: req.id ?? '', ok: false, error: req.error, code: 'invalid' });
      return;
    }
    if (req.command.kind === 'events.subscribe') {
      const since = req.command.since;
      const start = since ? this.recentIds.indexOf(since) + 1 : this.recent.length;
      this.send(sock, { id: req.id, ok: true, result: { subscribed: true } });
      for (const line of this.recent.slice(start)) sock.write(line);
      this.subscribers.add(sock);
      return;
    }
    try {
      const out = await this.opts.executor.execute(req.command, req.approval);
      if (out.kind === 'needs_approval') {
        this.send(sock, {
          id: req.id,
          ok: false,
          needsApproval: true,
          nonce: out.nonce,
          prompt: out.prompt,
        });
      } else {
        this.send(sock, { id: req.id, ok: true, result: out.result });
      }
    } catch (err) {
      const code = err instanceof ActionError ? err.code : 'failed';
      if (!(err instanceof ActionError))
        this.opts.log?.(`${req.command.kind} failed: ${(err as Error).stack}`);
      this.send(sock, { id: req.id, ok: false, error: (err as Error).message, code });
    }
  }
}
