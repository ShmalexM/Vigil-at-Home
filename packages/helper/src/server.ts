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
import type { ProtectedPeer } from './appPin.js';

// Large enough for detection.sync with a full rule set; still bounded.
const MAX_LINE = 1024 * 1024;
const RECENT_EVENTS = 2000;

export interface HelperServerOptions {
  socketPath: string;
  executor: Executor;
  /** Owner for the socket file (the console user). Skipped when undefined. */
  ownerUid?: number | undefined;
  log?: ((msg: string) => void) | undefined;
  /**
   * The connected process on the connection's file descriptor, when it is
   * the app the helper was installed for (appPin.ts verifyPeer).
   */
  identifyPeer?: ((fd: number) => Promise<ProtectedPeer | undefined>) | undefined;
}

export class HelperServer {
  private server: Server | undefined;
  private readonly subscribers = new Set<Socket>();
  private readonly connections = new Set<Socket>();
  private readonly recent: string[] = [];
  private readonly recentIds: string[] = [];
  /** Verified app connections; each loses its protection when it closes. */
  private readonly verified = new Map<Socket, ProtectedPeer>();
  /** Peer checks run one at a time: each reads every process's sockets. */
  private checking: Promise<void> = Promise.resolve();

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

  /** The connected processes verified as the pinned app (appPin.ts). */
  peers(): ProtectedPeer[] {
    return [...this.verified.values()];
  }

  /**
   * Check who is on the other end, once, when the connection opens. A
   * connection that closes first is skipped, and one that closes while it is
   * checked keeps nothing, so a reused descriptor never lends its protection.
   */
  private checkPeer(sock: Socket): void {
    const identify = this.opts.identifyPeer;
    // Node keeps the descriptor on the connection's handle; there is no public accessor.
    const fd = (sock as unknown as { _handle?: { fd?: unknown } })._handle?.fd;
    if (!identify || typeof fd !== 'number' || fd < 0) return;
    this.checking = this.checking.then(async () => {
      if (!this.connections.has(sock)) return;
      let peer: ProtectedPeer | undefined;
      try {
        peer = await identify(fd);
      } catch (err) {
        this.opts.log?.(`peer check failed: ${(err as Error).message}`);
      }
      if (!peer || !this.connections.has(sock)) return;
      this.verified.set(sock, peer);
      this.opts.log?.(`the app is connected as pid ${peer.pid}`);
    });
  }

  private onConnection(sock: Socket): void {
    let buf = '';
    this.connections.add(sock);
    this.checkPeer(sock);
    sock.setEncoding('utf8');
    sock.on('data', (chunk: string) => {
      buf += chunk;
      if (buf.length > MAX_LINE && !buf.includes('\n')) {
        sock.destroy();
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
      this.verified.delete(sock);
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
