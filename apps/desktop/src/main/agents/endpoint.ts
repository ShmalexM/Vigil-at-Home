// The agent bridge: a Unix socket in Vigil's own folder where the pre-flight
// hook (packages/agent-hook) asks about a tool call before Claude Code runs it.
//
// Newline-delimited JSON: one AgentBridgeRequest per line in, one reply line
// out. The socket is 0600 inside a 0700 folder, so other accounts on the Mac
// can't reach it. Anything running as the user can, so it changes nothing and
// answers only deny, ask or nothing, never allow. Answers come from rules
// alone: `handle` is synchronous, and nothing here reaches the AI or the
// scheduler. Whatever goes wrong, the answer is ask.

import { createConnection, createServer, type Server, type Socket } from 'node:net';
import { chmodSync, lstatSync, mkdirSync, rmSync } from 'node:fs';
import { dirname, join } from 'node:path';
import {
  AgentBridgeRequest,
  HelloReply,
  PreflightReply,
  type HookHello,
  type PreflightRequest,
  type ToolsReply,
} from '@vigil/core';

/** The requests `handle` answers. Vigil's tools for agents (tools.*) are refused until they exist. */
export type EndpointRequest = PreflightRequest | HookHello;
export type EndpointReply = PreflightReply | HelloReply | ToolsReply;

export interface AgentEndpointOptions {
  socketPath: string;
  /** Answers one request, synchronously: the reply is written before anything else runs. */
  handle(req: EndpointRequest): PreflightReply | HelloReply;
  /** Open connections at most; more are closed unanswered. Default 16. */
  maxConnections?: number;
  /** Requests per second over all connections, after a burst. Defaults 30 and 60. */
  ratePerSec?: number;
  burst?: number;
  /** A connection that sends nothing for this long is closed. Default 2 s. */
  idleMs?: number;
  /** Longest request line. Default 64 KB. */
  maxLine?: number;
  now?: () => number;
  log?: (msg: string) => void;
}

export interface AgentEndpointStatus {
  state: 'off' | 'listening' | 'error';
  error?: string;
  socketPath: string;
}

/** Longest socket path used as is; macOS allows 104 bytes in all. */
export const MAX_SOCKET_PATH = 100;

/**
 * Where the socket lives: `<userData>/run/agent.sock`, or a folder of the
 * user's own under the temporary folder when that path is too long for a
 * Unix socket.
 */
export function socketPathFor(userData: string, tmpdir: string, uid: number): string {
  const path = join(userData, 'run', 'agent.sock');
  return Buffer.byteLength(path) <= MAX_SOCKET_PATH
    ? path
    : join(tmpdir, `vigil-${uid}`, 'agent.sock');
}

const ask = (reason: string): PreflightReply => ({ v: 1, decision: 'ask', reason });
const UNREADABLE = ask('Vigil could not read this request');
const UNANSWERED = ask('Vigil could not answer');
const BUSY = ask('busy');
const TOOLS_OFF: ToolsReply = { v: 1, ok: false, error: "Vigil's tools are off" };

/** A 0700 folder that belongs to this user, created if missing. */
function privateDir(dir: string): void {
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const st = lstatSync(dir);
  if (!st.isDirectory()) throw new Error(`${dir} is not a folder`);
  const uid = process.getuid?.();
  if (uid !== undefined && st.uid !== uid) throw new Error(`${dir} belongs to another user`);
  chmodSync(dir, 0o700);
}

/** Whether something is listening on the socket at `path`. */
function answers(path: string): Promise<boolean> {
  return new Promise((resolve) => {
    const sock = createConnection(path);
    const done = (live: boolean) => {
      clearTimeout(timer);
      sock.destroy();
      resolve(live);
    };
    const timer = setTimeout(() => done(false), 500);
    sock.once('connect', () => done(true));
    sock.once('error', () => done(false));
  });
}

/** Removes a socket left by an earlier run. Refuses anything else, or a socket still in use. */
async function clearStale(path: string): Promise<void> {
  let isSocket: boolean;
  try {
    isSocket = lstatSync(path).isSocket();
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') return;
    throw err;
  }
  if (!isSocket) throw new Error(`${path} exists and is not a socket`);
  if (await answers(path)) throw new Error(`something is already answering on ${path}`);
  rmSync(path, { force: true });
}

export class AgentEndpoint {
  private server: Server | undefined;
  private readonly connections = new Set<Socket>();
  private state: AgentEndpointStatus['state'] = 'off';
  private error: string | undefined;
  private readonly now: () => number;
  private readonly rate: number;
  private readonly burst: number;
  private tokens: number;
  private refilledAt: number;

  constructor(private readonly opts: AgentEndpointOptions) {
    this.now = opts.now ?? Date.now;
    this.rate = opts.ratePerSec ?? 30;
    this.burst = opts.burst ?? 60;
    this.tokens = this.burst;
    this.refilledAt = this.now();
  }

  /** Starts listening. Never throws: a failure shows in status(). */
  async start(): Promise<void> {
    if (this.server) return;
    const path = this.opts.socketPath;
    const server = createServer((sock) => this.onConnection(sock));
    server.maxConnections = this.opts.maxConnections ?? 16;
    try {
      privateDir(dirname(path));
      await clearStale(path);
      await new Promise<void>((resolve, reject) => {
        server.once('error', reject);
        server.listen(path, () => {
          server.off('error', reject);
          resolve();
        });
      });
      this.server = server;
      chmodSync(path, 0o600);
    } catch (err) {
      await this.stop();
      this.fail(err);
      return;
    }
    server.on('error', (err) => this.fail(err));
    this.state = 'listening';
    this.error = undefined;
  }

  async stop(): Promise<void> {
    const server = this.server;
    this.server = undefined;
    if (server) {
      for (const sock of this.connections) sock.destroy();
      await new Promise<void>((resolve) => server.close(() => resolve()));
      rmSync(this.opts.socketPath, { force: true });
    }
    this.state = 'off';
    this.error = undefined;
  }

  status(): AgentEndpointStatus {
    return {
      state: this.state,
      ...(this.error ? { error: this.error } : {}),
      socketPath: this.opts.socketPath,
    };
  }

  private fail(err: unknown): void {
    this.state = 'error';
    this.error = (err as Error).message;
    this.opts.log?.(`agent endpoint: ${this.error}`);
  }

  private onConnection(sock: Socket): void {
    const maxLine = this.opts.maxLine ?? 64 * 1024;
    let buf = '';
    let closing = false;
    this.connections.add(sock);
    sock.setEncoding('utf8');
    sock.setTimeout(this.opts.idleMs ?? 2000, () => sock.destroy());
    const tooLong = () => {
      closing = true;
      buf = '';
      sock.end(JSON.stringify(UNREADABLE) + '\n');
    };
    sock.on('data', (chunk: string) => {
      if (closing) return;
      buf += chunk;
      let nl: number;
      while ((nl = buf.indexOf('\n')) >= 0) {
        const line = buf.slice(0, nl);
        buf = buf.slice(nl + 1);
        if (line.length > maxLine) return tooLong();
        if (line.trim()) this.send(sock, this.answer(line));
      }
      if (buf.length > maxLine) tooLong();
    });
    sock.on('finish', () => {
      if (closing) sock.destroy();
    });
    const forget = () => this.connections.delete(sock);
    sock.on('close', forget);
    sock.on('error', forget);
  }

  private send(sock: Socket, reply: EndpointReply): void {
    if (!sock.destroyed && sock.writable) sock.write(JSON.stringify(reply) + '\n');
  }

  /** A token bucket over all connections: `burst` at once, then `rate` a second. */
  private take(): boolean {
    const now = this.now();
    this.tokens = Math.min(this.burst, this.tokens + ((now - this.refilledAt) * this.rate) / 1000);
    this.refilledAt = now;
    if (this.tokens < 1) return false;
    this.tokens -= 1;
    return true;
  }

  /**
   * One request line to one reply. The rate limit comes first, so a flood of
   * lines costs no parsing. The handler's reply is checked against the
   * schema for its request, so a deny, ask, none or hello is all that leaves.
   */
  private answer(line: string): EndpointReply {
    if (!this.take()) return BUSY;
    let raw: unknown;
    try {
      raw = JSON.parse(line);
    } catch {
      return UNREADABLE;
    }
    const parsed = AgentBridgeRequest.safeParse(raw);
    if (!parsed.success) return UNREADABLE;
    const req = parsed.data;
    try {
      switch (req.method) {
        case 'preflight.check': {
          const reply = PreflightReply.safeParse(this.opts.handle(req));
          if (reply.success) return reply.data;
          break;
        }
        case 'hello': {
          const reply = HelloReply.safeParse(this.opts.handle(req));
          if (reply.success) return reply.data;
          break;
        }
        case 'tools.list':
        case 'tools.call':
          return TOOLS_OFF;
      }
      this.opts.log?.(`agent endpoint: refused the reply to ${req.method}`);
    } catch (err) {
      this.opts.log?.(`agent endpoint: ${req.method} failed: ${(err as Error).message}`);
    }
    return UNANSWERED;
  }
}
