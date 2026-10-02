// The agent bridge: a Unix socket in Vigil's own folder where the pre-flight
// hook (packages/agent-hook) asks about a tool call before Claude Code runs it,
// and where the same package's MCP server asks Vigil's read-only tools for the
// user's own agents (when the user has turned them on).
//
// Newline-delimited JSON: one AgentBridgeRequest per line in, one reply line
// out. The socket is 0600 inside a 0700 folder, so other accounts on the Mac
// can't reach it. Anything running as the user can, so it changes nothing:
// a tool request gets deny, ask or nothing, never allow, and a tools call gets
// data or a refusal, never a decision. Answers come from rules and stored
// data alone: the handlers are synchronous, and nothing here reaches the AI or
// the scheduler. Whatever goes wrong, a tool request is answered ask.
//
// Anything running as the user can also delete the socket and listen on the
// path itself. Vigil can't stop that, so it notices: it watches the socket's
// folder, takes the path back and reports it (`onTamper`).

import { createConnection, createServer, type Server, type Socket } from 'node:net';
import { chmodSync, lstatSync, mkdirSync, rmSync, watch, type FSWatcher } from 'node:fs';
import { dirname, join } from 'node:path';
import {
  AgentBridgeRequest,
  HelloReply,
  PreflightReply,
  ToolsReply,
  type HookHello,
  type PreflightRequest,
  type ToolsCallRequest,
  type ToolsListRequest,
} from '@vigil/core';

/** The requests `handle` answers. */
export type EndpointRequest = PreflightRequest | HookHello;
/** The requests `tools` answers: Vigil's read-only tools for the user's own agents. */
export type ToolsRequest = ToolsListRequest | ToolsCallRequest;
export type EndpointReply = PreflightReply | HelloReply | ToolsReply;

export interface AgentEndpointOptions {
  socketPath: string;
  /** Answers one request, synchronously: the reply is written before anything else runs. */
  handle(req: EndpointRequest): PreflightReply | HelloReply;
  /** Answers tools.list and tools.call, synchronously. Without it every tools call is refused. */
  tools?(req: ToolsRequest): ToolsReply;
  /** Tools calls per connection per minute. Default 120. */
  toolsPerMinute?: number;
  /**
   * Main-thread time Vigil's tools may take, over all connections: `msPerSec`
   * comes back each second, up to `maxMs`. Defaults 50 and 150.
   */
  toolsBudget?: { msPerSec: number; maxMs: number };
  /** Times tools calls, in milliseconds. Default performance.now. */
  clock?: () => number;
  /**
   * Another program has the socket's path: it was there first (`taken`), or
   * replaced or removed Vigil's socket, which Vigil has then taken back.
   */
  onTamper?(why: SocketTamper): void;
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

export type SocketTamper = 'taken' | 'replaced' | 'removed';

export interface AgentEndpointStatus {
  state: 'off' | 'listening' | 'error';
  error?: string;
  socketPath: string;
}

/**
 * Unsent reply bytes a connection may hold. A real client reads each reply
 * before it sends its next request, so a backlog means it isn't reading.
 * Well above one 64 KB tools reply.
 */
export const MAX_UNREAD = 256 * 1024;
/** Busy replies in a row before a connection is closed: it keeps sending into a full bucket. */
export const MAX_BUSY_IN_A_ROW = 8;

/**
 * When Vigil looks at its socket again after listening, in ms. macOS starts a
 * folder watch (FSEvents) on its own thread and misses changes made before it
 * is running, so these cover that start-up.
 */
export const WATCH_SETTLE_MS = [250, 1000, 3000] as const;

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
/** Vigil's tools for agents are turned off (Agents › Tool policy). */
export const TOOLS_OFF: ToolsReply = {
  v: 1,
  ok: false,
  error: "Vigil's tools are off. Turn them on in Vigil at Home: Agents › Tool policy.",
};
const TOOLS_UNANSWERED: ToolsReply = { v: 1, ok: false, error: 'Vigil could not answer' };
/** Vigil's tools used up their share of the main thread. */
export const TOOLS_BUSY: ToolsReply = {
  v: 1,
  ok: false,
  error: 'Vigil is busy: try again in a few seconds',
};
const toolsBusy = (perMinute: number): ToolsReply => ({
  v: 1,
  ok: false,
  error: `Too many tool calls: at most ${perMinute} a minute on one connection`,
});

/** One connection's tools calls in the current minute, and its busy replies in a row. */
interface Conn {
  since: number;
  calls: number;
  busy: number;
}

/** Shown while Vigil takes its socket back from another program. */
const TAKEN_BACK = "Another program removed or replaced Vigil's agent socket";

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

/**
 * Which file is at a path. The change time is part of it because a freed
 * inode number can come back at once on some file systems (not on APFS).
 */
interface SocketId {
  dev: bigint;
  ino: bigint;
  ctime: bigint;
}
function socketId(path: string): SocketId {
  const st = lstatSync(path, { bigint: true });
  return { dev: st.dev, ino: st.ino, ctime: st.ctimeNs };
}

/** Something else is listening on the socket's path. */
class SocketInUse extends Error {}

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
  if (await answers(path)) throw new SocketInUse(`something is already answering on ${path}`);
  rmSync(path, { force: true });
}

export class AgentEndpoint {
  private server: Server | undefined;
  private readonly connections = new Set<Socket>();
  private state: AgentEndpointStatus['state'] = 'off';
  private error: string | undefined;
  private readonly now: () => number;
  private readonly clock: () => number;
  private readonly rate: number;
  private readonly burst: number;
  private tokens: number;
  private refilledAt: number;
  private readonly toolsBudget: { msPerSec: number; maxMs: number };
  private toolsMs: number;
  private toolsRefilledAt: number;
  /** The socket Vigil made, and the watch on its folder. */
  private own: SocketId | undefined;
  private watcher: FSWatcher | undefined;
  private settle: NodeJS.Timeout[] = [];
  private retaking: Promise<void> | undefined;

  constructor(private readonly opts: AgentEndpointOptions) {
    this.now = opts.now ?? Date.now;
    this.clock = opts.clock ?? (() => performance.now());
    this.rate = opts.ratePerSec ?? 30;
    this.burst = opts.burst ?? 60;
    this.tokens = this.burst;
    this.refilledAt = this.now();
    this.toolsBudget = opts.toolsBudget ?? { msPerSec: 50, maxMs: 150 };
    this.toolsMs = this.toolsBudget.maxMs;
    this.toolsRefilledAt = this.now();
  }

  /** Starts listening. Never throws: a failure shows in status(). */
  async start(): Promise<void> {
    await this.retaking;
    if (this.server) return;
    try {
      privateDir(dirname(this.opts.socketPath));
      await clearStale(this.opts.socketPath);
      await this.listen();
    } catch (err) {
      await this.stop();
      this.fail(err);
      // Vigil's single-instance lock means no other Vigil listens here.
      if (err instanceof SocketInUse) this.opts.onTamper?.('taken');
      return;
    }
    this.state = 'listening';
    this.error = undefined;
  }

  async stop(): Promise<void> {
    await this.retaking;
    const own = this.own;
    // Closing a listening socket removes its path. Should it not have, the
    // path is removed only while it still holds Vigil's own socket.
    await this.close();
    if (own && this.isOwn(own)) rmSync(this.opts.socketPath, { force: true });
    this.state = 'off';
    this.error = undefined;
  }

  get socketPath(): string {
    return this.opts.socketPath;
  }

  status(): AgentEndpointStatus {
    // One lstat, for when the folder watch missed a change.
    this.verify();
    return {
      state: this.state,
      ...(this.error ? { error: this.error } : {}),
      socketPath: this.opts.socketPath,
    };
  }

  /** Listens on the socket path, records the socket's identity and watches its folder. */
  private async listen(): Promise<void> {
    const path = this.opts.socketPath;
    const server = createServer((sock) => this.onConnection(sock));
    server.maxConnections = this.opts.maxConnections ?? 16;
    await new Promise<void>((resolve, reject) => {
      server.once('error', reject);
      server.listen(path, () => {
        server.off('error', reject);
        resolve();
      });
    });
    this.server = server;
    server.on('error', (err) => this.fail(err));
    chmodSync(path, 0o600);
    this.own = socketId(path);
    try {
      // Told by the system, not polled: the folder changes only when something
      // else touches the socket.
      this.watcher = watch(dirname(path), { persistent: false }, () => this.verify());
      this.watcher.on('error', () => {
        this.watcher?.close();
        this.watcher = undefined;
      });
    } catch {
      // status() still checks.
    }
    this.settle = WATCH_SETTLE_MS.map((ms) => setTimeout(() => this.verify(), ms).unref());
  }

  /** Stops listening and closes every connection. */
  private async close(): Promise<void> {
    this.watcher?.close();
    this.watcher = undefined;
    for (const t of this.settle.splice(0)) clearTimeout(t);
    this.own = undefined;
    const server = this.server;
    this.server = undefined;
    if (!server) return;
    for (const sock of this.connections) sock.destroy();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }

  /** Whether the path still holds the socket `own`; undefined when it can't tell. */
  private isOwn(own: SocketId): boolean | undefined {
    try {
      const now = socketId(this.opts.socketPath);
      return now.dev === own.dev && now.ino === own.ino && now.ctime === own.ctime;
    } catch (err) {
      return (err as NodeJS.ErrnoException).code === 'ENOENT' ? false : undefined;
    }
  }

  /** The socket at the path is still Vigil's; if another program removed or replaced it, take it back. */
  private verify(): void {
    if (!this.server || !this.own || this.retaking) return;
    if (this.isOwn(this.own) !== false) return;
    let why: SocketTamper = 'removed';
    try {
      lstatSync(this.opts.socketPath);
      why = 'replaced';
    } catch {
      // Gone.
    }
    this.retaking = this.takeBack(why).finally(() => (this.retaking = undefined));
  }

  /**
   * The path is Vigil's own, inside its 0700 folder, so unlike at start-up a
   * live listener there isn't left alone: Vigil removes it and listens again.
   */
  private async takeBack(why: SocketTamper): Promise<void> {
    this.state = 'error';
    this.error = TAKEN_BACK;
    this.opts.log?.(`agent endpoint: ${TAKEN_BACK} (${why}); listening again`);
    this.opts.onTamper?.(why);
    await this.close();
    try {
      privateDir(dirname(this.opts.socketPath));
      rmSync(this.opts.socketPath, { force: true });
      await this.listen();
    } catch (err) {
      await this.close();
      this.fail(err);
      return;
    }
    this.state = 'listening';
    this.error = undefined;
  }

  private fail(err: unknown): void {
    this.state = 'error';
    this.error = (err as Error).message;
    this.opts.log?.(`agent endpoint: ${this.error}`);
  }

  private onConnection(sock: Socket): void {
    const maxLine = this.opts.maxLine ?? 64 * 1024;
    const conn: Conn = { since: this.now(), calls: 0, busy: 0 };
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
        if (!line.trim()) continue;
        const reply = this.answer(line, conn);
        // A client that keeps sending into a full bucket is flooding, not waiting its turn.
        if (reply !== BUSY) conn.busy = 0;
        else if (++conn.busy >= MAX_BUSY_IN_A_ROW) return void sock.destroy();
        this.send(sock, reply);
        // Closed for not reading: the rest of the chunk goes unanswered.
        if (sock.destroyed) return;
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

  /**
   * Writes one reply, unless the client has stopped reading. A false from
   * write() alone isn't that: macOS's 8 KB socket buffer gives it for one
   * honest tools reply.
   */
  private send(sock: Socket, reply: EndpointReply): void {
    if (sock.destroyed || !sock.writable) return;
    if (sock.writableLength > MAX_UNREAD) return void sock.destroy();
    sock.write(JSON.stringify(reply) + '\n');
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

  /** Main-thread time left for Vigil's tools, over all connections. */
  private toolsTimeLeft(): boolean {
    const now = this.now();
    const { msPerSec, maxMs } = this.toolsBudget;
    this.toolsMs = Math.min(maxMs, this.toolsMs + ((now - this.toolsRefilledAt) * msPerSec) / 1000);
    this.toolsRefilledAt = now;
    return this.toolsMs > 0;
  }

  /** Room for one more tools call on this connection this minute. */
  private takeTool(w: Conn, perMinute: number): boolean {
    const now = this.now();
    if (now - w.since >= 60_000) {
      w.since = now;
      w.calls = 0;
    }
    if (w.calls >= perMinute) return false;
    w.calls += 1;
    return true;
  }

  /**
   * One request line to one reply. The rate limit comes first, so a flood of
   * lines costs no parsing. The handler's reply is checked against the
   * schema for its request, so a deny, ask, none, hello or tools reply is all
   * that leaves. Tools calls read stored data, which takes far longer than a
   * pre-flight check, so they also share a budget of main-thread time: a
   * flood of them can't hold up the hook's answers.
   */
  private answer(line: string, conn: Conn): EndpointReply {
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
        case 'tools.call': {
          if (!this.opts.tools) return TOOLS_OFF;
          if (!this.toolsTimeLeft()) return TOOLS_BUSY;
          const perMinute = this.opts.toolsPerMinute ?? 120;
          if (!this.takeTool(conn, perMinute)) return toolsBusy(perMinute);
          const t0 = this.clock();
          let out: ToolsReply;
          try {
            out = this.opts.tools(req);
          } finally {
            this.toolsMs -= this.clock() - t0;
          }
          const reply = ToolsReply.safeParse(out);
          if (reply.success) return reply.data;
          break;
        }
      }
      this.opts.log?.(`agent endpoint: refused the reply to ${req.method}`);
    } catch (err) {
      this.opts.log?.(`agent endpoint: ${req.method} failed: ${(err as Error).message}`);
    }
    return req.method === 'tools.list' || req.method === 'tools.call'
      ? TOOLS_UNANSWERED
      : UNANSWERED;
  }
}
