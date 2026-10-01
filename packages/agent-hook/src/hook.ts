// The pre-flight hook. Claude Code runs it before a tool call (PreToolUse) and
// when a session starts (SessionStart). It asks Vigil over the agent socket
// and prints Claude Code's answer:
//
//   preflight  a deny or ask answer, or nothing when Vigil has no opinion
//   hello      tells Vigil the hook is set up; prints nothing, ever
//
// It never prints allow (in Claude Code, allow skips the user's own
// permission prompt) and reads no files: everything it knows comes from its
// stdin and the socket. Of what a tool would write it sends only the size
// and SHA-256, never the text.

import { createHash } from 'node:crypto';
import { homedir } from 'node:os';
import { resolve } from 'node:path';
import type { Duplex } from 'node:stream';
import { PreflightReply, PreflightRequest, type HookHello } from '@vigil/core';
import { z } from 'zod';

/** Sent with hello, so Vigil can tell an outdated hook from a current one. */
export const HOOK_VERSION = '1';

export const LIMITS = {
  /** Claude Code's input for one tool call. Anything bigger is not checked. */
  stdinBytes: 256 * 1024,
  connectMs: 250,
  /** From start to answer, stdin included. */
  totalMs: 1500,
  replyBytes: 64 * 1024,
  /** Vigil checks this much of a command; longer ones are flagged by their size. */
  commandChars: 4096,
  urlChars: 2048,
  hookSessionChars: 128,
} as const;

/** What the hook needs from the outside world, so tests can stand in for it. */
export interface HookIO {
  stdin: AsyncIterable<Buffer>;
  write(s: string): void;
  connect(path: string): Promise<Duplex>;
}

export type OnUnavailable = 'ask' | 'defer';

/** A string, or nothing when the host sent something else (an MCP tool's own fields). */
const text = z.string().optional().catch(undefined);

/**
 * The parts of Claude Code's hook input Vigil uses. Every other key, the
 * conversation's own file among them, is dropped here and never looked at.
 */
const HookInput = z.object({
  tool_name: z.string(),
  tool_input: z
    .object({
      command: text,
      file_path: text,
      notebook_path: text,
      url: text,
      content: text,
      new_string: text,
      new_source: text,
      edits: z
        .array(z.object({ new_string: z.string() }))
        .optional()
        .catch(undefined),
    })
    .optional()
    .catch(undefined),
  session_id: text,
  cwd: text,
});

const SessionInput = z.object({ session_id: text });

function parseJson(s: string): unknown {
  try {
    return JSON.parse(s);
  } catch {
    return undefined;
  }
}

function expandHome(p: string): string {
  return p === '~' || p.startsWith('~/') ? homedir() + p.slice(1) : p;
}

/**
 * Claude Code's hook input as a pre-flight request, or undefined when it
 * isn't one Vigil can check. Paths are made absolute against the session's
 * folder with `..` resolved, so rules see the file the tool would touch.
 */
export function toRequest(input: unknown, ppid: number): PreflightRequest | undefined {
  const parsed = HookInput.safeParse(input);
  if (!parsed.success) return undefined;
  const { tool_name, tool_input: ti, session_id, cwd } = parsed.data;
  const req: PreflightRequest = {
    v: 1,
    method: 'preflight.check',
    host: 'claude-code',
    tool: tool_name,
  };
  if (session_id) req.hookSession = session_id.slice(0, LIMITS.hookSessionChars);
  if (Number.isSafeInteger(ppid) && ppid > 0) req.ppid = ppid;
  const dir = cwd ? resolve(cwd) : undefined;
  if (dir) req.cwd = dir;
  if (ti?.command !== undefined) {
    req.command = ti.command.slice(0, LIMITS.commandChars);
    req.commandBytes = Buffer.byteLength(ti.command);
  }
  const file = ti?.file_path || ti?.notebook_path;
  if (file) req.filePath = dir ? resolve(dir, expandHome(file)) : resolve(expandHome(file));
  if (ti?.url !== undefined) req.url = ti.url.slice(0, LIMITS.urlChars);
  const content =
    ti?.content ??
    ti?.new_string ??
    ti?.new_source ??
    ti?.edits?.map((e) => e.new_string).join('\n');
  if (content !== undefined) {
    req.contentBytes = Buffer.byteLength(content);
    req.contentSha256 = createHash('sha256').update(content).digest('hex');
  }
  const ok = PreflightRequest.safeParse(req);
  return ok.success ? ok.data : undefined;
}

const UNAVAILABLE = "Vigil couldn't check this step";
const BUSY = "Vigil is busy and couldn't check this step";

function answer(decision: 'deny' | 'ask', reason: string): string {
  return JSON.stringify({
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      permissionDecision: decision,
      permissionDecisionReason: reason,
    },
  });
}

/**
 * What the hook prints: Claude Code's deny or ask answer, or '' to leave the
 * step to Claude Code's own permissions. There is no way to print allow.
 */
export function render(r: PreflightReply | 'unavailable', onUnavailable: OnUnavailable): string {
  if (r === 'unavailable') return onUnavailable === 'defer' ? '' : answer('ask', UNAVAILABLE);
  switch (r.decision) {
    case 'deny':
      return answer('deny', r.reason ?? 'Stopped by a Vigil rule');
    case 'ask':
      return answer('ask', r.reason === 'busy' ? BUSY : (r.reason ?? 'A Vigil rule asks first'));
    case 'none':
      return '';
    default:
      return render('unavailable', onUnavailable);
  }
}

class Timeout extends Error {}

/** `p`, or a Timeout after `ms`. A result that arrives late goes to `late`, to be closed. */
export function within<T>(p: Promise<T>, ms: number, late?: (v: T) => void): Promise<T> {
  return new Promise<T>((done, fail) => {
    let expired = false;
    const timer = setTimeout(
      () => {
        expired = true;
        fail(new Timeout('timed out'));
      },
      Math.max(0, ms),
    );
    p.then(
      (v) => {
        clearTimeout(timer);
        if (expired) late?.(v);
        else done(v);
      },
      (err: unknown) => {
        clearTimeout(timer);
        fail(err);
      },
    );
  });
}

/** All of stdin, or undefined when it is over the limit. */
async function readInput(stdin: AsyncIterable<Buffer>): Promise<string | undefined> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of stdin) {
    size += chunk.length;
    if (size > LIMITS.stdinBytes) return undefined;
    chunks.push(chunk);
  }
  return Buffer.concat(chunks, size).toString('utf8');
}

function readLine(sock: Duplex): Promise<string> {
  return new Promise<string>((done, fail) => {
    let buf = '';
    sock.setEncoding('utf8');
    sock.on('data', (chunk: string) => {
      buf += chunk;
      const nl = buf.indexOf('\n');
      if (nl >= 0) done(buf.slice(0, nl));
      else if (buf.length > LIMITS.replyBytes) fail(new Error('reply too long'));
    });
    sock.once('end', () => fail(new Error('closed without a reply')));
    sock.once('close', () => fail(new Error('closed without a reply')));
    sock.once('error', fail);
  });
}

/** One request line out, one reply line back, within the connect and overall limits. */
async function exchange(
  io: HookIO,
  socket: string,
  request: PreflightRequest | HookHello,
  until: number,
): Promise<unknown> {
  if (!socket) throw new Error('no socket');
  const sock = await within(
    io.connect(socket),
    Math.min(LIMITS.connectMs, until - Date.now()),
    (late) => late.destroy(),
  );
  // Errors end the wait in readLine; they must never crash the hook.
  sock.on('error', () => {});
  try {
    const reply = readLine(sock);
    sock.write(JSON.stringify(request) + '\n');
    return JSON.parse(await within(reply, until - Date.now()));
  } finally {
    sock.destroy();
  }
}

/**
 * PreToolUse: ask Vigil about the tool call on stdin and print the answer.
 * When Vigil is missing, slow or answers anything but a valid reply, the
 * answer is ask, or nothing with `onUnavailable: 'defer'`. Never throws.
 */
export async function runPreflight(
  io: HookIO,
  o: { socket: string; onUnavailable: OnUnavailable; ppid: number },
): Promise<0> {
  const until = Date.now() + LIMITS.totalMs;
  let reply: PreflightReply | 'unavailable' = 'unavailable';
  try {
    const input = await within(readInput(io.stdin), LIMITS.totalMs);
    const req = input === undefined ? undefined : toRequest(parseJson(input), o.ppid);
    if (req) {
      const parsed = PreflightReply.safeParse(await exchange(io, o.socket, req, until));
      if (parsed.success) reply = parsed.data;
    }
  } catch {
    // Not there, too slow or garbled: Vigil is unavailable for this step.
  }
  const out = render(reply, o.onUnavailable);
  if (out) io.write(out);
  return 0;
}

/**
 * SessionStart: tell Vigil the hook is set up. Prints nothing, whatever
 * happens, because Claude Code adds SessionStart output to the agent's context.
 */
export async function runHello(io: HookIO, o: { socket: string }): Promise<0> {
  const until = Date.now() + LIMITS.totalMs;
  try {
    const input = await within(readInput(io.stdin), LIMITS.totalMs);
    const session =
      input === undefined ? undefined : SessionInput.safeParse(parseJson(input)).data?.session_id;
    const hello: HookHello = {
      v: 1,
      method: 'hello',
      host: 'claude-code',
      hookVersion: HOOK_VERSION,
    };
    if (session) hello.hookSession = session.slice(0, LIMITS.hookSessionChars);
    await exchange(io, o.socket, hello, until);
  } catch {
    // Nothing to report: the hook stays silent.
  }
  return 0;
}

export type HookArgs =
  | { command: 'preflight'; socket: string; onUnavailable: OnUnavailable }
  | { command: 'hello'; socket: string }
  | { command: 'mcp'; socket: string }
  | { command: 'usage' };

/**
 * `preflight --socket <path> [--on-unavailable ask|defer]`, `hello --socket <path>`
 * or `mcp --socket <path>` (Vigil's read-only tools as an MCP server, mcp.ts).
 */
export function parseArgs(argv: readonly string[]): HookArgs {
  const option = (name: string) => {
    const i = argv.indexOf(name);
    return i >= 0 ? argv[i + 1] : undefined;
  };
  const socket = option('--socket') ?? '';
  switch (argv[0]) {
    case 'preflight':
      return {
        command: 'preflight',
        socket,
        onUnavailable: option('--on-unavailable') === 'defer' ? 'defer' : 'ask',
      };
    case 'hello':
      return { command: 'hello', socket };
    case 'mcp':
      return { command: 'mcp', socket };
    default:
      return { command: 'usage' };
  }
}
