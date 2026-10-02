// The pre-flight hook as Claude Code runs it: the command from the snippet,
// through a shell, on node, from the bundle the app ships. Whatever happens,
// it exits 0, and on any failure it asks (or, with defer, prints nothing).

import { spawn } from 'node:child_process';
import { mkdtempSync, renameSync, rmSync } from 'node:fs';
import { createServer, type Socket } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { build } from 'esbuild';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { BUNDLE_OPTIONS } from '../../../scripts/bundle-options.mjs';
import { hookSnippet } from './hook-snippet.js';

const REPO = join(import.meta.dirname, '..', '..', '..', '..', '..');
let dir: string;
let hookPath: string;

beforeAll(async () => {
  dir = mkdtempSync(join(tmpdir(), 'vhp-'));
  hookPath = join(dir, 'vigil-hook.mjs');
  await build({
    ...BUNDLE_OPTIONS,
    entryPoints: [join(REPO, 'packages/agent-hook/src/cli.ts')],
    outfile: hookPath,
    logLevel: 'error',
  });
}, 30_000);

afterAll(() => rmSync(dir, { recursive: true, force: true }));

const stops: Array<() => Promise<unknown>> = [];
afterEach(async () => {
  for (const stop of stops.splice(0)) await stop();
});

let socketN = 0;
const socketPath = () => join(dir, `s${socketN++}.sock`);

/** A socket that answers each request line with `reply(line)`, or with nothing. */
async function stub(reply: (line: string) => string | undefined): Promise<string> {
  const path = socketPath();
  const conns = new Set<Socket>();
  const server = createServer((sock) => {
    conns.add(sock);
    sock.on('error', () => {});
    sock.on('close', () => conns.delete(sock));
    let buf = '';
    sock.setEncoding('utf8');
    sock.on('data', (chunk: string) => {
      buf += chunk;
      let nl: number;
      while ((nl = buf.indexOf('\n')) >= 0) {
        const out = reply(buf.slice(0, nl));
        buf = buf.slice(nl + 1);
        if (out !== undefined) sock.write(out);
      }
    });
  });
  await new Promise<void>((r) => server.listen(path, r));
  stops.push(() => {
    for (const c of conns) c.destroy();
    return new Promise((r) => server.close(r));
  });
  return path;
}

/** A socket file nothing listens on: connecting is refused. */
async function refusing(): Promise<string> {
  const bound = socketPath();
  const s = createServer();
  await new Promise<void>((r) => s.listen(bound, r));
  // Closing unlinks the bound name, so the socket file lives on under another.
  const dead = socketPath();
  renameSync(bound, dead);
  await new Promise((r) => s.close(r));
  return dead;
}

/** The two commands the snippet tells Claude Code to run. */
function commands(socket: string, onUnavailable: 'ask' | 'defer') {
  const snippet = JSON.parse(
    hookSnippet({ nodePath: process.execPath, hookPath, socketPath: socket, onUnavailable }),
  ) as {
    hooks: Record<'PreToolUse' | 'SessionStart', Array<{ hooks: Array<{ command: string }> }>>;
  };
  return {
    preflight: snippet.hooks.PreToolUse[0]!.hooks[0]!.command,
    hello: snippet.hooks.SessionStart[0]!.hooks[0]!.command,
  };
}

/** Run `command` through a shell as Claude Code does, with `input` on stdin. */
function run(
  command: string,
  input: string,
  o: { closeStdout?: boolean } = {},
): Promise<{ code: number | null; stdout: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn('/bin/sh', ['-c', command], { stdio: ['pipe', 'pipe', 'ignore'] });
    let stdout = '';
    child.stdout.setEncoding('utf8');
    child.stdout.on('data', (s: string) => (stdout += s));
    if (o.closeStdout) child.stdout.destroy();
    child.on('error', reject);
    child.on('close', (code) => resolve({ code, stdout }));
    child.stdin.on('error', () => {});
    child.stdin.end(input);
  });
}

const STEP = JSON.stringify({
  session_id: 'abc-123',
  cwd: '/Users/alex/code/app',
  hook_event_name: 'PreToolUse',
  tool_name: 'Bash',
  tool_input: { command: 'git status' },
});
const SESSION = JSON.stringify({ session_id: 'abc-123', hook_event_name: 'SessionStart' });

const answer = (decision: 'ask' | 'deny', reason: string) =>
  JSON.stringify({
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      permissionDecision: decision,
      permissionDecisionReason: reason,
    },
  });
const UNAVAILABLE = answer('ask', "Vigil couldn't check this step");

describe('the bundled hook, run from the snippet', () => {
  it('asks when Vigil is not there, or prints nothing with defer, and exits 0', async () => {
    for (const socket of [join(dir, 'missing.sock'), await refusing()]) {
      expect(await run(commands(socket, 'ask').preflight, STEP)).toEqual({
        code: 0,
        stdout: UNAVAILABLE,
      });
      expect(await run(commands(socket, 'defer').preflight, STEP)).toEqual({
        code: 0,
        stdout: '',
      });
    }
  });

  it('prints Vigil’s deny, and asks when the reply is garbage', async () => {
    const lines: string[] = [];
    const deny = await stub((line) => {
      lines.push(line);
      return (
        JSON.stringify({ v: 1, decision: 'deny', reason: 'Stopped: credentials upload' }) + '\n'
      );
    });
    expect(await run(commands(deny, 'defer').preflight, STEP)).toEqual({
      code: 0,
      stdout: answer('deny', 'Stopped: credentials upload'),
    });
    expect(JSON.parse(lines[0]!)).toMatchObject({
      method: 'preflight.check',
      tool: 'Bash',
      command: 'git status',
      hookSession: 'abc-123',
    });

    const garbage = await stub(() => 'not json\n');
    expect(await run(commands(garbage, 'ask').preflight, STEP)).toEqual({
      code: 0,
      stdout: UNAVAILABLE,
    });
    expect(await run(commands(garbage, 'defer').preflight, STEP)).toEqual({
      code: 0,
      stdout: '',
    });
  });

  it('prints nothing for hello, whether or not Vigil answers', async () => {
    const ok = await stub(() => JSON.stringify({ v: 1, ok: true }) + '\n');
    for (const socket of [ok, join(dir, 'missing.sock')]) {
      expect(await run(commands(socket, 'ask').hello, SESSION)).toEqual({ code: 0, stdout: '' });
    }
  });

  it('exits 0 with nothing on stdout for a command it doesn’t know', async () => {
    const node = JSON.stringify(process.execPath);
    expect(await run(`${node} ${JSON.stringify(hookPath)} frobnicate`, '')).toEqual({
      code: 0,
      stdout: '',
    });
  });

  it('exits 0 when Claude Code stops reading before the answer', async () => {
    const socket = join(dir, 'missing.sock');
    const r = await run(commands(socket, 'ask').preflight, STEP, { closeStdout: true });
    expect(r.code).toBe(0);
  });
});
