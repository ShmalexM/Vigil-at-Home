import { createHash } from 'node:crypto';
import { mkdtempSync, readdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { connect, createServer, type Server, type Socket } from 'node:net';
import { homedir, tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { HookHello, PreflightRequest } from '@vigil/core';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  LIMITS,
  parseArgs,
  render,
  runHello,
  runPreflight,
  toRequest,
  type HookIO,
  type OnUnavailable,
} from './hook.js';

// Every node:fs call made while the hook runs is recorded, to show it reads no files.
const { fsCalls, recording } = vi.hoisted(() => {
  const fsCalls: string[] = [];
  const recording = (mod: Record<string, unknown>, name: string) => {
    const wrap = (obj: Record<string, unknown>) =>
      Object.fromEntries(
        Object.entries(obj).map(([k, v]) => [
          k,
          typeof v === 'function' && /^[a-z]/.test(k)
            ? (...a: unknown[]) => {
                fsCalls.push(`${name}.${k}`);
                return (v as (...a: unknown[]) => unknown).apply(obj, a);
              }
            : v,
        ]),
      );
    return { ...wrap(mod), default: wrap((mod.default ?? mod) as Record<string, unknown>) };
  };
  return { fsCalls, recording };
});
vi.mock('node:fs', async (load) => recording(await load(), 'fs'));
vi.mock('node:fs/promises', async (load) => recording(await load(), 'fs/promises'));

const SOCKET_DIR = () => mkdtempSync(join(tmpdir(), 'vh-'));

const servers: Server[] = [];
afterEach(async () => {
  await Promise.all(servers.splice(0).map((s) => new Promise((r) => s.close(r))));
});

/** A stand-in for Vigil: answers each request line with `reply(line)`, after `delayMs`. */
async function stub(reply: (line: string) => string | undefined, delayMs = 0) {
  const path = join(SOCKET_DIR(), 'agent.sock');
  const lines: string[] = [];
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
        const line = buf.slice(0, nl);
        buf = buf.slice(nl + 1);
        lines.push(line);
        const out = reply(line);
        if (out === undefined) continue;
        // A reply without an end of line is sent and the connection closed.
        const send = () =>
          !sock.destroyed && (out.endsWith('\n') ? sock.write(out) : sock.end(out));
        if (delayMs) setTimeout(send, delayMs);
        else send();
      }
    });
  });
  const close = server.close.bind(server);
  server.close = ((cb?: (err?: Error) => void) => {
    for (const c of conns) c.destroy();
    return close(cb);
  }) as typeof server.close;
  servers.push(server);
  await new Promise<void>((r) => server.listen(path, r));
  return { path, lines };
}

const realConnect = (path: string) =>
  new Promise<Socket>((resolve, reject) => {
    const sock = connect(path);
    sock.once('connect', () => resolve(sock));
    sock.once('error', reject);
  });

function io(input: unknown): HookIO & { out: string[] } {
  const out: string[] = [];
  const bytes = Buffer.from(typeof input === 'string' ? input : JSON.stringify(input));
  return {
    out,
    stdin: (async function* () {
      yield bytes;
    })(),
    write: (s) => out.push(s),
    connect: realConnect,
  };
}

const bashInput = (command = 'git status') => ({
  session_id: 'abc-123',
  hook_event_name: 'PreToolUse',
  cwd: '/Users/alex/code/app',
  tool_name: 'Bash',
  tool_input: { command, description: 'Show the status' },
});

const reply = (r: object) => JSON.stringify({ v: 1, ...r }) + '\n';

const answer = (decision: 'deny' | 'ask', reason: string) =>
  JSON.stringify({
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      permissionDecision: decision,
      permissionDecisionReason: reason,
    },
  });
const UNAVAILABLE = answer('ask', "Vigil couldn't check this step");

/** What the hook may print: nothing, or Claude Code's deny or ask answer. */
function expectHookOutput(out: string[]): void {
  const text = out.join('');
  if (text === '') return;
  const parsed = JSON.parse(text) as { hookSpecificOutput: Record<string, unknown> };
  expect(Object.keys(parsed)).toEqual(['hookSpecificOutput']);
  expect(Object.keys(parsed.hookSpecificOutput).sort()).toEqual([
    'hookEventName',
    'permissionDecision',
    'permissionDecisionReason',
  ]);
  expect(parsed.hookSpecificOutput.hookEventName).toBe('PreToolUse');
  expect(['deny', 'ask']).toContain(parsed.hookSpecificOutput.permissionDecision);
  expect(text).not.toMatch(/allow/i);
}

async function preflight(path: string, onUnavailable: OnUnavailable = 'ask', input?: unknown) {
  const h = io(input ?? bashInput());
  expect(await runPreflight(h, { socket: path, onUnavailable, ppid: 4242 })).toBe(0);
  expectHookOutput(h.out);
  return h.out.join('');
}

/** A socket file with nothing listening on it: connecting gets ECONNREFUSED. */
async function refusingSocket(): Promise<string> {
  const path = join(SOCKET_DIR(), 'agent.sock');
  const tmp = join(dirname(path), 'tmp.sock');
  const s = createServer();
  await new Promise<void>((r) => s.listen(tmp, r));
  renameSync(tmp, path);
  await new Promise((r) => s.close(r));
  return path;
}

describe('toRequest', () => {
  it("maps a Bash call and drops everything Vigil doesn't use", () => {
    const req = toRequest(
      { ...bashInput('git push --force'), transcript_path: '/Users/alex/.claude/t.jsonl' },
      4242,
    );
    expect(req).toEqual({
      v: 1,
      method: 'preflight.check',
      host: 'claude-code',
      hookSession: 'abc-123',
      ppid: 4242,
      cwd: '/Users/alex/code/app',
      tool: 'Bash',
      command: 'git push --force',
      commandBytes: 16,
    });
    expect(PreflightRequest.parse(req)).toEqual(req);
  });

  it('clips a long command and keeps its full size in bytes', () => {
    const command = 'echo ' + 'é'.repeat(5000);
    const req = toRequest(bashInput(command), 1)!;
    expect(req.command).toHaveLength(LIMITS.commandChars);
    expect(req.command).toBe(command.slice(0, 4096));
    expect(req.commandBytes).toBe(5 + 2 * 5000);
  });

  it('sends the size and SHA-256 of what would be written, never the text', () => {
    const content = 'AWS_SECRET_ACCESS_KEY=hunter2\n';
    const sha = createHash('sha256').update(content).digest('hex');
    for (const tool_input of [
      { file_path: '/Users/alex/code/app/.env', content },
      { file_path: '/Users/alex/code/app/.env', old_string: 'x', new_string: content },
      { notebook_path: '/Users/alex/code/app/n.ipynb', new_source: content },
    ]) {
      const req = toRequest({ ...bashInput(), tool_name: 'Write', tool_input }, 1)!;
      expect(req.contentBytes).toBe(Buffer.byteLength(content));
      expect(req.contentSha256).toBe(sha);
      expect(JSON.stringify(req)).not.toContain('hunter2');
      expect(req.filePath).toMatch(/^\/Users\/alex\/code\/app\//);
    }
    const multi = toRequest(
      {
        ...bashInput(),
        tool_name: 'MultiEdit',
        tool_input: {
          file_path: 'a.ts',
          edits: [
            { old_string: '1', new_string: 'one' },
            { old_string: '2', new_string: 'two' },
          ],
        },
      },
      1,
    )!;
    expect(multi.contentBytes).toBe('one\ntwo'.length);
    expect(multi.filePath).toBe('/Users/alex/code/app/a.ts');
  });

  it('resolves .. and ~ in paths against the session folder', () => {
    const read = (file_path: string, cwd = '/Users/alex/code/app') =>
      toRequest({ tool_name: 'Read', tool_input: { file_path }, cwd }, 1)?.filePath;
    expect(read('/Users/alex/code/app/../../.ssh/id_ed25519')).toBe('/Users/alex/.ssh/id_ed25519');
    expect(read('src/../../../.aws/credentials')).toBe('/Users/alex/.aws/credentials');
    expect(read('./notes.md', '/Users/alex/code/app/sub/..')).toBe('/Users/alex/code/app/notes.md');
    expect(read('~/.netrc')).toBe(join(homedir(), '.netrc'));
    expect(
      toRequest({ tool_name: 'Read', tool_input: { file_path: 'x' }, cwd: '/a/b/../c/' }, 1)?.cwd,
    ).toBe('/a/c');
  });

  it('maps URLs, MCP tools and fields of other shapes', () => {
    expect(
      toRequest({ tool_name: 'WebFetch', tool_input: { url: 'https://x.test/a', prompt: 'p' } }, 1),
    ).toEqual({
      v: 1,
      method: 'preflight.check',
      host: 'claude-code',
      ppid: 1,
      tool: 'WebFetch',
      url: 'https://x.test/a',
    });
    // An MCP tool's own fields can be anything; only strings Vigil knows are used.
    expect(
      toRequest(
        {
          tool_name: 'mcp__github__create_issue',
          tool_input: { url: { href: 'x' }, content: [{ type: 'text' }], command: 3, title: 't' },
        },
        0,
      ),
    ).toEqual({
      v: 1,
      method: 'preflight.check',
      host: 'claude-code',
      tool: 'mcp__github__create_issue',
    });
  });

  it('refuses input that names no usable tool', () => {
    expect(toRequest(undefined, 1)).toBeUndefined();
    expect(toRequest({ tool_input: { command: 'ls' } }, 1)).toBeUndefined();
    expect(toRequest({ tool_name: 'rm -rf /', tool_input: {} }, 1)).toBeUndefined();
    expect(
      toRequest({ tool_name: 'Read', tool_input: { file_path: '/' + 'a'.repeat(1100) } }, 1),
    ).toBeUndefined();
  });
});

describe('render', () => {
  it('prints deny, ask or nothing, and never allow', () => {
    for (const onUnavailable of ['ask', 'defer'] as const) {
      expect(render({ v: 1, decision: 'deny', reason: 'r' }, onUnavailable)).toBe(
        answer('deny', 'r'),
      );
      expect(render({ v: 1, decision: 'ask', reason: 'r' }, onUnavailable)).toBe(
        answer('ask', 'r'),
      );
      expect(render({ v: 1, decision: 'none' }, onUnavailable)).toBe('');
      for (const decision of ['allow', 'approve', 'block', 'ALLOW']) {
        const out = render({ v: 1, decision } as never, onUnavailable);
        expect(out).toBe(onUnavailable === 'ask' ? UNAVAILABLE : '');
      }
    }
    expect(render('unavailable', 'ask')).toBe(UNAVAILABLE);
    expect(render('unavailable', 'defer')).toBe('');
    expect(render({ v: 1, decision: 'ask', reason: 'busy' }, 'defer')).toBe(
      answer('ask', "Vigil is busy and couldn't check this step"),
    );
  });
});

describe('runPreflight', () => {
  it("prints Vigil's deny or ask, and nothing when Vigil has no opinion", async () => {
    const deny = await stub(() => reply({ decision: 'deny', reason: 'Vigil rule "X": y' }));
    expect(await preflight(deny.path)).toBe(answer('deny', 'Vigil rule "X": y'));
    const req = PreflightRequest.parse(JSON.parse(deny.lines[0]!));
    expect(req).toMatchObject({ tool: 'Bash', command: 'git status', ppid: 4242 });

    const ask = await stub(() => reply({ decision: 'ask', reason: 'Vigil rule "Z": w' }));
    expect(await preflight(ask.path)).toBe(answer('ask', 'Vigil rule "Z": w'));
    expect(await preflight(ask.path, 'defer')).toBe(answer('ask', 'Vigil rule "Z": w'));

    const none = await stub(() => reply({ decision: 'none' }));
    expect(await preflight(none.path)).toBe('');
  });

  it('asks when Vigil answers anything else, or nothing with defer', async () => {
    const answers = [
      reply({ decision: 'allow' }),
      reply({ decision: 'deny', extra: 1 }),
      reply({ decision: 'deny', reason: 'r'.repeat(301) }),
      JSON.stringify({ v: 2, decision: 'deny' }) + '\n',
      reply({ ok: true }),
      'garbage\n',
      '{"v":1,"decision":"deny"', // no end of line, then closed
    ];
    for (const a of answers) {
      const s = await stub(() => a);
      expect(await preflight(s.path)).toBe(UNAVAILABLE);
      expect(await preflight(s.path, 'defer')).toBe('');
    }
  });

  it('asks when Vigil is not there', async () => {
    const missing = join(SOCKET_DIR(), 'agent.sock'); // ENOENT
    const refusing = await refusingSocket(); // ECONNREFUSED
    const silent = (await stub(() => undefined, 0)).path;
    for (const path of [missing, refusing, '']) {
      expect(await preflight(path)).toBe(UNAVAILABLE);
      expect(await preflight(path, 'defer')).toBe('');
    }
    // A connection that stays open with no reply runs into the overall limit.
    const t0 = Date.now();
    expect(await preflight(silent)).toBe(UNAVAILABLE);
    expect(Date.now() - t0).toBeGreaterThanOrEqual(LIMITS.totalMs - 50);
  });

  it('gives up on a reply slower than 1.5 s', async () => {
    const slow = await stub(() => reply({ decision: 'deny', reason: 'late' }), 2000);
    const t0 = Date.now();
    expect(await preflight(slow.path)).toBe(UNAVAILABLE);
    const took = Date.now() - t0;
    expect(took).toBeGreaterThanOrEqual(LIMITS.totalMs - 50);
    expect(took).toBeLessThan(2000); // it did not wait for the late deny
  });

  it('asks without contacting Vigil when the input is too big or unreadable', async () => {
    const s = await stub(() => reply({ decision: 'none' }));
    const huge = bashInput('x'.repeat(LIMITS.stdinBytes));
    expect(await preflight(s.path, 'ask', huge)).toBe(UNAVAILABLE);
    expect(await preflight(s.path, 'ask', 'not json')).toBe(UNAVAILABLE);
    expect(await preflight(s.path, 'defer', 'not json')).toBe('');
    expect(s.lines).toEqual([]);
  });

  it('reads no files, not even the ones the input names', async () => {
    const dir = SOCKET_DIR();
    const conversation = join(dir, 'conversation.jsonl');
    const secret = join(dir, 'id_ed25519');
    writeFileSync(conversation, 'the whole conversation\n');
    writeFileSync(secret, 'PRIVATE KEY\n');
    const s = await stub(() => reply({ decision: 'none' }));
    const input = {
      ...bashInput(`cat ${secret}`),
      transcript_path: conversation,
      tool_name: 'Read',
      tool_input: { file_path: secret },
    };
    expect(fsCalls).toContain('fs.writeFileSync'); // the recorder is live
    fsCalls.length = 0;
    expect(await preflight(s.path, 'ask', input)).toBe('');
    await runHello(io({ session_id: 'abc', transcript_path: conversation }), { socket: s.path });
    expect(fsCalls).toEqual([]);
    expect(s.lines.join('\n')).not.toContain(conversation);
    expect(s.lines.join('\n')).not.toContain('PRIVATE KEY');
    expect(JSON.parse(s.lines[0]!)).toMatchObject({ filePath: secret });
  });
});

describe('runHello', () => {
  it('tells Vigil the hook is set up and prints nothing', async () => {
    const s = await stub(() => reply({ ok: true }));
    const h = io({ session_id: 'abc-123', hook_event_name: 'SessionStart', source: 'startup' });
    expect(await runHello(h, { socket: s.path })).toBe(0);
    expect(h.out).toEqual([]);
    expect(HookHello.parse(JSON.parse(s.lines[0]!))).toEqual({
      v: 1,
      method: 'hello',
      host: 'claude-code',
      hookVersion: '1',
      hookSession: 'abc-123',
    });
  });

  it('prints nothing when Vigil is missing, slow or garbled', async () => {
    const paths = [
      join(SOCKET_DIR(), 'agent.sock'),
      await refusingSocket(),
      (await stub(() => 'garbage\n')).path,
      (await stub(() => reply({ decision: 'deny' }))).path,
    ];
    for (const path of paths) {
      for (const input of [{ session_id: 'a' }, 'not json', '']) {
        const h = io(input);
        expect(await runHello(h, { socket: path })).toBe(0);
        expect(h.out).toEqual([]);
      }
    }
  });
});

describe('parseArgs', () => {
  it('reads the two commands the snippet runs', () => {
    expect(parseArgs(['preflight', '--socket', '/s', '--on-unavailable', 'defer'])).toEqual({
      command: 'preflight',
      socket: '/s',
      onUnavailable: 'defer',
    });
    expect(parseArgs(['preflight', '--socket', '/s', '--on-unavailable', 'allow'])).toEqual({
      command: 'preflight',
      socket: '/s',
      onUnavailable: 'ask',
    });
    expect(parseArgs(['preflight'])).toEqual({
      command: 'preflight',
      socket: '',
      onUnavailable: 'ask',
    });
    expect(parseArgs(['hello', '--socket', '/s'])).toEqual({ command: 'hello', socket: '/s' });
    expect(parseArgs(['allow'])).toEqual({ command: 'usage' });
    expect(parseArgs([])).toEqual({ command: 'usage' });
  });
});

describe('the hook package source', () => {
  const dir = new URL('./', import.meta.url);
  const sources = readdirSync(dir)
    .filter((f) => f.endsWith('.ts') && !f.endsWith('.test.ts'))
    .map((f) => ({ f, text: readFileSync(new URL(f, dir), 'utf8') }));

  it("never names the agent's settings, tokens or conversation", () => {
    expect(sources.map((s) => s.f).sort()).toEqual(['cli.ts', 'hook.ts']);
    const banned = ['settings.json', '.credentials.json', 'auth.json', 'transcript_path'];
    for (const { f, text } of sources) {
      for (const word of banned) expect(`${f}: ${text.includes(word)}`).toBe(`${f}: false`);
    }
  });

  it('imports no file-system module', () => {
    for (const { text } of sources) expect(text).not.toMatch(/from '(node:)?fs(\/promises)?'/);
  });
});
