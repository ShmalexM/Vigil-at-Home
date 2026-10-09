import { mkdtempSync, readFileSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { WITHHELD } from '@vigil/ai/redact';
import { afterEach, describe, expect, it } from 'vitest';
import { Connectors, type ConnectorRecord } from './connectors.js';

const server = fileURLToPath(new URL('./fixtures/demo-mcp.mjs', import.meta.url));

/** Reversible stand-in for the Keychain cipher: the file must not hold the plain value. */
const cipher = {
  available: () => true,
  encrypt: (s: string) => Buffer.from(`enc:${Buffer.from(s).toString('hex')}`),
  decrypt: (b: Buffer) => Buffer.from(b.toString().slice(4), 'hex').toString(),
};

function hub(extra: Partial<ConstructorParameters<typeof Connectors>[0]> = {}) {
  let records: ConnectorRecord[] = [];
  const dir = mkdtempSync(join(tmpdir(), 'vigil-pack-'));
  const c = new Connectors({
    load: () => records,
    save: (r) => (records = r),
    secretsPath: join(dir, 'pack-secrets.json'),
    cipher,
    onChange: () => undefined,
    ...extra,
  });
  return { c, dir, records: () => records };
}

let open: Connectors[] = [];
afterEach(async () => {
  await Promise.all(open.map((c) => c.closeAll()));
  open = [];
});

describe('connectors', () => {
  it('stops a server still connecting when it is switched off, and untags it once', async () => {
    let aborted = false;
    const spawned: Array<[number, boolean]> = [];
    const { c } = hub({
      // A server stuck in its handshake: it only ends when told to.
      connect: (_r, _s, onPid, signal) => {
        onPid(4242);
        return new Promise((_res, rej) =>
          signal.addEventListener('abort', () => {
            aborted = true;
            rej(new Error('closed'));
          }),
        );
      },
      spawned: (pid, running) => spawned.push([pid, running]),
    });
    open.push(c);
    const { id } = c.add({
      kind: 'stdio',
      name: 'Slow',
      command: process.execPath,
      args: [server],
    });
    const listing = c.tools(id);
    await new Promise((r) => setTimeout(r, 0));
    c.setEnabled(id, false);
    await expect(listing).rejects.toThrow();
    await new Promise((r) => setTimeout(r, 0));
    expect(aborted).toBe(true);
    expect(spawned).toEqual([
      [4242, true],
      [4242, false],
    ]);
  });

  it('closes a server that finishes connecting after it was removed', async () => {
    let finish: (c: unknown) => void = () => undefined;
    let closed = false;
    const { c } = hub({
      connect: () => new Promise((res) => (finish = res)) as never,
    });
    open.push(c);
    const { id } = c.add({
      kind: 'stdio',
      name: 'Slow',
      command: process.execPath,
      args: [server],
    });
    const listing = c.tools(id);
    await new Promise((r) => setTimeout(r, 0));
    c.remove(id);
    finish({ close: async () => void (closed = true) });
    await expect(listing).rejects.toThrow('switched off');
    expect(closed).toBe(true);
  });

  it('lists a stdio server’s tools, with its read-only hints, and calls them', async () => {
    const spawned: Array<[number, boolean]> = [];
    const { c, dir } = hub({ spawned: (pid, running) => spawned.push([pid, running]) });
    open.push(c);
    const view = c.add({
      kind: 'stdio',
      name: 'Demo issues',
      command: process.execPath,
      args: [server],
      env: { DEMO_TOKEN: 'secret-value-123' },
    });
    expect(view).toMatchObject({ secrets: ['DEMO_TOKEN'], enabled: true });
    expect(view.id).toMatch(/^demo-issues-[0-9a-f]{20}$/);
    const id = view.id;
    // The token is in the Keychain-encrypted file, never in plain text.
    expect(readFileSync(join(dir, 'pack-secrets.json'), 'utf8')).not.toContain('secret-value-123');

    const tools = await c.tools(id);
    expect(tools.map((t) => [t.name, t.readOnlyHint])).toEqual([
      ['list_issues', true],
      ['create_issue', false],
    ]);
    expect(c.view()[0]).toMatchObject({ state: 'connected', tools: 2 });
    // The server got its token through the environment.
    expect(await c.call(id, 'create_issue', { repo: 'a/b', title: 'Hi' })).toBe(
      'created a/b#2 "Hi" (token set)',
    );

    // The tracker hears the server's pid once, and again when it is closed.
    expect(spawned).toHaveLength(1);
    const [pid, running] = spawned[0]!;
    expect(pid).toBeGreaterThan(1);
    expect(running).toBe(true);
    await c.closeAll();
    expect(spawned).toEqual([
      [pid, true],
      [pid, false],
    ]);
  }, 20_000);

  it('sends nothing once the run asking has ended, even mid-connect', async () => {
    const { c, dir } = hub();
    open.push(c);
    const log = join(dir, 'calls.log');
    const { id } = c.add({
      kind: 'stdio',
      name: 'Demo issues',
      command: process.execPath,
      args: [server],
      env: { DEMO_CALL_LOG: log },
    });
    const run = new AbortController();
    const call = c.call(id, 'create_issue', { repo: 'a/b', title: 'Late' }, run.signal);
    run.abort(new Error('run over')); // while it is still connecting
    await expect(call).rejects.toThrow('run over');
    // Once connected, the same call in a live run goes through.
    expect(await c.call(id, 'create_issue', { repo: 'a/b', title: 'Now' })).toContain('created');
    expect(readFileSync(log, 'utf8')).toBe('Now\n');
    const ended = new AbortController();
    ended.abort(new Error('run over'));
    await expect(
      c.call(id, 'create_issue', { repo: 'a/b', title: 'After' }, ended.signal),
    ).rejects.toThrow('run over');
    await new Promise((r) => setTimeout(r, 200));
    expect(readFileSync(log, 'utf8')).toBe('Now\n');
  }, 20_000);

  it('hides secrets in what a connector returns before any model sees it', async () => {
    const reply = [
      'api_key=sk-ant-abcdefghijklmnopqrstuvwxyz0123',
      'Authorization: Bearer abcdefghijklmnopqrstuvwxyz012345',
      'owner: someone@example.com',
      'file: /Users/alex/notes.txt',
    ].join('\n');
    const { c } = hub({
      connect: async () =>
        ({
          callTool: async () => ({ content: [{ type: 'text', text: reply }] }),
          close: async () => undefined,
        }) as never,
    });
    open.push(c);
    const { id } = c.add({ kind: 'http', name: 'Leaky', url: 'https://mcp.example.test/mcp' });
    const out = await c.call(id, 'read', {});
    expect(out).not.toMatch(/sk-ant-|abcdefghijklmnop|someone@|alex/);
    // A secret that can't be cut out exactly withholds the whole field.
    expect(out).toBe(WITHHELD);
  });

  /** A hub whose one connector answers `result` to every call. */
  const answering = (result: unknown) => {
    const { c } = hub({
      connect: async () =>
        ({ callTool: async () => result, close: async () => undefined }) as never,
    });
    open.push(c);
    const { id } = c.add({ kind: 'http', name: 'Leaky', url: 'https://mcp.example.test/mcp' });
    return { call: (tool: string, args: Record<string, unknown>) => c.call(id, tool, args) };
  };
  /** Joined at run time so code scanning doesn't take the sample for a real key. */
  const KEY = ['sk', 'ant', 'Abc123Def456Ghi789Jkl012Mno'].join('-');

  it('redacts structured content as data before writing it out', async () => {
    const out = await answering({ content: [], structuredContent: { rows: [{ key: KEY }] } }).call(
      'read',
      {},
    );
    expect(out).not.toContain(KEY);
    expect(out).toMatch(/^\{"rows":\[\{"key":/);
  });

  it('withholds a {"token"} value in a reply, as text or structured', async () => {
    const token = ['tok', 'Plain', 'Value9'].join('');
    const asText = await answering({
      content: [{ type: 'text', text: JSON.stringify({ token }) }],
    }).call('read', {});
    const structured = await answering({ content: [], structuredContent: { token } }).call(
      'read',
      {},
    );
    expect(asText).not.toContain(token);
    expect(structured).not.toContain(token);
  });

  it('reads a text part that is JSON encoded twice as data', async () => {
    const secrets = [['Tr0ub4', 'dor&3'].join(''), ['hunter2', 'xyzQ'].join('')];
    const text = JSON.stringify(JSON.stringify({ password: secrets[0], api_token: secrets[1] }));
    const out = await answering({ content: [{ type: 'text', text }] }).call('read', {});
    for (const secret of secrets) expect(out).not.toContain(secret);
  });

  it('refuses a command inside Vigil’s own app, even through a link', () => {
    const { c, dir } = hub({ selfPaths: [process.execPath] });
    const input = { kind: 'stdio' as const, name: 'Sneaky', args: [server] };
    expect(() => c.add({ ...input, command: process.execPath })).toThrow('part of Vigil');
    const link = join(dir, 'node-link');
    symlinkSync(process.execPath, link);
    expect(() => c.add({ ...input, command: link })).toThrow('part of Vigil');
    expect(c.list()).toEqual([]);
  });

  it('refuses calls to a switched-off connector and forgets secrets on removal', async () => {
    const { c, dir, records } = hub();
    open.push(c);
    const { id } = c.add({
      kind: 'http',
      name: 'Remote',
      url: 'https://mcp.example.test/mcp',
      token: 'tok-abc',
    });
    c.setEnabled(id, false);
    await expect(c.call(id, 'x', {})).rejects.toThrow('switched off');
    c.remove(id);
    expect(records()).toEqual([]);
    expect(readFileSync(join(dir, 'pack-secrets.json'), 'utf8')).toBe('{}');
  });

  it('takes https, or plain http only to this computer', () => {
    const { c } = hub();
    const http = (url: string) => ({ kind: 'http' as const, name: 'Remote', url });
    expect(() => c.add(http('http://mcp.example.test/mcp'))).toThrow('http only');
    expect(() => c.add(http('file:///etc/passwd'))).toThrow();
    expect(c.add(http('http://localhost:8080/mcp')).target).toBe('http://localhost:8080/mcp');
    expect(c.add(http('http://127.0.0.1:8080/mcp')).kind).toBe('http');
    expect(c.add(http('http://[::1]:8080/mcp')).kind).toBe('http');
  });

  it('still lists a connector saved before the https rule', () => {
    const saved = { id: 'old', name: 'Old', kind: 'http' as const, url: 'http://lan.test/mcp' };
    const { c } = hub({ load: () => [{ ...saved, secrets: [], enabled: false }] });
    expect(c.view()).toMatchObject([{ id: 'old', target: 'http://lan.test/mcp' }]);
  });

  it('never connects to a saved plain-http connector off this computer', async () => {
    const saved = { id: 'old', name: 'Old', kind: 'http' as const, url: 'http://lan.test/mcp' };
    let reached = false;
    const { c } = hub({
      load: () => [{ ...saved, secrets: [], enabled: true }],
      connect: async () => {
        reached = true;
        throw new Error('should not connect');
      },
    });
    c.setEnabled('old', true);
    await expect(c.tools('old')).rejects.toThrow('http only');
    expect(reached).toBe(false);
  });

  it('never takes the name vigil', () => {
    const { c } = hub();
    expect(c.add({ kind: 'http', name: 'Vigil', url: 'https://x.test/mcp' }).id).toMatch(
      /^vigil-[0-9a-f]{20}$/,
    );
  });

  it('never gives an id twice, even to a connector added again under the same name', () => {
    const { c } = hub();
    const ids = new Set<string>();
    for (let i = 0; i < 5; i++) {
      const { id } = c.add({ kind: 'http', name: 'GitHub', url: `https://x${i}.test/mcp` });
      expect(id).toMatch(/^github-[0-9a-f]{20}$/);
      expect(ids.has(id)).toBe(false);
      ids.add(id);
      if (i % 2 === 0) c.remove(id);
    }
    // A long name still fits the saved shape.
    const long = c.add({
      kind: 'http',
      name: 'A very long connector name indeed',
      url: 'https://y.test',
    });
    expect(long.id.length).toBeLessThanOrEqual(40);
    expect(long.id).toMatch(/^[a-z0-9-]{1,40}$/);
  });

  it('keeps the id a connector was saved with', () => {
    const saved: ConnectorRecord = {
      id: 'github',
      name: 'GitHub',
      kind: 'http',
      url: 'https://x.test/mcp',
      secrets: [],
      enabled: true,
    };
    const { c } = hub({ load: () => [saved] });
    expect(c.view().map((v) => v.id)).toEqual(['github']);
  });
});
