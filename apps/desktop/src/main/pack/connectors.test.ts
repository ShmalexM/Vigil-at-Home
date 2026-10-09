import { mkdtempSync, readFileSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
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
    expect(view).toMatchObject({ id: 'demo-issues', secrets: ['DEMO_TOKEN'], enabled: true });
    // The token is in the Keychain-encrypted file, never in plain text.
    expect(readFileSync(join(dir, 'pack-secrets.json'), 'utf8')).not.toContain('secret-value-123');

    const tools = await c.tools('demo-issues');
    expect(tools.map((t) => [t.name, t.readOnlyHint])).toEqual([
      ['list_issues', true],
      ['create_issue', false],
    ]);
    expect(c.view()[0]).toMatchObject({ state: 'connected', tools: 2 });
    // The server got its token through the environment.
    expect(await c.call('demo-issues', 'create_issue', { repo: 'a/b', title: 'Hi' })).toBe(
      'created a/b#2 "Hi" token=set',
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
    c.add({
      kind: 'stdio',
      name: 'Demo issues',
      command: process.execPath,
      args: [server],
      env: { DEMO_CALL_LOG: log },
    });
    const run = new AbortController();
    const call = c.call('demo-issues', 'create_issue', { repo: 'a/b', title: 'Late' }, run.signal);
    run.abort(new Error('run over')); // while it is still connecting
    await expect(call).rejects.toThrow('run over');
    // Once connected, the same call in a live run goes through.
    expect(await c.call('demo-issues', 'create_issue', { repo: 'a/b', title: 'Now' })).toContain(
      'created',
    );
    expect(readFileSync(log, 'utf8')).toBe('Now\n');
    const ended = new AbortController();
    ended.abort(new Error('run over'));
    await expect(
      c.call('demo-issues', 'create_issue', { repo: 'a/b', title: 'After' }, ended.signal),
    ).rejects.toThrow('run over');
    await new Promise((r) => setTimeout(r, 200));
    expect(readFileSync(log, 'utf8')).toBe('Now\n');
  }, 20_000);

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
    c.add({ kind: 'http', name: 'Remote', url: 'https://mcp.example.test/mcp', token: 'tok-abc' });
    c.setEnabled('remote', false);
    await expect(c.call('remote', 'x', {})).rejects.toThrow('switched off');
    c.remove('remote');
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
      /^vigil-[a-z0-9]{6}$/,
    );
  });
});
