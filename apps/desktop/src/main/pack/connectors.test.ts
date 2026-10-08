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
    c.add({ kind: 'stdio', name: 'Slow', command: process.execPath, args: [server] });
    const listing = c.tools('slow');
    await new Promise((r) => setTimeout(r, 0));
    c.setEnabled('slow', false);
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
    c.add({ kind: 'stdio', name: 'Slow', command: process.execPath, args: [server] });
    const listing = c.tools('slow');
    await new Promise((r) => setTimeout(r, 0));
    c.remove('slow');
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

  it('never takes the name vigil', () => {
    const { c } = hub();
    expect(c.add({ kind: 'http', name: 'Vigil', url: 'https://x.test/mcp' }).id).toMatch(
      /^vigil-[a-z0-9]{6}$/,
    );
  });
});
