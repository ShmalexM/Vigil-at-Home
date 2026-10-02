import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { fileURLToPath } from 'node:url';
import { describe, expect, it, vi } from 'vitest';
import { AGENT_CATALOG } from '../agents/catalog.js';
import { AgentRegistry } from '../agents/registry.js';
import type { UserOrigin } from '../origin.js';
import { migrate, sqliteStores, type SqlDatabase } from '../state/sqlite.js';
import { MemoryAgentStore } from '../state/stores.js';
import { userOrigin } from '../user.js';
import { DAY, T0 } from './fixtures.js';

const me = userOrigin('test');
const aider = {
  id: 'aider',
  name: 'Aider',
  kind: 'cli' as const,
  match: [{ names: ['aider'] }],
  watch: true,
};

function registry() {
  const store = new MemoryAgentStore();
  return { store, reg: new AgentRegistry(store, AGENT_CATALOG, () => T0) };
}

describe('agent registry', () => {
  it('refuses every change that does not come from the user', () => {
    const { store, reg } = registry();
    reg.save(aider, me);
    const before = store.list();
    const forged = Object.freeze({ kind: 'user', via: 'agents-screen', at: T0 }) as UserOrigin;
    const attempts = [
      () => reg.save({ ...aider, name: 'Renamed' }, forged),
      () => reg.setWatch('aider', false, forged),
      () => reg.setStatus('aider', 'ignored', forged),
      () => reg.remove('aider', forged),
      () => reg.reset('claude-code', forged),
      () => reg.save(aider, undefined as unknown as UserOrigin),
    ];
    for (const attempt of attempts) expect(attempt).toThrow("needs the user's own approval");
    expect(store.list()).toEqual(before);
  });

  it('adds the user’s own agents as active, and keeps vigil-self reserved', () => {
    const { reg } = registry();
    expect(reg.save(aider, me)).toEqual({
      ...aider,
      origin: 'user',
      status: 'active',
      createdAt: T0,
      updatedAt: T0,
    });
    expect(reg.list().at(-1)).toMatchObject({ id: 'aider', builtin: false, edited: false });
    expect(() => reg.save({ ...aider, id: 'vigil-self' }, me)).toThrow(/reserved/);
    expect(() => reg.save({ ...aider, id: 'vigil-connector' }, me)).toThrow(/reserved/);
    expect(() => reg.save({ ...aider, id: 'Not An Id' }, me)).toThrow();
    expect(() => reg.save({ ...aider, match: [{ argGlobs: ['*x*'] }] }, me)).toThrow();
  });

  it('never removes a built-in: it can be reset or ignored instead', () => {
    const { store, reg } = registry();
    expect(() => reg.remove('claude-code', me)).toThrow(/reset or ignore/);
    reg.setStatus('claude-code', 'ignored', me);
    expect(reg.get('claude-code')?.status).toBe('ignored');
    reg.reset('claude-code', me);
    expect(reg.get('claude-code')?.status).toBe('active');
    expect(store.list()).toEqual([]);

    reg.save(aider, me);
    reg.remove('aider', me);
    expect(reg.get('aider')).toBeUndefined();
    expect(() => reg.reset('aider', me)).toThrow(/built-in/);
  });

  it('stores only watch and status for a built-in, so catalogue updates still apply', () => {
    const store = new MemoryAgentStore();
    new AgentRegistry(store, AGENT_CATALOG, () => T0).setWatch('cursor', true, me);
    expect(store.list()).toMatchObject([{ id: 'cursor', origin: 'builtin', watch: true }]);

    // A later release changes Cursor's matchers; the user's watch setting carries over.
    const updated = AGENT_CATALOG.map((c) =>
      c.id === 'cursor' ? { ...c, match: [{ paths: ['/Applications/Cursor*.app/**'] }] } : c,
    );
    const reg = new AgentRegistry(store, updated, () => T0 + DAY);
    expect(reg.get('cursor')).toMatchObject({
      watch: true,
      match: [{ paths: ['/Applications/Cursor*.app/**'] }],
    });
    expect(reg.list().find((a) => a.id === 'cursor')).toMatchObject({
      builtin: true,
      edited: false,
    });
  });

  it('suggests a program once, dedupes by path and honours "not an agent"', () => {
    const { reg } = registry();
    const path = '/Users/alex/tools/agentx';
    const s = reg.suggest({ path, at: T0 })!;
    expect(s).toMatchObject({
      id: 'suggested-agentx',
      origin: 'suggested',
      status: 'suggested',
      watch: false,
      match: [{ paths: [path] }],
    });
    // A suggestion tags nothing until accepted.
    expect(reg.matcher().match({ path })).toBeUndefined();
    expect(reg.suggest({ path, at: T0 + DAY })).toBeUndefined();
    expect(reg.suggest({ path: '/opt/agentx', at: T0 })?.id).toBe('suggested-agentx-2');
    // Programs Vigil already knows are never suggested.
    expect(reg.suggest({ path: '/usr/local/bin/claude', at: T0 })).toBeUndefined();
    // Accepting one is "watch it".
    reg.setStatus('suggested-agentx-2', 'active', me);
    expect(reg.get('suggested-agentx-2')).toMatchObject({ status: 'active', watch: true });

    reg.setStatus(s.id, 'ignored', me);
    expect(reg.suggest({ path, at: T0 + 2 * DAY })).toBeUndefined();
    expect(reg.matcher().match({ path })).toMatchObject({ id: s.id, watch: false });

    reg.setStatus(s.id, 'active', me);
    expect(reg.get(s.id)).toMatchObject({ status: 'active', watch: true });
    expect(reg.matcher().match({ path })).toMatchObject({ id: s.id, watch: true });
  });

  it('tells listeners about every change, and rebuilds the matcher', () => {
    const { reg } = registry();
    const cb = vi.fn();
    const stop = reg.onChange(cb);
    const before = reg.matcher();
    reg.save(aider, me);
    expect(reg.matcher()).not.toBe(before);
    expect(reg.matcher()).toBe(reg.matcher());
    reg.setWatch('aider', false, me);
    reg.suggest({ path: '/Users/alex/tools/agentx', at: T0 });
    expect(cb).toHaveBeenCalledTimes(3);
    stop();
    reg.remove('aider', me);
    expect(cb).toHaveBeenCalledTimes(3);
  });

  it('keeps agents in SQLite across restarts', () => {
    const db = new DatabaseSync(':memory:') as unknown as SqlDatabase;
    {
      const reg = new AgentRegistry(sqliteStores(db).agents, AGENT_CATALOG, () => T0);
      reg.save(aider, me);
      reg.setWatch('vscode', true, me);
      reg.suggest({ path: '/Users/alex/tools/agentx', at: T0 });
    }
    migrate(db); // idempotent
    const reg = new AgentRegistry(sqliteStores(db).agents, AGENT_CATALOG, () => T0);
    expect(reg.get('aider')?.match).toEqual([{ names: ['aider'] }]);
    expect(reg.get('vscode')?.watch).toBe(true);
    expect(reg.get('suggested-agentx')?.status).toBe('suggested');
    expect(db.prepare('SELECT id, origin, status FROM det_agents ORDER BY id').all()).toEqual([
      { id: 'aider', origin: 'user', status: 'active' },
      { id: 'suggested-agentx', origin: 'suggested', status: 'suggested' },
      { id: 'vscode', origin: 'builtin', status: 'active' },
    ]);
  });

  it('is not reachable from the AI proposal code', () => {
    const dir = fileURLToPath(new URL('../proposals/', import.meta.url));
    const files = readdirSync(dir, { recursive: true, encoding: 'utf8' }).filter((f) =>
      f.endsWith('.ts'),
    );
    expect(files.length).toBeGreaterThan(0);
    for (const f of files) {
      const src = readFileSync(join(dir, f), 'utf8');
      // Directly, or through a barrel that re-exports it.
      expect(src, f).not.toMatch(/agents\/(registry|index)(\.js)?['"]/);
      expect(src, f).not.toMatch(/from '(\.\.\/index(\.js)?|@vigil\/detection)'/);
      expect(src, f).not.toMatch(/\bAgentRegistry\b/);
    }
  });
});
