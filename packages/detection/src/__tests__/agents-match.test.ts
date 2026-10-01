import { AgentIdentity } from '@vigil/core';
import { describe, expect, it } from 'vitest';
import { AGENT_CATALOG, VIGIL_SELF } from '../agents/catalog.js';
import { argGlobMatch, compileAgentMatchers } from '../agents/match.js';
import { AgentRegistry } from '../agents/registry.js';
import { MemoryAgentStore } from '../state/stores.js';
import { userOrigin } from '../user.js';
import { catalog, T0 } from './fixtures.js';

const idOf = (path: string, args?: string[]) =>
  catalog().match({ path, ...(args ? { args } : {}) })?.id;

function identity(id: string, match: AgentIdentity['match'], extra: Partial<AgentIdentity> = {}) {
  return {
    id,
    name: id,
    kind: 'cli',
    origin: 'user',
    status: 'active',
    watch: true,
    match,
    createdAt: T0,
    updatedAt: T0,
    ...extra,
  } satisfies AgentIdentity;
}

describe('agent matching', () => {
  it('knows node-based agents only by the package they run', () => {
    const node = '/opt/homebrew/bin/node';
    const cli = '/opt/homebrew/lib/node_modules/@anthropic-ai/claude-code/cli.js';
    expect(idOf(node, ['node', cli, '--resume'])).toBe('claude-code');
    expect(idOf(node, ['node', '/opt/homebrew/lib/node_modules/@OpenAI/codex/bin/codex.js'])).toBe(
      'codex',
    );
    expect(idOf(node, ['node', '/Users/alex/code/app/server.js'])).toBeUndefined();
    expect(idOf(node)).toBeUndefined();
    // The package name has to be in the arguments, not just anywhere near node.
    expect(idOf('/Users/alex/@anthropic-ai/claude-code/node', ['node'])).toBeUndefined();
  });

  it('matches path globs, with ~/ standing for any home folder', () => {
    expect(idOf('/Applications/Claude.app/Contents/MacOS/Claude')).toBe('claude-desktop');
    expect(idOf('/Applications/Claude.app/Contents/Helpers/disclaimer')).toBe('claude-desktop');
    expect(idOf('/Users/sam/.local/share/claude/versions/2.0.14')).toBe('claude-code');
    expect(idOf('/Applications/Claude.app.evil/Contents/MacOS/Claude')).toBeUndefined();
    expect(idOf('/Users/sam/.local/share/claude/versions/2.0.14/extra')).toBeUndefined();
  });

  it('matches names exactly, wherever the program lives', () => {
    expect(idOf('/usr/local/bin/claude')).toBe('claude-code');
    expect(idOf('/Users/alex/.cargo/bin/codex')).toBe('codex');
    expect(idOf('/usr/local/bin/claude-helper')).toBeUndefined();
    expect(idOf('/usr/local/bin/Claude')).toBeUndefined();
  });

  it('requires every list a matcher names, and uses team and signing IDs', () => {
    const m = compileAgentMatchers([
      identity('signed', [{ teamIds: ['ABCDE12345'], names: ['helper'] }]),
      identity('by-signing-id', [{ signingIds: ['com.example.agent'] }]),
    ]);
    expect(m.match({ path: '/x/helper', teamId: 'ABCDE12345' })?.id).toBe('signed');
    expect(m.match({ path: '/x/other', teamId: 'ABCDE12345' })).toBeUndefined();
    expect(m.match({ path: '/x/helper' })).toBeUndefined();
    expect(m.match({ path: '/x/a', signingId: 'com.example.agent' })?.id).toBe('by-signing-id');
  });

  it('lets the first identity win, leaves suggestions out and turns watch off where it must', () => {
    const m = compileAgentMatchers([
      identity('first', [{ paths: ['/opt/tools/**'] }]),
      identity('second', [{ names: ['agent'] }]),
      identity('maybe', [{ names: ['maybe'] }], {
        origin: 'suggested',
        status: 'suggested',
        watch: false,
      }),
      identity('quiet', [{ names: ['quiet'] }], { status: 'ignored' }),
      identity('model', [{ names: ['model'] }], { kind: 'runtime' }),
    ]);
    expect(m.match({ path: '/opt/tools/bin/agent' })?.id).toBe('first');
    expect(m.match({ path: '/usr/bin/agent' })?.id).toBe('second');
    expect(m.match({ path: '/usr/bin/maybe' })).toBeUndefined();
    expect(m.match({ path: '/usr/bin/quiet' })).toMatchObject({ id: 'quiet', watch: false });
    expect(m.match({ path: '/usr/bin/model' })).toMatchObject({ id: 'model', watch: false });
    expect(m.byId('second')?.watch).toBe(true);
    expect(m.byId('maybe')).toBeUndefined();
    expect(catalog().match({ path: '/opt/homebrew/bin/ollama' })).toMatchObject({ watch: false });
  });

  it("uses the user's copy of a built-in instead of the shipped one", () => {
    const registry = new AgentRegistry(new MemoryAgentStore(), AGENT_CATALOG, () => T0);
    const me = userOrigin('test');
    registry.save(
      {
        id: 'claude-code',
        name: 'Claude Code',
        kind: 'cli',
        match: [{ names: ['claude-dev'] }],
        watch: true,
      },
      me,
    );
    expect(registry.matcher().match({ path: '/usr/local/bin/claude-dev' })?.id).toBe('claude-code');
    expect(registry.matcher().match({ path: '/usr/local/bin/claude' })).toBeUndefined();
    expect(registry.list().find((a) => a.id === 'claude-code')).toMatchObject({
      builtin: true,
      edited: true,
      origin: 'builtin',
    });
    registry.reset('claude-code', me);
    expect(registry.matcher().match({ path: '/usr/local/bin/claude' })?.id).toBe('claude-code');
  });

  it('says which programs need their arguments kept', () => {
    expect(catalog().wantsArgs({ path: '/opt/homebrew/bin/node' })).toBe(true);
    expect(catalog().wantsArgs({ path: '/bin/zsh' })).toBe(false);
  });

  it('matches argument globs in linear time, whatever the pattern', () => {
    expect(argGlobMatch('*@openai/codex*', 'node /a/@openai/codex/bin.js')).toBe(true);
    expect(argGlobMatch('node ?a*', 'node xa')).toBe(true);
    expect(argGlobMatch('node ?a*', 'node a')).toBe(false);
    const start = performance.now();
    expect(argGlobMatch('*a*a*a*a*a*a*a*b', 'a'.repeat(1024))).toBe(false);
    expect(performance.now() - start).toBeLessThan(50);
  });

  it('keeps the catalogue valid and Vigil out of it', () => {
    expect(AGENT_CATALOG.map((c) => c.id)).not.toContain(VIGIL_SELF);
    for (const c of AGENT_CATALOG) {
      const { installPaths: _paths, preflightHost: _host, ...id } = c;
      expect(AgentIdentity.safeParse(id).success).toBe(true);
      expect(c.origin).toBe('builtin');
      expect(c.match.every((m) => !m.teamIds)).toBe(true); // none until verified on a Mac
    }
    expect(AGENT_CATALOG.filter((c) => c.preflightHost).map((c) => c.id)).toEqual(['claude-code']);
    expect(AGENT_CATALOG.filter((c) => !c.watch).map((c) => c.id)).toEqual([
      'cursor',
      'vscode',
      'ollama',
    ]);
  });
});
