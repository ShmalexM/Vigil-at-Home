import type { AgentIdentity } from '@vigil/core';
import { describe, expect, it, vi } from 'vitest';
import { AGENT_CATALOG } from '../agents/catalog.js';
import { compileAgentMatchers } from '../agents/match.js';
import { AgentRegistry } from '../agents/registry.js';
import { AgentTracker, type SessionStart, type TrackerOptions } from '../agents/tracker.js';
import { MemoryAgentStore } from '../state/stores.js';
import type { DetectionEvent, DetectionProcessRef } from '../types.js';
import { userOrigin } from '../user.js';
import {
  agentTree,
  catalog,
  CLAUDE_BIN,
  connect,
  ev,
  exec,
  fileOpen,
  proc,
  T0,
  type ExecEvent,
} from './fixtures.js';

const TERMINAL = '/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal';
const CURSOR = '/Applications/Cursor.app/Contents/MacOS/Cursor';
const CODEX = '/opt/homebrew/bin/codex';

/** The (tagged) process on any event. */
const procOf = (e: DetectionEvent) => ('process' in e ? e.process : undefined);

function tracker(opts: Partial<TrackerOptions> = {}) {
  const sessions: SessionStart[] = [];
  const t = new AgentTracker({ matcher: catalog, onSession: (s) => sessions.push(s), ...opts });
  let next = 3000;
  /** Launch `path` with parent pid `ppid` and return the tagged event. */
  const launch = (path: string, ppid: number, extra: Partial<DetectionProcessRef> = {}) =>
    t.observe(exec(proc({ path, pid: next++, ppid, args: [path], ...extra }))) as ExecEvent;
  return { t, sessions, launch };
}

describe('agent tracker', () => {
  it('tags an agent and everything under it, one level deeper each time', () => {
    const tree = agentTree(CLAUDE_BIN, { tracker: { onSession: vi.fn() } });
    const { root } = tree;
    expect(root.process.agent).toMatchObject({ id: 'claude-code', depth: 0 });
    expect(root.process.agent!.session).toMatch(/^[0-9a-f]{16}$/);

    const sh = tree.sh('cat README.md | head');
    const cat = tree.exec('/bin/cat', ['cat', 'README.md'], sh.process);
    const session = root.process.agent!.session;
    expect(sh.process.agent).toEqual({ id: 'claude-code', session, depth: 1 });
    expect(cat.process.agent).toEqual({ id: 'claude-code', session, depth: 2 });
    expect(cat.process.ancestors).toEqual(['zsh', '2.0.14']);
    expect(tree.tracker.lookup(cat.process.pid)).toEqual({
      path: '/bin/cat',
      tag: cat.process.agent,
    });
  });

  it('reports each session once, with its root', () => {
    const { t, sessions, launch } = tracker();
    const claude = launch(CLAUDE_BIN, 501);
    launch('/bin/zsh', claude.process.pid);
    t.retag();
    expect(sessions).toEqual([
      {
        id: claude.process.agent!.session,
        agentId: 'claude-code',
        rootPid: claude.process.pid,
        rootPath: CLAUDE_BIN,
        startedAt: claude.ts,
        seeded: false,
      },
    ]);
  });

  it('leaves a person’s own terminal untagged, but still knows its ancestry', () => {
    const { launch } = tracker();
    const terminal = launch(TERMINAL, 1);
    const zsh = launch('/bin/zsh', terminal.process.pid);
    const git = launch('/usr/bin/git', zsh.process.pid);
    expect(git.process.agent).toBeUndefined();
    expect(git.process.ancestors).toEqual(['zsh', 'Terminal']);
  });

  it('keeps the tag when a process execs a new program, unless that program is an agent', () => {
    const { t, sessions, launch } = tracker();
    const claude = launch(CLAUDE_BIN, 501);
    const sh = launch('/bin/zsh', claude.process.pid);
    const pid = sh.process.pid;
    // zsh -c 'curl …' execs curl in place: same pid, same parent.
    const curl = t.observe(
      exec(proc({ path: '/usr/bin/curl', pid, ppid: claude.process.pid })),
    ) as ExecEvent;
    expect(curl.process.agent).toEqual(sh.process.agent);

    // exec codex: the same process becomes a new agent, inside Claude Code's session.
    const codex = t.observe(exec(proc({ path: CODEX, pid, ppid: claude.process.pid })));
    expect(procOf(codex)?.agent).toMatchObject({ id: 'codex', depth: 0 });
    expect(sessions.at(-1)).toMatchObject({
      agentId: 'codex',
      rootPid: pid,
      parentSession: claude.process.agent!.session,
    });
  });

  it('treats a pid seen again under a different parent as a new process', () => {
    const { t, launch } = tracker();
    const claude = launch(CLAUDE_BIN, 501);
    const sh = launch('/bin/zsh', claude.process.pid);
    const terminal = launch(TERMINAL, 1);
    const reused = t.observe(
      exec(proc({ path: '/bin/zsh', pid: sh.process.pid, ppid: terminal.process.pid })),
    );
    expect(procOf(reused)?.agent).toBeUndefined();
    expect(t.lookup(sh.process.pid)?.tag).toBeUndefined();
    const open = t.observe(fileOpen(procOf(reused)!, '/Users/alex/.ssh/id_ed25519'));
    expect(procOf(open)?.agent).toBeUndefined();
  });

  it('leaves a hole when the parent is unknown, asks for ps, and fills it from a seed', () => {
    const onMiss = vi.fn();
    const { t, launch } = tracker({ onMiss });
    const claude = launch(CLAUDE_BIN, 501);
    // A subshell forked without exec: its pid never launched anything Vigil saw.
    const curl = launch('/usr/bin/curl', 4100);
    expect(curl.process.agent).toBeUndefined();
    expect(onMiss).toHaveBeenCalledWith(4100);

    launch('/usr/sbin/cron', 1); // launchd's children are not misses
    expect(onMiss).not.toHaveBeenCalledWith(1);

    t.seed([{ pid: 4100, ppid: claude.process.pid, startedAt: T0, path: '/bin/zsh' }]);
    expect(t.lookup(curl.process.pid)?.tag).toEqual({
      id: 'claude-code',
      session: claude.process.agent!.session,
      depth: 2,
    });
  });

  it('keeps the lineage of a process handed to launchd when its shell exited', () => {
    const { t, launch } = tracker();
    const claude = launch(CLAUDE_BIN, 501);
    const sh = launch('/bin/zsh', claude.process.pid);
    const curl = launch('/usr/bin/curl', sh.process.pid);
    // `nohup curl … &`: the shell exits and ps now says launchd is the parent.
    t.seed([{ pid: curl.process.pid, ppid: 1, startedAt: curl.ts - 400, path: '/usr/bin/curl' }]);
    expect(t.lookup(curl.process.pid)?.tag).toEqual(curl.process.agent);
    // Started at another time, it is a different process that reused the pid.
    t.seed([
      { pid: curl.process.pid, ppid: 1, startedAt: curl.ts + 60_000, path: '/usr/bin/curl' },
    ]);
    expect(t.lookup(curl.process.pid)?.tag).toBeUndefined();
  });

  it('tags file and network events by pid, only while the program is the same', () => {
    const onMiss = vi.fn();
    const tree = agentTree(CLAUDE_BIN, { tracker: { onMiss } });
    const mcp = tree.exec('/opt/homebrew/bin/node', ['node', '/Users/alex/mcp/server.js']);
    const open = tree.observe(fileOpen(mcp.process, '/Users/alex/.ssh/id_ed25519'));
    expect(procOf(open)?.agent).toEqual(mcp.process.agent);
    expect(procOf(open)?.ancestors).toEqual(['2.0.14']);
    const net = tree.observe(
      connect(proc({ path: mcp.process.path, pid: mcp.process.pid }), '1.2.3.4'),
    );
    expect(procOf(net)?.agent).toMatchObject({ id: 'claude-code', depth: 1 });

    // Same pid, another program: the node is stale, so nothing is trusted.
    const other = fileOpen(proc({ path: '/usr/bin/ssh', pid: mcp.process.pid }), '/tmp/x');
    expect(tree.observe(other)).toBe(other);
    expect(onMiss).toHaveBeenLastCalledWith(mcp.process.pid);

    const unknown = fileOpen(proc({ path: '/usr/bin/ssh', pid: 9999 }), '/tmp/x');
    expect(tree.observe(unknown)).toBe(unknown);
    expect(onMiss).toHaveBeenLastCalledWith(9999);

    const quiet = ev({
      kind: 'browser.extension',
      change: 'added',
      browser: 'chrome',
      extensionId: 'x',
    });
    expect(tree.observe(quiet)).toBe(quiet);
  });

  it('gives a nested agent its own session that points at the outer one', () => {
    const { sessions, launch } = tracker();
    const claude = launch(CLAUDE_BIN, 501);
    const sh = launch('/bin/zsh', claude.process.pid);
    const codex = launch(CODEX, sh.process.pid);
    const inner = launch('/bin/bash', codex.process.pid);
    expect(codex.process.agent).toMatchObject({ id: 'codex', depth: 0 });
    expect(codex.process.agent!.session).not.toBe(claude.process.agent!.session);
    expect(inner.process.agent).toEqual({ ...codex.process.agent, depth: 1 });
    expect(sessions.map((s) => [s.agentId, s.parentSession])).toEqual([
      ['claude-code', undefined],
      ['codex', claude.process.agent!.session],
    ]);
  });

  it('keeps tagging under an agent that runs a program with watch off', () => {
    const { launch } = tracker();
    const claude = launch(CLAUDE_BIN, 501);
    const sh = launch('/bin/zsh', claude.process.pid);
    // `cursor .` from an agent's shell must not be a way out.
    const cursor = launch(CURSOR, sh.process.pid);
    const child = launch('/bin/zsh', cursor.process.pid);
    expect(cursor.process.agent).toMatchObject({ id: 'claude-code', depth: 2 });
    expect(child.process.agent).toMatchObject({ id: 'claude-code', depth: 3 });

    // Started by the person, Cursor (watch off) tags nothing.
    const own = launch(CURSOR, 1);
    expect(own.process.agent).toBeUndefined();
    expect(launch('/bin/zsh', own.process.pid).process.agent).toBeUndefined();
  });

  it('never makes an ignored identity a root', () => {
    const ids: AgentIdentity[] = AGENT_CATALOG.map((c) =>
      c.id === 'claude-code' ? { ...c, status: 'ignored' } : c,
    );
    const m = compileAgentMatchers(ids);
    const { launch } = tracker({ matcher: () => m });
    const claude = launch(CLAUDE_BIN, 501);
    expect(claude.process.agent).toBeUndefined();
    expect(launch('/bin/zsh', claude.process.pid).process.agent).toBeUndefined();
  });

  it('stays within its node budget, forgetting the least recently seen first', () => {
    const { t, launch } = tracker({ maxNodes: 100 });
    const claude = launch(CLAUDE_BIN, 501);
    const first = launch('/bin/zsh', 1);
    for (let i = 0; i < 1000; i++) {
      launch('/usr/bin/true', 1);
      // The agent keeps doing things, so it stays.
      if (i % 50 === 0) t.observe(fileOpen(claude.process, '/Users/alex/code/a.ts'));
    }
    expect(t.size()).toBe(100);
    expect(t.lookup(first.process.pid)).toBeUndefined();
    expect(t.lookup(claude.process.pid)?.tag?.id).toBe('claude-code');
  });

  it('retags running processes when the registry changes', () => {
    const registry = new AgentRegistry(new MemoryAgentStore(), AGENT_CATALOG, () => T0);
    const { t, sessions, launch } = tracker({ matcher: () => registry.matcher() });
    registry.onChange(() => t.retag());
    const me = userOrigin('test');

    const aider = launch('/Users/alex/.local/bin/aider', 501);
    const sh = launch('/bin/zsh', aider.process.pid);
    const cursor = launch(CURSOR, 1);
    expect(t.lookup(sh.process.pid)?.tag).toBeUndefined();

    registry.save(
      { id: 'aider', name: 'Aider', kind: 'cli', match: [{ names: ['aider'] }], watch: true },
      me,
    );
    const root = t.lookup(aider.process.pid)?.tag;
    expect(root).toMatchObject({ id: 'aider', depth: 0 });
    expect(t.lookup(sh.process.pid)?.tag).toEqual({ ...root, depth: 1 });
    expect(sessions.at(-1)).toMatchObject({ agentId: 'aider', rootPid: aider.process.pid });

    registry.setWatch('cursor', true, me);
    expect(t.lookup(cursor.process.pid)?.tag).toMatchObject({ id: 'cursor', depth: 0 });

    registry.setWatch('aider', false, me);
    expect(t.lookup(aider.process.pid)?.tag).toBeUndefined();
    expect(t.lookup(sh.process.pid)?.tag).toBeUndefined();
  });

  it('keeps a child tagged after its parent is forgotten, while the agent is still watched', () => {
    const registry = new AgentRegistry(new MemoryAgentStore(), AGENT_CATALOG, () => T0);
    const { t, launch } = tracker({ matcher: () => registry.matcher(), maxNodes: 3 });
    const claude = launch(CLAUDE_BIN, 501);
    const sh = launch('/bin/zsh', claude.process.pid);
    const server = launch('/opt/homebrew/bin/node', sh.process.pid);
    launch('/usr/bin/true', 1); // evicts claude
    expect(t.lookup(claude.process.pid)).toBeUndefined();
    t.retag();
    expect(t.lookup(server.process.pid)?.tag).toMatchObject({ id: 'claude-code', depth: 2 });

    registry.setWatch('claude-code', false, userOrigin('test'));
    t.retag();
    expect(t.lookup(server.process.pid)?.tag).toBeUndefined();
  });

  it('tags Vigil’s own tree vigil-self, including the claude it runs', () => {
    const vigil = {
      pid: 777,
      path: '/Applications/Vigil at Home.app/Contents/MacOS/Vigil at Home',
    };
    const { t, sessions, launch } = tracker({ self: { ...vigil, startedAt: T0 } });
    const helper = launch(CLAUDE_BIN, vigil.pid);
    const shell = launch('/bin/zsh', helper.process.pid);
    expect(t.lookup(vigil.pid)?.tag).toMatchObject({ id: 'vigil-self', depth: 0 });
    expect(helper.process.agent).toMatchObject({ id: 'vigil-self', depth: 1 });
    expect(shell.process.agent).toMatchObject({ id: 'vigil-self', depth: 2 });
    expect(sessions.map((s) => s.agentId)).toEqual(['vigil-self']);
    expect(t.size()).toBe(3);

    // A ps seed lists Vigil too; it stays Vigil's.
    t.seed([{ pid: vigil.pid, ppid: 1, startedAt: T0, path: vigil.path }]);
    expect(t.lookup(vigil.pid)?.tag?.id).toBe('vigil-self');
  });

  it('suggests an unknown program that runs 20 shell commands in 10 minutes', () => {
    const onCandidate = vi.fn();
    const { t, launch } = tracker({ onCandidate });
    const shellUnder = (ppid: number, at: number) =>
      t.observe(
        ev({
          kind: 'process.exec',
          ts: at,
          process: proc({
            path: '/bin/sh',
            pid: 7000 + (at % 997),
            ppid,
            args: ['sh', '-c', 'ls'],
          }),
        }),
      );

    const agent = launch('/Users/alex/tools/agentx', 501);
    for (let i = 0; i < 19; i++) shellUnder(agent.process.pid, T0 + i * 1000);
    // Shells without -c, and ones under someone else, do not count.
    launch('/bin/zsh', agent.process.pid, { args: ['zsh', '-l'] });
    expect(onCandidate).not.toHaveBeenCalled();
    shellUnder(agent.process.pid, T0 + 19_000);
    expect(onCandidate).toHaveBeenCalledExactlyOnceWith({
      pid: agent.process.pid,
      path: '/Users/alex/tools/agentx',
      shellChildren: 20,
    });
    shellUnder(agent.process.pid, T0 + 20_000);
    expect(onCandidate).toHaveBeenCalledTimes(1);

    // Too slow: 20 commands over more than 10 minutes.
    const slow = launch('/Users/alex/tools/slowpoke', 501);
    for (let i = 0; i < 25; i++) shellUnder(slow.process.pid, T0 + i * 60_000);
    // Build tools, terminals and known agents never count.
    for (const path of ['/usr/bin/make', '/opt/homebrew/bin/node', TERMINAL, CLAUDE_BIN]) {
      const parent = launch(path, 501);
      for (let i = 0; i < 25; i++) shellUnder(parent.process.pid, T0 + i * 1000);
    }
    expect(onCandidate).toHaveBeenCalledTimes(1);
  });

  it('observes a mixed stream in under 5 µs per event on average', () => {
    const t = new AgentTracker({ matcher: catalog, onMiss: () => {} });
    const events: DetectionEvent[] = [];
    let pid = 10_000;
    const live: DetectionProcessRef[] = [];
    for (let i = 0; i < 100_000; i++) {
      const kind = i % 4;
      if (kind === 0 || live.length < 10) {
        const parent = live.length ? live[(i * 7) % live.length]! : undefined;
        const path =
          i % 400 === 0 ? CLAUDE_BIN : i % 3 === 0 ? '/bin/zsh' : `/Users/a/code/bin/t${i % 500}`;
        const p = proc({
          path,
          pid: pid++,
          ppid: parent?.pid ?? 1,
          args: [path, '-c', `run ${i}`],
        });
        live.push(p);
        if (live.length > 2000) live.shift();
        events.push({ id: `p${i}`, ts: T0 + i, source: 'test', kind: 'process.exec', process: p });
      } else {
        const p = live[(i * 13) % live.length]!;
        events.push(
          kind === 1
            ? {
                id: `p${i}`,
                ts: T0 + i,
                source: 'test',
                kind: 'file',
                op: 'open',
                path: `/tmp/f${i % 50}`,
                process: p,
              }
            : {
                id: `p${i}`,
                ts: T0 + i,
                source: 'test',
                kind: 'network.connection',
                direction: 'outbound',
                protocol: 'tcp',
                remoteAddress: '140.82.1.1',
                process: p,
              },
        );
      }
    }
    for (const e of events.slice(0, 2000)) t.observe(e); // warm up
    const start = performance.now();
    for (const e of events) t.observe(e);
    const perEventUs = ((performance.now() - start) * 1000) / events.length;
    console.log(`agent tracker: ${perEventUs.toFixed(2)} µs per event`);
    expect(perEventUs).toBeLessThan(5);
  });
});
