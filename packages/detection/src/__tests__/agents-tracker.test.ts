import type { AgentIdentity } from '@vigil/core';
import { setFlagsFromString } from 'node:v8';
import { runInNewContext } from 'node:vm';
import { describe, expect, it, vi } from 'vitest';
import { AGENT_CATALOG } from '../agents/catalog.js';
import { compileAgentMatchers } from '../agents/match.js';
import { parsePsComm } from '../agents/ps-table.js';
import { AgentRegistry } from '../agents/registry.js';
import { sessionId } from '../agents/session-id.js';
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
    launch('/usr/bin/true', 1); // pushes claude out (it is kept apart, as a root)
    launch('/usr/bin/true', 1); // evicts the shell
    expect(t.lookup(sh.process.pid)).toBeUndefined();
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

  it('gives a connector Vigil starts a session of its own, not Vigil’s tag', () => {
    const vigil = {
      pid: 777,
      path: '/Applications/Vigil at Home.app/Contents/MacOS/Vigil at Home',
    };
    const { t, sessions, launch } = tracker({ self: { ...vigil, startedAt: T0 } });
    const selfSession = t.lookup(vigil.pid)?.tag?.session;
    t.connectorStarted(3000);
    const server = launch('/opt/homebrew/bin/node', vigil.pid);
    expect(server.process.pid).toBe(3000);
    expect(server.process.agent).toMatchObject({ id: 'vigil-connector', depth: 0 });
    // What it runs stays the connector's, even another agent's program.
    const shell = launch('/bin/zsh', server.process.pid);
    const nested = launch(CLAUDE_BIN, shell.process.pid);
    expect(shell.process.agent).toEqual({ ...server.process.agent, depth: 1 });
    expect(nested.process.agent).toEqual({ ...server.process.agent, depth: 2 });
    expect(sessions.at(-1)).toMatchObject({
      agentId: 'vigil-connector',
      rootPid: 3000,
      parentSession: selfSession,
    });

    // Vigil's own helpers next to it keep vigil-self.
    const helper = launch(CLAUDE_BIN, vigil.pid);
    expect(helper.process.agent).toMatchObject({ id: 'vigil-self', depth: 1 });

    // Told after the launch was seen: retagged with its tree.
    t.connectorStarted(helper.process.pid);
    expect(t.lookup(helper.process.pid)?.tag).toMatchObject({ id: 'vigil-connector', depth: 0 });

    // Stopped: a process still running keeps its tag through a retag, and
    // never falls back to Vigil's own.
    t.connectorStopped(3000);
    t.retag();
    expect(t.lookup(3000)?.tag).toEqual(server.process.agent);

    // Only Vigil's direct children: a pid under someone else is not a connector.
    t.connectorStarted(4000);
    t.observe(exec(proc({ path: '/opt/homebrew/bin/node', pid: 4000, ppid: 501, args: ['node'] })));
    expect(t.lookup(4000)?.tag).toBeUndefined();
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

describe('agent tracker and ps', () => {
  const NODE = '/opt/homebrew/Cellar/node/22.9.0/bin/node';

  it('keeps what a sensor said when ps lists the same process by argv[0]', () => {
    const onMiss = vi.fn();
    const tree = agentTree(CLAUDE_BIN, { tracker: { onMiss } });
    const mcp = tree.exec(NODE, ['node', '/Users/alex/mcp/server.js']);
    onMiss.mockClear(); // the agent's own parent, a terminal shell, was a miss
    const { pid, ppid } = mcp.process;
    // ps prints argv[0] (`node`), not the executable Santa reported.
    tree.tracker.seed([{ pid, ppid: ppid!, startedAt: mcp.ts, path: 'node', args: ['node'] }]);
    expect(tree.tracker.lookup(pid)).toEqual({ path: NODE, tag: mcp.process.agent });
    const open = tree.observe(
      fileOpen(proc({ path: NODE, pid, ppid }), '/Users/alex/.ssh/id_ed25519'),
    );
    expect(procOf(open)?.agent).toMatchObject({ id: 'claude-code', depth: 1 });
    expect(onMiss).not.toHaveBeenCalled();
  });

  it('keeps path-only and team-ID-only agents tagged through a ps seed', () => {
    const goose = '/Users/alex/.local/bin/goose';
    const m = compileAgentMatchers([
      ...AGENT_CATALOG,
      {
        id: 'goose',
        name: 'Goose',
        kind: 'cli',
        origin: 'user',
        status: 'active',
        watch: true,
        match: [{ paths: [goose] }],
        createdAt: T0,
        updatedAt: T0,
      },
      {
        id: 'signed',
        name: 'Signed',
        kind: 'cli',
        origin: 'user',
        status: 'active',
        watch: true,
        match: [{ teamIds: ['ABCDE12345'] }],
        createdAt: T0,
        updatedAt: T0,
      },
    ]);
    const { t, launch } = tracker({ matcher: () => m });
    const g = launch(goose, 501);
    const s = launch('/opt/tools/signed-agent', 502, { teamId: 'ABCDE12345' });
    expect(g.process.agent?.id).toBe('goose');
    expect(s.process.agent?.id).toBe('signed');
    t.seed([
      { pid: g.process.pid, ppid: 501, startedAt: g.ts, path: 'goose' },
      { pid: s.process.pid, ppid: 502, startedAt: s.ts, path: 'signed-agent' },
    ]);
    expect(t.lookup(g.process.pid)?.tag?.id).toBe('goose');
    expect(t.lookup(s.process.pid)?.tag?.id).toBe('signed');
    expect(launch('/bin/zsh', g.process.pid).process.agent).toMatchObject({
      id: 'goose',
      depth: 1,
    });
  });

  it('keeps the lineage of nohup curl when ps lists it as `curl` under launchd', () => {
    const { t, launch } = tracker();
    const claude = launch(CLAUDE_BIN, 501);
    const sh = launch('/bin/zsh', claude.process.pid);
    const curl = launch('/usr/bin/curl', sh.process.pid);
    t.seed([{ pid: curl.process.pid, ppid: 1, startedAt: curl.ts - 400, path: 'curl' }]);
    expect(t.lookup(curl.process.pid)).toEqual({ path: '/usr/bin/curl', tag: curl.process.agent });
  });

  it('replaces a ps path with the first sensor path, and tags what that names', () => {
    const goose = '/Users/alex/.local/bin/goose';
    const registry = new AgentRegistry(new MemoryAgentStore(), AGENT_CATALOG, () => T0);
    registry.save(
      { id: 'goose', name: 'Goose', kind: 'cli', match: [{ paths: [goose] }], watch: true },
      userOrigin('test'),
    );
    const { t, launch } = tracker({ matcher: () => registry.matcher() });
    t.seed([{ pid: 9100, ppid: 530, startedAt: T0, path: 'goose' }]);
    expect(t.lookup(9100)?.tag).toBeUndefined();
    const open = t.observe(fileOpen(proc({ path: goose, pid: 9100, ppid: 530 }), '/tmp/x'));
    expect(procOf(open)?.agent).toMatchObject({ id: 'goose', depth: 0 });
    expect(launch('/bin/zsh', 9100).process.agent).toMatchObject({ id: 'goose', depth: 1 });
  });

  it('keeps an npm Claude Code that ps listed by its title once it sees the node path', () => {
    const { t, launch } = tracker();
    // npm's Claude Code names its process `claude`; ps shows that for comm and args.
    t.seed([{ pid: 9200, ppid: 530, startedAt: T0, path: 'claude', args: ['claude'] }]);
    const root = t.lookup(9200)!.tag;
    expect(root).toMatchObject({ id: 'claude-code', depth: 0 });
    t.observe(fileOpen(proc({ path: NODE, pid: 9200, ppid: 530 }), '/Users/alex/code/a.ts'));
    expect(t.lookup(9200)).toEqual({ path: NODE, tag: root });
    expect(launch('/bin/zsh', 9200).process.agent).toEqual({ ...root, depth: 1 });
  });

  it('never suggests a program known only by its ps name', () => {
    const onCandidate = vi.fn();
    const { t } = tracker({ onCandidate });
    t.seed([{ pid: 9300, ppid: 530, startedAt: T0, path: 'goose' }]);
    for (let i = 0; i < 25; i++)
      t.observe(
        ev({
          kind: 'process.exec',
          ts: T0 + i * 1000,
          process: proc({ path: '/bin/sh', pid: 9400 + i, ppid: 9300, args: ['sh', '-c', 'ls'] }),
        }),
      );
    expect(onCandidate).not.toHaveBeenCalled();
  });

  it('extends the ancestry of processes below a hole a seed fills', () => {
    const { t, launch } = tracker();
    const claude = launch(CLAUDE_BIN, 501);
    const curl = launch('/usr/bin/curl', 4100); // its parent, a forked subshell, was never seen
    expect(curl.process.ancestors).toBeUndefined();
    t.seed([{ pid: 4100, ppid: claude.process.pid, startedAt: T0, path: '/bin/zsh' }]);
    const open = t.observe(
      fileOpen(proc({ path: '/usr/bin/curl', pid: curl.process.pid, ppid: 4100 }), '/tmp/x'),
    );
    expect(procOf(open)?.ancestors).toEqual(['zsh', '2.0.14']);
  });

  it('never shortens an ancestry when a parent was forgotten', () => {
    const { t, launch } = tracker({ maxNodes: 3 });
    const claude = launch(CLAUDE_BIN, 501);
    const sh = launch('/bin/zsh', claude.process.pid);
    const cat = launch('/bin/cat', sh.process.pid);
    expect(cat.process.ancestors).toEqual(['zsh', '2.0.14']);
    launch('/usr/bin/true', 1);
    launch('/usr/bin/true', 1); // the shell is forgotten
    t.seed([]);
    const open = t.observe(
      fileOpen(proc({ path: '/bin/cat', pid: cat.process.pid, ppid: sh.process.pid }), '/tmp/x'),
    );
    expect(procOf(open)?.ancestors).toEqual(['zsh', '2.0.14']);
  });
});

describe('agent tracker and npm installs', () => {
  it('starts a session when env hands an npm CLI to node on the same process', () => {
    const { t, sessions } = tracker();
    const shim = t.observe(
      exec(
        proc({
          path: '/usr/bin/env',
          pid: 9600,
          ppid: 530,
          args: ['/usr/bin/env', 'node', '/opt/homebrew/bin/claude', '-p', 'x'],
        }),
      ),
    ) as ExecEvent;
    expect(shim.process.agent).toBeUndefined();
    const node = t.observe(
      exec(
        proc({
          path: '/opt/homebrew/Cellar/node/22.9.0/bin/node',
          pid: 9600,
          ppid: 530,
          args: ['node', '/opt/homebrew/bin/claude', '-p', 'x'],
        }),
      ),
    ) as ExecEvent;
    expect(node.process.agent).toMatchObject({ id: 'claude-code', depth: 0 });
    const sh = t.observe(
      exec(proc({ path: '/bin/zsh', pid: 9601, ppid: 9600, args: ['zsh', '-c', 'ls'] })),
    ) as ExecEvent;
    expect(sh.process.agent).toMatchObject({ id: 'claude-code', depth: 1 });
    expect(sessions.map((s) => s.agentId)).toEqual(['claude-code']);
    // A retag (registry change) matches again from the joined arguments it kept.
    t.retag();
    expect(t.lookup(9601)?.tag).toEqual(sh.process.agent);
  });

  it('starts a Gemini CLI session through its memory-flag relaunch', () => {
    const { launch } = tracker();
    const gemini = launch('/opt/homebrew/Cellar/node/22.9.0/bin/node', 530, {
      args: ['node', '--max-old-space-size=8192', '/opt/homebrew/bin/gemini'],
    });
    expect(gemini.process.agent).toMatchObject({ id: 'gemini-cli', depth: 0 });
  });
});

describe('agent tracker under churn', () => {
  it('keeps an idle agent root while thousands of other programs launch', () => {
    const { t, launch } = tracker();
    const claude = launch(CLAUDE_BIN, 501);
    for (let i = 0; i < 8200; i++) launch('/usr/bin/true', 400);
    expect(t.lookup(claude.process.pid)?.tag).toEqual(claude.process.agent);
    const sh = launch('/bin/zsh', claude.process.pid, { args: ['zsh', '-c', 'ls'] });
    expect(sh.process.agent).toEqual({ ...claude.process.agent, depth: 1 });
    expect(t.size()).toBeLessThanOrEqual(8192 + 256);
  });

  it('keeps the root when its own tool shell launches thousands of programs', () => {
    const { t, launch } = tracker();
    const claude = launch(CLAUDE_BIN, 501);
    const loop = launch('/bin/zsh', claude.process.pid);
    for (let i = 0; i < 9000; i++) launch('/usr/bin/true', loop.process.pid);
    const next = launch('/bin/zsh', claude.process.pid);
    expect(next.process.agent).toMatchObject({ id: 'claude-code', depth: 1 });
    expect(t.lookup(claude.process.pid)?.tag?.depth).toBe(0);
  });

  it('gives a forgotten server under an agent its tag back when ps lists it', () => {
    const { t, launch } = tracker();
    const claude = launch(CLAUDE_BIN, 501);
    const sh = launch('/bin/zsh', claude.process.pid);
    const server = launch('/opt/homebrew/bin/node', sh.process.pid);
    for (let i = 0; i < 8200; i++) launch('/usr/bin/true', 400);
    expect(t.lookup(server.process.pid)).toBeUndefined();
    // The shell exited, so ps says launchd is its parent; same start time, same process.
    t.seed([{ pid: server.process.pid, ppid: 1, startedAt: server.ts, path: 'node' }]);
    expect(t.lookup(server.process.pid)?.tag).toEqual(server.process.agent);
    const curl = launch('/usr/bin/curl', server.process.pid);
    expect(curl.process.agent).toMatchObject({ id: 'claude-code', depth: 3 });
  });

  it('keeps one session id when ps finds a root again after it was forgotten', () => {
    const { t, sessions } = tracker({ maxNodes: 4 });
    const at = (ts: number, pid: number) =>
      t.observe(
        ev({ kind: 'process.exec', ts, process: proc({ path: CLAUDE_BIN, pid, ppid: 501 }) }),
      ) as ExecEvent;
    // Santa logged the launch at x.003; ps will say it started at x-1.
    const first = at(T0 + 10_003, 20_000);
    for (let i = 1; i <= 300; i++) at(T0 + 20_000 + i, 20_000 + i); // more roots than are kept
    expect(t.lookup(first.process.pid)).toBeUndefined();
    t.seed([{ pid: 20_000, ppid: 501, startedAt: T0 + 9000, path: 'claude' }]);
    expect(t.lookup(20_000)?.tag?.session).toBe(first.process.agent!.session);
    expect(sessions.filter((s) => s.rootPid === 20_000)).toHaveLength(1);
  });

  it('keeps the session id across a restart when the app knows the launch time', () => {
    const { launch } = tracker();
    const before = t0Launch(launch);
    const launchTs = before.ts + 3;
    const id = sessionId('claude-code', before.process.pid, launchTs);
    const sessions: SessionStart[] = [];
    const t = new AgentTracker({
      matcher: catalog,
      onSession: (s) => sessions.push(s),
      priorStart: (agentId, pid, psStart) =>
        agentId === 'claude-code' &&
        pid === before.process.pid &&
        Math.abs(psStart - launchTs) < 2000
          ? launchTs
          : undefined,
    });
    t.seed([{ pid: before.process.pid, ppid: 501, startedAt: before.ts - 1000, path: 'claude' }]);
    expect(t.lookup(before.process.pid)?.tag?.session).toBe(id);
    expect(sessions).toEqual([expect.objectContaining({ id, startedAt: launchTs, seeded: true })]);
  });
});

/** A Claude Code launch whose time is a whole second. */
function t0Launch(launch: (path: string, ppid: number) => ExecEvent): ExecEvent {
  return launch(CLAUDE_BIN, 501);
}

describe('agent tracker housekeeping', () => {
  it('ignores exits: no lookup, no miss, no change to what it forgets first', () => {
    const onMiss = vi.fn();
    const { t, launch } = tracker({ onMiss, maxNodes: 2 });
    const a = launch('/usr/bin/true', 1);
    const b = launch('/usr/bin/true', 1);
    const exit = ev({
      kind: 'process.exit',
      process: { pid: a.process.pid, path: '' },
      exitCode: 0,
    });
    expect(t.observe(exit)).toBe(exit);
    expect(t.observe(ev({ kind: 'process.exit', process: { pid: 9999, path: '' } }))).toBeDefined();
    expect(onMiss).not.toHaveBeenCalled();
    launch('/usr/bin/true', 1); // a is still the oldest, so it goes
    expect(t.lookup(a.process.pid)).toBeUndefined();
    expect(t.lookup(b.process.pid)).toBeDefined();
  });

  it('leaves programs a forked subshell starts untagged (Santa logs no fork yet)', () => {
    const onMiss = vi.fn();
    const tree = agentTree(CLAUDE_BIN, { tracker: { onMiss } });
    const sh = tree.sh(`k=$HOME/.ssh/id_rsa; (cat "$k"; :) | wc -c`);
    expect(sh.process.agent).toMatchObject({ depth: 1 });
    // The subshell forked from the agent's shell and never exec'd, so Vigil never saw it.
    const subshell = sh.process.pid + 1000;
    const cat = tree.tracker.observe(
      ev({
        kind: 'process.exec',
        process: proc({ path: '/bin/cat', pid: 61_500, ppid: subshell }),
      }),
    ) as ExecEvent;
    expect(cat.process.agent).toBeUndefined();
    expect(onMiss).toHaveBeenCalledWith(subshell);
    const open = tree.observe(
      fileOpen(proc({ path: '/bin/cat', pid: 61_500, ppid: subshell }), '/Users/alex/.ssh/id_rsa'),
    );
    expect(procOf(open)?.agent).toBeUndefined();
  });

  it('never counts interpreters, editors and build services, whatever their version', () => {
    const onCandidate = vi.fn();
    const { t, launch } = tracker({ onCandidate });
    const parents = [
      '/opt/homebrew/Cellar/python@3.12/3.12.7_1/Frameworks/Python.framework/Versions/3.12/Resources/Python.app/Contents/MacOS/Python',
      '/Users/alex/.local/share/uv/python/cpython-3.12/bin/python3.12',
      '/usr/bin/perl5.34',
      '/Applications/Xcode.app/Contents/SharedFrameworks/XCBuild.framework/Versions/A/PlugIns/XCBBuildService.bundle/Contents/MacOS/XCBBuildService',
      '/usr/bin/xargs',
      '/usr/bin/find',
      '/opt/homebrew/bin/nvim',
    ];
    let pid = 30_000;
    for (const path of parents) {
      const parent = launch(path, 501);
      for (let i = 0; i < 25; i++)
        t.observe(
          ev({
            kind: 'process.exec',
            ts: T0 + i * 1000,
            process: proc({
              path: '/bin/sh',
              pid: pid++,
              ppid: parent.process.pid,
              args: ['sh', '-c', 'x'],
            }),
          }),
        );
    }
    expect(onCandidate).not.toHaveBeenCalled();
  });

  it('suggests a program again after a while, in case the app dropped the first one', () => {
    const onCandidate = vi.fn();
    const { t, launch } = tracker({ onCandidate });
    const agent = launch('/Users/alex/tools/agentx', 501);
    let pid = 40_000;
    const shells = (from: number, n: number) => {
      for (let i = 0; i < n; i++)
        t.observe(
          ev({
            kind: 'process.exec',
            ts: from + i * 1000,
            process: proc({
              path: '/bin/sh',
              pid: pid++,
              ppid: agent.process.pid,
              args: ['sh', '-c', 'ls'],
            }),
          }),
        );
    };
    shells(T0, 20);
    expect(onCandidate).toHaveBeenCalledTimes(1);
    shells(T0 + 60_000, 20); // too soon
    expect(onCandidate).toHaveBeenCalledTimes(1);
    shells(T0 + 2 * 3_600_000, 20);
    expect(onCandidate).toHaveBeenCalledTimes(2);
  });
});

describe('agent tracker memory', () => {
  setFlagsFromString('--expose-gc');
  const gc = runInNewContext('gc') as () => void;
  /** MB of heap still in use once `build`'s result is all that is left. */
  function heldMB(build: () => unknown): number {
    gc();
    gc();
    const before = process.memoryUsage().heapUsed;
    const kept = build();
    gc();
    gc();
    const after = process.memoryUsage().heapUsed;
    expect(kept).toBeDefined();
    return (after - before) / 1e6;
  }

  it('keeps 1 KB of a long command line, not the whole line', () => {
    const mb = heldMB(() => {
      const t = new AgentTracker({ matcher: catalog });
      for (let i = 0; i < 2000; i++)
        t.observe(
          ev({
            kind: 'process.exec',
            process: proc({
              path: '/usr/bin/python3',
              pid: 10_000 + i,
              ppid: 1,
              args: ['python3', '-c', `${i}`.padEnd(100_000, 'x')],
            }),
          }),
        );
      return t;
    });
    expect(mb).toBeLessThan(8);
  });

  it('keeps nothing of a ps listing but the rows it adds', () => {
    const mb = heldMB(() => {
      const t = new AgentTracker({ matcher: catalog });
      for (let s = 0; s < 100; s++) {
        const lines: string[] = [];
        for (let i = 0; i < 1000; i++) {
          const pid = i < 995 ? 20_000 + i : 30_000 + s * 5 + (i - 995);
          lines.push(
            `${pid} 1 Wed Oct  1 20:53:59 2026 /Applications/Some Long Application Name.app/Contents/MacOS/helper-${i}`,
          );
        }
        t.seed(parsePsComm(lines.join('\n')));
      }
      return t;
    });
    expect(mb).toBeLessThan(5);
  });

  it('holds 8,192 tagged processes in a few MB', () => {
    const mb = heldMB(() => {
      const t = new AgentTracker({ matcher: catalog });
      t.observe(ev({ kind: 'process.exec', process: proc({ path: CLAUDE_BIN, pid: 5, ppid: 1 }) }));
      for (let i = 0; i < 8191; i++)
        t.observe(
          ev({
            kind: 'process.exec',
            process: proc({ path: '/bin/zsh', pid: 100 + i, ppid: 5, args: ['zsh', '-c', 'x'] }),
          }),
        );
      return t;
    });
    expect(mb).toBeLessThan(6);
  });
});

describe('agent tracker and a slow ps', () => {
  it('keeps a launch it saw while ps ran over that ps’s older row for the pid', () => {
    const { t, launch } = tracker();
    const claude = launch(CLAUDE_BIN, 501);
    const since = t.mark();
    // While ps runs, a process exits and its pid goes to a new shell under the agent.
    const sh = launch('/bin/zsh', claude.process.pid);
    const { pid } = sh.process;
    t.seed([{ pid, ppid: 1, startedAt: T0 - 3_600_000, path: 'olddaemon' }], since);
    expect(t.lookup(pid)).toEqual({ path: '/bin/zsh', tag: sh.process.agent });
    expect(launch('/bin/ls', pid).process.agent).toMatchObject({ id: 'claude-code', depth: 2 });
  });

  it('takes ps’s row over a launch it saw before ps ran', () => {
    const { t, launch } = tracker();
    const claude = launch(CLAUDE_BIN, 501);
    const sh = launch('/bin/zsh', claude.process.pid);
    const { pid } = sh.process;
    // The shell exited and its pid went to another program before ps ran.
    const since = t.mark();
    t.seed([{ pid, ppid: 1, startedAt: T0 + 3_600_000, path: 'otherd' }], since);
    expect(t.lookup(pid)?.tag).toBeUndefined();
  });
});

describe('agent tracker and the ancestry the sensor hub fills in', () => {
  // The helper's sensor hub (packages/sensors enrich.ts) names a launch's
  // ancestors from the launches it saw: basenames, nearest first, at most four,
  // the same shape the tracker uses.

  it('keeps what the hub says when the tracker never saw the parent', () => {
    const { t } = tracker();
    const git = t.observe(
      exec(
        proc({
          path: '/usr/bin/git',
          pid: 4200,
          ppid: 4199,
          ancestors: ['zsh', 'login', 'Terminal'],
        }),
      ),
    ) as ExecEvent;
    expect(git.process.ancestors).toEqual(['zsh', 'login', 'Terminal']);
    // The tracker remembers it for later events the hub sent without it, and for children.
    const open = t.observe(
      fileOpen(proc({ path: '/usr/bin/git', pid: 4200, ppid: 4199 }), '/tmp/x'),
    );
    expect(procOf(open)?.ancestors).toEqual(['zsh', 'login', 'Terminal']);
    const child = t.observe(
      exec(proc({ path: '/usr/libexec/git-core/git-remote-https', pid: 4201, ppid: 4200 })),
    ) as ExecEvent;
    expect(child.process.ancestors).toEqual(['git', 'zsh', 'login', 'Terminal']);
  });

  it('keeps what the hub says when the two disagree', () => {
    const { launch } = tracker();
    const terminal = launch(TERMINAL, 1);
    const zsh = launch('/bin/zsh', terminal.process.pid);
    // The hub saw this pid run something else (say, a re-exec Vigil missed).
    const git = launch('/usr/bin/git', zsh.process.pid, { ancestors: ['bash', 'Terminal'] });
    expect(git.process.ancestors).toEqual(['bash', 'Terminal']);
    // Nothing the tracker knows takes away what a sensor said on a later event.
    const { t } = tracker();
    const known = t.observe(exec(proc({ path: '/usr/bin/ssh', pid: 4300, ppid: 1 }))) as ExecEvent;
    expect(known.process.ancestors).toBeUndefined();
    const open = t.observe(
      fileOpen(proc({ path: '/usr/bin/ssh', pid: 4300, ppid: 1, ancestors: ['launchd'] }), '/x'),
    );
    expect(procOf(open)?.ancestors).toEqual(['launchd']);
  });

  it('carries the hub’s chain further up when the tracker knows more of it (ps)', () => {
    const { t } = tracker();
    // Claude Code started before Vigil, so only ps knows it.
    t.seed([{ pid: 4400, ppid: 600, startedAt: T0 - 60_000, path: CLAUDE_BIN }]);
    const sh = t.observe(
      exec(proc({ path: '/bin/zsh', pid: 4401, ppid: 4400, args: ['zsh', '-c', 'cat x'] })),
    ) as ExecEvent;
    expect(sh.process.ancestors).toEqual(['2.0.14']);
    expect(sh.process.agent).toMatchObject({ id: 'claude-code', depth: 1 });
    // The hub saw the shell start, but not Claude Code: it names only the shell.
    const cat = t.observe(
      exec(proc({ path: '/bin/cat', pid: 4402, ppid: 4401, ancestors: ['zsh'] })),
    ) as ExecEvent;
    expect(cat.process.ancestors).toEqual(['zsh', '2.0.14']);
    expect(cat.process.agent).toMatchObject({ id: 'claude-code', depth: 2 });
  });

  it('returns the same event when the hub already said everything', () => {
    const { t, launch } = tracker();
    const terminal = launch(TERMINAL, 1);
    const zsh = launch('/bin/zsh', terminal.process.pid);
    const e = exec(
      proc({ path: '/usr/bin/true', pid: 4500, ppid: zsh.process.pid, ancestors: ['zsh'] }),
    );
    // The tracker knows ['zsh', 'Terminal'], which carries the hub's chain on.
    expect((t.observe(e) as ExecEvent).process.ancestors).toEqual(['zsh', 'Terminal']);
    const full = exec(
      proc({
        path: '/usr/bin/true',
        pid: 4501,
        ppid: zsh.process.pid,
        ancestors: ['zsh', 'Terminal'],
      }),
    );
    expect(t.observe(full)).toBe(full);
  });
});
