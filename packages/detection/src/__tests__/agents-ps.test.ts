import { describe, expect, it, vi } from 'vitest';
import { mergePsArgs, parsePsComm, type PsRow } from '../agents/ps-table.js';
import { AgentTracker } from '../agents/tracker.js';
import { catalog } from './fixtures.js';

/**
 * `ps -axww -o pid=,ppid=,lstart=,comm=` under LC_ALL=C. comm is argv[0]: a
 * login shell's `-zsh`, a bare name for a program started from the shell's
 * PATH, a full path only when the program was started by one.
 */
const COMM = [
  '    1     0 Mon Sep 28 08:01:12 2026 /sbin/launchd',
  '    0     0 Mon Sep 28 08:01:10 2026 kernel_task',
  '  512     1 Wed Oct  1 09:15:02 2026 /System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal',
  '  530   512 Wed Oct  1 09:15:03 2026 -zsh',
  ' 4242   530 Wed Oct  1 20:53:59 2026 claude',
  ' 4300  4242 Wed Oct  1 20:54:30 2026 node',
  ' 4301  4242 Wed Oct  1 20:54:31 2026 /bin/zsh',
  '  900     1 Tue Sep 29 10:00:00 2026 /Applications/Visual Studio Code.app/Contents/MacOS/Electron',
  '  901   900 Tue Sep 29 10:00:01 2026 /Applications/Visual Studio Code.app/Contents/Frameworks/Code Helper (Renderer).app/Contents/MacOS/Code Helper (Renderer)',
  'garbage that is not a ps row',
  '',
].join('\n');

const ARGS = [
  '    1 /sbin/launchd',
  ' 4242 claude --resume',
  ' 4300 node /Users/alex/mcp/server.js --stdio',
  ` 4301 /bin/zsh -c ${'x'.repeat(2000)}`,
].join('\n');

describe('ps parsing', () => {
  it('reads full paths, paths with spaces and bare names, with local start times', () => {
    const rows = parsePsComm(COMM);
    expect(rows).toHaveLength(9);
    expect(rows[0]).toEqual({
      pid: 1,
      ppid: 0,
      startedAt: new Date(2026, 8, 28, 8, 1, 12).getTime(),
      path: '/sbin/launchd',
    });
    expect(rows[1]!.path).toBe('kernel_task');
    expect(rows[4]).toMatchObject({
      pid: 4242,
      ppid: 530,
      startedAt: new Date(2026, 9, 1, 20, 53, 59).getTime(),
    });
    expect(rows[7]!.path).toBe('/Applications/Visual Studio Code.app/Contents/MacOS/Electron');
    expect(rows[8]!.path).toMatch(/Code Helper \(Renderer\)$/);
  });

  it('drops the padding ps puts before a bare name (seen on a real Mac)', () => {
    const rows = parsePsComm(
      [
        '  530   512 Wed Oct  1 09:15:03 2026     -zsh',
        ' 4242   530 Wed Oct  1 20:53:59 2026     claude',
      ].join('\n'),
    );
    expect(rows.map((r) => r.path)).toEqual(['-zsh', 'claude']);
  });

  it('adds command lines by pid, capped at 1 KB, without touching the input', () => {
    const rows = parsePsComm(COMM);
    const merged = mergePsArgs(rows, ARGS);
    const byPid = new Map(merged.map((r) => [r.pid, r]));
    expect(byPid.get(4242)!.args).toEqual(['claude', '--resume']);
    expect(byPid.get(4300)!.args!.join(' ')).toBe('node /Users/alex/mcp/server.js --stdio');
    expect(byPid.get(4301)!.args!.join(' ')).toHaveLength(1024);
    expect(byPid.get(512)!.args).toBeUndefined();
    expect(rows.every((r) => r.args === undefined)).toBe(true);
  });

  it('seeds the tracker with agents that started before Vigil', () => {
    const onSession = vi.fn();
    const t = new AgentTracker({ matcher: catalog, onSession });
    t.seed(mergePsArgs(parsePsComm(COMM), ARGS));
    const claude = t.lookup(4242)!.tag!;
    expect(claude).toMatchObject({ id: 'claude-code', depth: 0 });
    expect(t.lookup(4300)?.tag).toEqual({ ...claude, depth: 1 });
    expect(t.lookup(530)?.tag).toBeUndefined();
    // VS Code is an IDE, off by default.
    expect(t.lookup(901)?.tag).toBeUndefined();
    expect(onSession).toHaveBeenCalledExactlyOnceWith({
      id: claude.session,
      agentId: 'claude-code',
      rootPid: 4242,
      rootPath: 'claude',
      startedAt: new Date(2026, 9, 1, 20, 53, 59).getTime(),
      seeded: true,
    });
  });

  it('finds a node-installed Claude Code by its arguments', () => {
    const rows: PsRow[] = [
      { pid: 50, ppid: 1, startedAt: 0, path: '/opt/homebrew/bin/node' },
      { pid: 51, ppid: 50, startedAt: 0, path: '/bin/zsh' },
    ];
    const t = new AgentTracker({ matcher: catalog });
    t.seed(
      mergePsArgs(rows, ' 50 node /opt/homebrew/lib/node_modules/@anthropic-ai/claude-code/cli.js'),
    );
    expect(t.lookup(51)?.tag).toMatchObject({ id: 'claude-code', depth: 1 });
  });

  it('finds an npm Claude Code started through its bin link', () => {
    const rows: PsRow[] = [
      { pid: 60, ppid: 530, startedAt: 0, path: 'node' },
      { pid: 61, ppid: 60, startedAt: 0, path: '/bin/zsh' },
    ];
    const t = new AgentTracker({ matcher: catalog });
    t.seed(mergePsArgs(rows, ' 60 node /opt/homebrew/bin/claude --resume'));
    expect(t.lookup(60)?.tag).toMatchObject({ id: 'claude-code', depth: 0 });
    expect(t.lookup(61)?.tag).toMatchObject({ id: 'claude-code', depth: 1 });
  });
});
