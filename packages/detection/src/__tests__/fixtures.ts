import type { EventOfKind } from '@vigil/core';
import { AGENT_CATALOG } from '../agents/catalog.js';
import { compileAgentMatchers, type CompiledAgentMatcher } from '../agents/match.js';
import { AgentTracker, type TrackerOptions } from '../agents/tracker.js';
import type { DetectionEvent, DetectionProcessRef } from '../types.js';

let seq = 0;
export const T0 = Date.UTC(2026, 8, 1);
export const HOUR = 3_600_000;
export const DAY = 24 * HOUR;

export function proc(p: Partial<DetectionProcessRef> & { path: string }): DetectionProcessRef {
  return { pid: 4242, ppid: 500, args: [p.path], ...p };
}

type Draft<E> = E extends DetectionEvent
  ? Omit<E, 'id' | 'ts' | 'source'> & Partial<Pick<E, 'id' | 'ts' | 'source'>>
  : never;

/** Build an event; ids and timestamps advance by one second per call. */
export function ev(e: Draft<DetectionEvent>): DetectionEvent {
  seq++;
  return { id: `e${seq}`, ts: T0 + seq * 1000, source: 'test', ...e } as DetectionEvent;
}

export const exec = (process: DetectionProcessRef) => ev({ kind: 'process.exec', process });
export const fileOpen = (process: DetectionProcessRef, path: string) =>
  ev({ kind: 'file', op: 'open', path, process });
export const connect = (process: DetectionProcessRef, remoteAddress: string, remoteHost?: string) =>
  ev({
    kind: 'network.connection',
    direction: 'outbound',
    protocol: 'tcp',
    remoteAddress,
    remotePort: 443,
    process,
    ...(remoteHost ? { remoteHost } : {}),
  });

export const chrome = proc({
  path: '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
  signing: 'developer_id',
  teamId: 'EQHXZ8M8AV',
  signingId: 'com.google.Chrome',
  sha256: 'c'.repeat(64),
});

export const unsignedStealer = proc({
  path: '/private/tmp/.helper',
  sha256: 'a'.repeat(64),
  signing: 'adhoc',
  parentPath: '/bin/zsh',
});

export const osascriptTool = (args: string[], ppid = 777) =>
  proc({
    path: '/usr/bin/osascript',
    args: ['osascript', ...args],
    ppid,
    signing: 'apple',
    parentPath: '/private/tmp/.helper',
  });

export const shell = (cmd: string, name = 'bash') =>
  proc({
    path: `/bin/${name}`,
    args: [name, '-c', cmd],
    signing: 'apple',
    parentPath: '/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal',
  });

/** A minimal valid rule for engine tests. */
export function testRule(r: Record<string, unknown> & { id: string; condition: unknown }) {
  return {
    version: 1,
    name: 'Test rule',
    description: '',
    origin: 'user',
    mode: 'alert',
    severity: 'high',
    fidelity: 'medium',
    eventKinds: ['process.exec'],
    createdAt: T0,
    updatedAt: T0,
    reasons: ['{{process.name}} matched'],
    ...r,
  } as never;
}

export type ExecEvent = EventOfKind<'process.exec'>;

/** Claude Code's native binary as Santa reports it (the ~/.local/bin/claude link resolved). */
export const CLAUDE_BIN = '/Users/alex/.local/share/claude/versions/2.0.14';

let catalogMatcher: CompiledAgentMatcher | undefined;
/** The built-in catalogue, compiled once. */
export const catalog = (): CompiledAgentMatcher =>
  (catalogMatcher ??= compileAgentMatchers(AGENT_CATALOG));

/**
 * A process tree under a watched agent, tagged by a real tracker with the
 * built-in catalogue, the way the app tags events before rules run. The
 * agent's own launch comes first; pids count up from `basePid`.
 */
export function agentTree(
  agentPath = CLAUDE_BIN,
  opts: {
    args?: string[];
    basePid?: number;
    tracker?: Partial<TrackerOptions>;
    /** The root is a connector Vigil (`tracker.self`) started for the pack. */
    connector?: boolean;
  } = {},
) {
  const tracker = new AgentTracker({ matcher: catalog, ...opts.tracker });
  let next = opts.basePid ?? 60_000;
  if (opts.connector) tracker.connectorStarted(next);
  const launch = (p: Partial<DetectionProcessRef> & { path: string }, ppid: number) =>
    tracker.observe(
      ev({ kind: 'process.exec', process: proc({ ...p, pid: next++, ppid }) }) as ExecEvent,
    );
  const root = launch(
    { path: agentPath, args: opts.args ?? ['claude'], signing: 'developer_id' },
    // A shell in the user's terminal, which the tracker has not seen (or Vigil, for a connector).
    opts.connector ? opts.tracker!.self!.pid : 501,
  );
  const exec = (
    path: string,
    args: string[] = [path.slice(path.lastIndexOf('/') + 1)],
    parent: DetectionProcessRef = root.process,
    extra: Partial<DetectionProcessRef> = {},
  ): ExecEvent => launch({ signing: 'apple', ...extra, path, args }, parent.pid);
  return {
    tracker,
    /** The agent's own launch (depth 0). */
    root,
    /** Launch a program under `parent` (the agent by default) and return the tagged event. */
    exec,
    /** A command the way agents run them: `zsh -c` under `parent`. */
    sh: (command: string, parent: DetectionProcessRef = root.process) =>
      exec('/bin/zsh', ['/bin/zsh', '-c', command], parent),
    /** Tag any other event (a file open, a connection) as the app would. */
    observe: <E extends DetectionEvent>(e: E): E => tracker.observe(e),
  };
}
