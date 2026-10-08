import type { SensorEvent } from '@vigil/core';
import {
  AgentTracker,
  DetectionEngine,
  compileAgentMatchers,
  macosCoreRules,
  memoryStores,
  type DetectionRuleInput,
} from '@vigil/detection';
import { ProcessEnricher } from '@vigil/sensors';
import { describe, expect, it } from 'vitest';
import { MAX_STORED_ARG, MAX_STORED_ARGS, slimForStorage, storedArgs } from './event-slim.js';

const bytes = (e: SensorEvent) => Buffer.byteLength(JSON.stringify(e));
const ancestors = ['zsh', 'claude', 'zsh', 'Terminal'];
const tag = { id: 'claude-code', session: '0123456789abcdef', depth: 2 };

function git(extra: Partial<Extract<SensorEvent, { kind: 'process.exec' }>['process']> = {}) {
  return {
    id: 'e1',
    ts: 1,
    source: 'santa',
    kind: 'process.exec',
    process: {
      pid: 10,
      ppid: 9,
      path: '/usr/bin/git',
      args: ['git', 'status'],
      signing: 'apple',
      ...extra,
    },
  } satisfies SensorEvent;
}

describe('slimForStorage', () => {
  it('drops the raw record, and keeps only the parent’s name of an untagged, unmatched launch', () => {
    const today = slimForStorage(git(), false);
    const withTree = { ...git({ ancestors }), raw: { line: 'x'.repeat(500) } };
    const stored = slimForStorage(withTree, false);
    expect(stored).not.toHaveProperty('raw');
    // The parent's name: what process.parentName reads when the sensor gave no parent path.
    expect(stored).toEqual(git({ ancestors: ['zsh'] }));
    expect(bytes(stored) - bytes(today)).toBe(Buffer.byteLength(',"ancestors":["zsh"]'));
  });

  it('adds no bytes where the parent’s name is known otherwise, or is not a launch', () => {
    const withPath = git({ ancestors, parentPath: '/bin/zsh' });
    expect(slimForStorage(withPath, false)).toEqual(git({ parentPath: '/bin/zsh' }));
    const file = {
      id: 'f1',
      ts: 1,
      source: 'santa',
      kind: 'file',
      op: 'open',
      path: '/Users/you/notes.txt',
      process: { pid: 10, path: '/usr/bin/vim', ancestors },
    } satisfies SensorEvent;
    const { ancestors: _a, ...bare } = file.process;
    expect(slimForStorage(file, false)).toEqual({ ...file, process: bare });
  });

  it('judges a rule on the parent’s name the same on a stored launch as live', () => {
    // Santa's log gives no parent path: the tracker names the parent.
    const t = new AgentTracker({ matcher: () => compileAgentMatchers([]) });
    const launch = (pid: number, ppid: number, path: string, ts: number): SensorEvent =>
      t.observe({
        id: `e${pid}`,
        ts,
        source: 'santa',
        kind: 'process.exec',
        process: { pid, ppid, path, args: [path], signing: 'apple' },
      } satisfies SensorEvent);
    launch(500, 1, '/Applications/Microsoft Word.app/Contents/MacOS/Microsoft Word', 1000);
    const live = launch(600, 500, '/bin/zsh', 2000);
    expect(live.kind === 'process.exec' && live.process.ancestors).toEqual(['Microsoft Word']);
    const stored = JSON.parse(JSON.stringify(slimForStorage(live, false))) as SensorEvent;
    const rule = (id: string, condition: DetectionRuleInput['condition']): DetectionRuleInput => ({
      id,
      version: 1,
      name: id,
      description: id,
      origin: 'user',
      mode: 'shadow',
      severity: 'high',
      fidelity: 'medium',
      eventKinds: ['process.exec'],
      condition,
      response: [],
      reasons: ['A shell under Word.'],
      tags: [],
      createdAt: 0,
      updatedAt: 0,
    });
    const shell = { field: 'process.name', op: 'in', value: ['zsh', 'bash', 'sh'] } as const;
    const word = { field: 'process.parentName', op: 'in', value: ['Microsoft Word'] } as const;
    const rules = [
      rule('office-shell', { all: [shell, word] }),
      rule('not-office-shell', { all: [shell, { not: word }] }),
    ];
    // Replay and preview run stored events through an engine like this one.
    const fired = (e: SensorEvent) =>
      new DetectionEngine(rules, memoryStores()).evaluate(e).map((d) => d.match.ruleId);
    expect(fired(live)).toEqual(['office-shell']);
    expect(fired(stored)).toEqual(fired(live));
  });

  it('keeps what chain rules read, so a stored download chain replays like the live one', () => {
    // The helper's sensor hub fills in the tree (parentPath, ancestors and the
    // downloaded ancestor); the app's tracker comes after it.
    const hub = new ProcessEnricher();
    const t = new AgentTracker({ matcher: () => compileAgentMatchers([]) });
    const app = '/Volumes/Free Game/Free Game.app/Contents/MacOS/Free Game';
    const cookies = '/Users/you/Library/Application Support/Google/Chrome/Default/Cookies';
    const raw: SensorEvent[] = [
      {
        id: 'g',
        ts: 1000,
        source: 'santa',
        kind: 'process.exec',
        process: {
          pid: 700,
          ppid: 1,
          path: app,
          signing: 'adhoc',
          quarantine: { originUrl: 'https://games.example/free-game.dmg' },
        },
      },
      {
        id: 's',
        ts: 1100,
        source: 'santa',
        kind: 'process.exec',
        process: {
          pid: 701,
          ppid: 700,
          path: '/bin/sh',
          signing: 'apple',
          args: ['sh', '-c', 'x'],
        },
      },
      {
        id: 'c',
        ts: 1200,
        source: 'santa',
        kind: 'process.exec',
        process: { pid: 702, ppid: 701, path: '/bin/cp', signing: 'apple', args: ['cp', cookies] },
      },
      {
        id: 'r',
        ts: 1300,
        source: 'santa',
        kind: 'file',
        op: 'open',
        path: cookies,
        process: { pid: 702, path: '/bin/cp' },
      },
      {
        id: 'u',
        ts: 1400,
        source: 'santa',
        kind: 'process.exec',
        process: { pid: 703, ppid: 701, path: '/usr/bin/curl', signing: 'apple' },
      },
      {
        id: 'n',
        ts: 1500,
        source: 'osquery',
        kind: 'network.connection',
        direction: 'outbound',
        protocol: 'tcp',
        remoteAddress: '198.51.100.23',
        remotePort: 443,
        process: { pid: 703, path: '/usr/bin/curl' },
      },
    ];
    const live = raw.map((e) => t.observe(hub.enrich(e)));
    const curl = live.at(-1)!;
    expect(curl.kind === 'network.connection' && curl.process).toMatchObject({
      parentPath: '/bin/sh',
      ancestors: ['sh', 'Free Game'],
      downloadedAncestor: { path: app, signing: 'adhoc' },
    });
    const stored = live.map((e) => JSON.parse(JSON.stringify(slimForStorage(e, false))));
    // The tree's names go, and what the chain rule and parentName read stays.
    expect(stored.at(-1)).not.toHaveProperty('process.ancestors');
    expect(stored.at(-1)).toMatchObject({
      process: { parentPath: '/bin/sh', downloadedAncestor: { path: app } },
    });
    const fired = (events: SensorEvent[]) => {
      const engine = new DetectionEngine(macosCoreRules, memoryStores());
      return events.flatMap((e) => engine.evaluate(e).map((d) => d.match.ruleId));
    };
    expect(fired(live)).toContain('untrusted-download-collect-then-connect');
    expect(fired(stored)).toEqual(fired(live));
  });

  it('keeps the ancestry of events under an agent, and of events a rule matched', () => {
    const plain = slimForStorage(git(), false);
    const tagged = slimForStorage(git({ ancestors, agent: tag }), false);
    expect(tagged).toMatchObject({ process: { ancestors, agent: tag } });
    const matched = slimForStorage(git({ ancestors }), true);
    expect(matched).toMatchObject({ process: { ancestors } });
    // What keeping it costs, per event: the names plus the JSON around them.
    const treeBytes = Buffer.byteLength(JSON.stringify({ ancestors })) - 1;
    expect(bytes(matched) - bytes(plain)).toBe(treeBytes);
    expect(bytes(tagged) - bytes(plain)).toBeLessThan(treeBytes + 80);
  });

  it('stores a long command line trimmed, and a matched one whole', () => {
    const script = 'cat > notes.md <<EOF\n' + 'line of a heredoc\n'.repeat(400) + 'EOF';
    const wrapper = ['/bin/zsh', '-c', '-l', `source snapshot.sh && eval '${script}'`];
    const stored = slimForStorage(git({ args: wrapper, agent: tag }), false);
    const args = (stored as ReturnType<typeof git>).process.args!;
    expect(args.slice(0, 3)).toEqual(['/bin/zsh', '-c', '-l']);
    expect(args[3]!.length).toBeLessThan(MAX_STORED_ARG + 60);
    expect(args[3]).toMatch(/^source snapshot\.sh && eval 'cat > notes\.md <<EOF/);
    expect(args[3]).toMatch(/…\[\d+ characters not stored\]…/);
    expect(args[3]!.endsWith("EOF'")).toBe(true);
    expect(bytes(stored)).toBeLessThan(1500);
    // A rule matched it: kept whole, as an alert's evidence would be.
    expect(slimForStorage(git({ args: wrapper }), true)).toEqual(git({ args: wrapper }));
  });

  it('keeps short command lines as they are, and leaves out arguments past the budget', () => {
    const short = ['git', 'commit', '-m', 'x'.repeat(MAX_STORED_ARG)];
    expect(storedArgs(short)).toBe(short);
    const many = Array.from({ length: 500 }, (_, i) => `/Users/you/src/file-${i}.ts`);
    const kept = storedArgs(['eslint', ...many]);
    expect(kept.slice(0, 3)).toEqual(['eslint', many[0], many[1]]);
    expect(kept.at(-1)).toMatch(/^…\[\d+ more arguments not stored\]$/);
    expect(kept.join('').length).toBeLessThanOrEqual(MAX_STORED_ARGS + 40);
    const n = Number(/\d+/.exec(kept.at(-1)!)![0]);
    expect(kept.length - 1 + n).toBe(501);
  });

  it('leaves events without a process alone', () => {
    const e: SensorEvent = {
      id: 'p1',
      ts: 1,
      source: 'osquery',
      kind: 'persistence',
      change: 'added',
      mechanism: 'launch_agent',
      path: '/Users/you/Library/LaunchAgents/x.plist',
    };
    expect(slimForStorage(e, false)).toEqual(e);
  });

  it('does not change the event it was given', () => {
    const e = git({ ancestors });
    slimForStorage(e, false);
    expect(e.process.ancestors).toEqual(ancestors);
  });
});
