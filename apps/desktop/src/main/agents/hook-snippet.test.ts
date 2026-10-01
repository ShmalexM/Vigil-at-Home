import { execFileSync } from 'node:child_process';
import { describe, expect, it } from 'vitest';
import { HOOK_TIMEOUT_S, PREFLIGHT_MATCHER, hookFiles, hookSnippet } from './hook-snippet.js';

interface Snippet {
  hooks: Record<
    'PreToolUse' | 'SessionStart',
    { matcher?: string; hooks: { type: string; command: string; timeout: number }[] }[]
  >;
}

/** The words a POSIX shell makes of `command`, without running it. */
function shellWords(command: string): string[] {
  const out = execFileSync('/bin/sh', ['-c', `printf '%s\\0' ${command}`], { encoding: 'utf8' });
  return out.split('\0').slice(0, -1);
}

const app = '/Applications/Vigil at Home.app/Contents/Resources/helper';
const plain = {
  ...hookFiles(app),
  socketPath: '/Users/alex/Library/Application Support/Vigil at Home/run/agent.sock',
  onUnavailable: 'ask' as const,
};

describe('hookSnippet', () => {
  it("is Claude Code's hooks block for pre-flight and hello", () => {
    const s = JSON.parse(hookSnippet(plain)) as Snippet;
    expect(Object.keys(s)).toEqual(['hooks']);
    expect(Object.keys(s.hooks)).toEqual(['PreToolUse', 'SessionStart']);
    const [pre] = s.hooks.PreToolUse;
    expect(pre!.matcher).toBe(PREFLIGHT_MATCHER);
    expect(pre!.hooks).toEqual([
      {
        type: 'command',
        command:
          `"${app}/node" "${app}/vigil-hook.mjs" preflight ` +
          `--socket "${plain.socketPath}" --on-unavailable ask`,
        timeout: HOOK_TIMEOUT_S,
      },
    ]);
    const [start] = s.hooks.SessionStart;
    expect(start!.matcher).toBeUndefined();
    expect(start!.hooks[0]!.command).toBe(
      `"${app}/node" "${app}/vigil-hook.mjs" hello --socket "${plain.socketPath}"`,
    );
    expect(HOOK_TIMEOUT_S).toBe(5);
    for (const tool of ['Bash', 'Write', 'Edit', 'MultiEdit', 'NotebookEdit', 'Read', 'WebFetch'])
      expect(new RegExp(`^(${PREFLIGHT_MATCHER})$`).test(tool)).toBe(true);
    expect(new RegExp(`^(${PREFLIGHT_MATCHER})$`).test('mcp__github__create_issue')).toBe(true);
  });

  it('passes the defer setting through', () => {
    const s = JSON.parse(hookSnippet({ ...plain, onUnavailable: 'defer' })) as Snippet;
    expect(s.hooks.PreToolUse[0]!.hooks[0]!.command).toMatch(/ --on-unavailable defer$/);
  });

  it('stays valid JSON and one shell word per path, whatever the paths hold', () => {
    const odd = {
      nodePath: '/Users/o\'brien/dev "build"/node',
      hookPath: '/tmp/a $HOME `id` $(id) \\ b/vigil-hook.mjs',
      socketPath: '/Users/a b/Library/Application Support/Vigil at Home/run/agent.sock',
      onUnavailable: 'ask' as const,
    };
    const s = JSON.parse(hookSnippet(odd)) as Snippet;
    expect(shellWords(s.hooks.PreToolUse[0]!.hooks[0]!.command)).toEqual([
      odd.nodePath,
      odd.hookPath,
      'preflight',
      '--socket',
      odd.socketPath,
      '--on-unavailable',
      'ask',
    ]);
    expect(shellWords(s.hooks.SessionStart[0]!.hooks[0]!.command)).toEqual([
      odd.nodePath,
      odd.hookPath,
      'hello',
      '--socket',
      odd.socketPath,
    ]);
    expect(
      shellWords(JSON.parse(hookSnippet(plain)).hooks.SessionStart[0].hooks[0].command),
    ).toEqual([plain.nodePath, plain.hookPath, 'hello', '--socket', plain.socketPath]);
  });
});

describe('hookFiles', () => {
  it('points at the signed node and the hook next to it', () => {
    expect(hookFiles('/x/build/helper/dev-arm64')).toEqual({
      nodePath: '/x/build/helper/dev-arm64/node',
      hookPath: '/x/build/helper/dev-arm64/vigil-hook.mjs',
    });
  });
});
