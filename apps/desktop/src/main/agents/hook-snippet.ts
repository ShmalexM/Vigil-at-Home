// The Claude Code hooks the user pastes into their own Claude Code settings so
// the pre-flight hook runs before tool calls, and the MCP server entry that
// gives the user's own agents Vigil's read-only tools. Vigil only shows this
// text: it never reads or writes an agent's configuration, which can hold API
// keys.

import { join } from 'node:path';
import type { McpSnippets } from '../../shared/agents.js';

/** The tools Claude Code asks the pre-flight hook about. */
export const PREFLIGHT_MATCHER = 'Bash|Write|Edit|MultiEdit|NotebookEdit|Read|WebFetch|mcp__.*';

/** Seconds Claude Code waits for the hook. The hook gives up on Vigil after 1.5 s. */
export const HOOK_TIMEOUT_S = 5;

export interface HookSnippetInput {
  nodePath: string;
  hookPath: string;
  socketPath: string;
  onUnavailable: 'ask' | 'defer';
}

/**
 * The signed node and the hook script in the app's helper folder: what
 * `helperBundleDir()` returns, Contents/Resources/helper in the app or
 * build/helper/dev-<arch> in a development build.
 */
export function hookFiles(bundleDir: string): { nodePath: string; hookPath: string } {
  return { nodePath: join(bundleDir, 'node'), hookPath: join(bundleDir, 'vigil-hook.mjs') };
}

/** One shell word in double quotes, with `"`, `$`, backtick and backslash escaped. */
export function doubleQuote(s: string): string {
  return `"${s.replace(/["$`\\]/g, '\\$&')}"`;
}

/** One shell word in single quotes, for a command the user pastes into Terminal. */
export function singleQuote(s: string): string {
  return `'${s.replace(/'/g, `'\\''`)}'`;
}

/** A TOML basic string. JSON's escapes are TOML's, except that TOML also escapes DEL. */
export function tomlString(s: string): string {
  return JSON.stringify(s).replace(/\u007f/g, '\\u007F');
}

export interface McpSnippetInput {
  nodePath: string;
  hookPath: string;
  socketPath: string;
}

/**
 * Vigil as a stdio MCP server, `vigil-hook mcp --socket <path>` run by the
 * app's own node: as a `claude mcp add-json` command, as a `.mcp.json` file
 * (Claude Code projects, Cursor) and as a table for Codex's config.toml.
 */
export function mcpSnippet(i: McpSnippetInput): McpSnippets {
  const args = [i.hookPath, 'mcp', '--socket', i.socketPath];
  const server = { type: 'stdio', command: i.nodePath, args };
  return {
    claudeCommand: `claude mcp add-json vigil ${singleQuote(JSON.stringify(server))}`,
    mcpJson: JSON.stringify({ mcpServers: { vigil: server } }, null, 2),
    codexToml: [
      '[mcp_servers.vigil]',
      `command = ${tomlString(i.nodePath)}`,
      `args = [${args.map(tomlString).join(', ')}]`,
    ].join('\n'),
  };
}

/** The `hooks` block for Claude Code, as pretty JSON. */
export function hookSnippet(i: HookSnippetInput): string {
  const run = (...args: string[]) =>
    [doubleQuote(i.nodePath), doubleQuote(i.hookPath), ...args].join(' ');
  const socket = doubleQuote(i.socketPath);
  const command = (line: string) => ({ type: 'command', command: line, timeout: HOOK_TIMEOUT_S });
  return JSON.stringify(
    {
      hooks: {
        PreToolUse: [
          {
            matcher: PREFLIGHT_MATCHER,
            hooks: [
              command(run('preflight', '--socket', socket, '--on-unavailable', i.onUnavailable)),
            ],
          },
        ],
        SessionStart: [{ hooks: [command(run('hello', '--socket', socket))] }],
      },
    },
    null,
    2,
  );
}
