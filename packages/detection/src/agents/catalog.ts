import type { AgentIdentity } from '@vigil/core';

/**
 * The AI agents Vigil knows out of the box. Matching is deterministic: a
 * process is an agent when its program fits one of these matchers.
 *
 * Every identifier here is marked VERIFY until it has been checked on a Mac
 * (`codesign -dv` on the binary, and the same program's Santa EXEC line).
 * Team IDs are left out until then: a wrong one would match nothing, or
 * worse, the wrong thing.
 */

export interface CatalogEntry extends AgentIdentity {
  /** Where an install shows up, checked with a stat once a day. `~/` is the user's home. */
  installPaths: string[];
  /** The agent's hook can ask Vigil before each tool call. */
  preflightHost?: 'claude-code';
}

/** Vigil's own process tree (its AI helpers). Reserved: never in the catalogue, never a user's id. */
export const VIGIL_SELF = 'vigil-self';

/**
 * An MCP server Vigil starts for the pack (a connector the user added). It
 * runs the user's program, not Vigil's, so it is watched like an agent and
 * never shares Vigil's own tag. Reserved like VIGIL_SELF.
 */
export const VIGIL_CONNECTOR = 'vigil-connector';

/** When this catalogue version was written. Entries carry it as createdAt/updatedAt. */
const CATALOG_DATE = Date.UTC(2026, 9, 1);

type Entry = Omit<CatalogEntry, 'origin' | 'status' | 'createdAt' | 'updatedAt' | 'watch'> & {
  watch?: boolean;
};

function entry(e: Entry): CatalogEntry {
  return {
    origin: 'builtin',
    status: 'active',
    watch: true,
    createdAt: CATALOG_DATE,
    updatedAt: CATALOG_DATE,
    ...e,
  };
}

export const AGENT_CATALOG: readonly CatalogEntry[] = [
  entry({
    id: 'claude-code',
    name: 'Claude Code',
    kind: 'cli',
    match: [
      // VERIFY: the native install links ~/.local/bin/claude to a versioned binary.
      { names: ['claude'] },
      { paths: ['~/.local/share/claude/versions/*'] },
      // VERIFY: the npm install runs as node with the package's cli.js.
      { names: ['node'], argGlobs: ['*@anthropic-ai/claude-code*'] },
    ],
    installPaths: ['~/.local/bin/claude', '/opt/homebrew/bin/claude', '/usr/local/bin/claude'],
    preflightHost: 'claude-code',
  }),
  entry({
    id: 'claude-desktop',
    name: 'Claude app',
    kind: 'app',
    match: [{ paths: ['/Applications/Claude.app/**'] }], // VERIFY
    installPaths: ['/Applications/Claude.app'],
  }),
  entry({
    id: 'codex',
    name: 'Codex CLI',
    kind: 'cli',
    match: [
      { names: ['codex'] }, // VERIFY
      { names: ['node'], argGlobs: ['*@openai/codex*'] }, // VERIFY
    ],
    installPaths: ['/opt/homebrew/bin/codex', '/usr/local/bin/codex'],
  }),
  entry({
    id: 'codex-app',
    name: 'Codex app',
    kind: 'app',
    match: [{ paths: ['/Applications/Codex.app/**'] }], // VERIFY
    installPaths: ['/Applications/Codex.app'],
  }),
  entry({
    id: 'copilot-cli',
    name: 'GitHub Copilot CLI',
    kind: 'cli',
    match: [
      { names: ['copilot'] }, // VERIFY
      { names: ['node'], argGlobs: ['*@github/copilot*'] }, // VERIFY
    ],
    installPaths: ['/opt/homebrew/bin/copilot', '/usr/local/bin/copilot'],
  }),
  entry({
    id: 'gemini-cli',
    name: 'Gemini CLI',
    kind: 'cli',
    match: [
      { names: ['gemini'] }, // VERIFY
      { names: ['node'], argGlobs: ['*@google/gemini-cli*'] }, // VERIFY
    ],
    installPaths: ['/opt/homebrew/bin/gemini', '/usr/local/bin/gemini'],
  }),
  entry({
    id: 'cursor-agent',
    name: 'Cursor Agent',
    kind: 'cli',
    match: [{ names: ['cursor-agent'] }], // VERIFY
    installPaths: ['~/.local/bin/cursor-agent'],
  }),
  // IDEs start off: people type their own commands in the built-in terminal.
  entry({
    id: 'cursor',
    name: 'Cursor',
    kind: 'ide',
    watch: false,
    match: [{ paths: ['/Applications/Cursor.app/**'] }], // VERIFY
    installPaths: ['/Applications/Cursor.app'],
    note: "Off by default: commands you type in its terminal would count as the agent's.",
  }),
  entry({
    id: 'vscode',
    name: 'Visual Studio Code',
    kind: 'ide',
    watch: false,
    match: [{ paths: ['/Applications/Visual Studio Code.app/**'] }], // VERIFY
    installPaths: ['/Applications/Visual Studio Code.app'],
    note: "Off by default: commands you type in its terminal would count as the agent's.",
  }),
  // Runtimes are listed so you can see them; they never tag anything.
  entry({
    id: 'ollama',
    name: 'Ollama',
    kind: 'runtime',
    watch: false,
    match: [
      { paths: ['/Applications/Ollama.app/**'] }, // VERIFY
      { names: ['ollama'] },
    ],
    installPaths: ['/Applications/Ollama.app', '/opt/homebrew/bin/ollama', '/usr/local/bin/ollama'],
  }),
];
