import type { AgentIdentity } from '@vigil/core';

/**
 * The AI agents Vigil knows out of the box. Matching is deterministic: a
 * process is an agent when its program fits one of these matchers.
 *
 * Identifiers marked VERIFY have not been checked on a Mac yet. The rest
 * were checked on 2026-10-02 against real installs (`codesign -dv` on the
 * binary, and where it really lives). Team and signing IDs appear only once
 * checked. Santa's EXEC line has no signing ID, so those matchers serve
 * sensors that report one; names and paths do the work for Santa.
 */

export interface CatalogEntry extends AgentIdentity {
  /** Where an install shows up, checked with a stat once a day. `~/` is the user's home. */
  installPaths: string[];
  /** The agent's hook can ask Vigil before each tool call. */
  preflightHost?: 'claude-code';
  /**
   * Keychain services (`security find-generic-password -s`) the agent saves
   * its own sign-in under and reads back with its own code. agent-watch lets
   * exactly that read pass (see ownKeychainLogin); the same read from a shell
   * the agent runs for a tool still alerts. Only names seen on a real Mac.
   */
  keychainLogins?: string[];
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

/**
 * Where a Mac app can run from: /Applications, ~/Applications (a user who is
 * not an admin, `brew --cask --appdir`), or translocated, when it was opened
 * from Downloads or a disk image without being moved.
 */
function appGlobs(bundle: string): string[] {
  return [
    `/Applications/${bundle}.app/**`,
    `~/Applications/${bundle}.app/**`,
    `/private/var/folders/**/AppTranslocation/*/d/${bundle}.app/**`,
  ];
}

/** Install locations to look for an app (translocated copies come and go, so they are left out). */
function appInstalls(bundle: string): string[] {
  return [`/Applications/${bundle}.app`, `~/Applications/${bundle}.app`];
}

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
      { teamIds: ['Q6L2SF6YDW'], signingIds: ['com.anthropic.claude-code'] },
      // The native install links ~/.local/bin/claude to ~/.local/share/claude/versions/<version>,
      // so the running program's name is the version number: the path matcher is the one that fits.
      // The second path is the copy the Claude app runs for its Code tab
      // (…/claude-code/<version>/<hash>/claude.app/Contents/MacOS/claude).
      {
        paths: [
          '~/.local/share/claude/versions/*',
          '~/Library/Application Support/Claude/claude-code/**',
        ],
      },
      { names: ['claude'] },
      // VERIFY: the npm install links bin/claude to cli.js (`#!/usr/bin/env node`), so a
      // launch is `node …/bin/claude`, which `names` matches through the script name
      // (match.ts). This matcher is for a direct `node …/claude-code/cli.js` (an IDE).
      { names: ['node'], argGlobs: ['*@anthropic-ai/claude-code*'] },
    ],
    installPaths: ['~/.local/bin/claude', '/opt/homebrew/bin/claude', '/usr/local/bin/claude'],
    preflightHost: 'claude-code',
    // Its claude.ai sign-in and its API key, read with `security` from its own
    // code at every start (seen on a real Mac, 2026-10-02, Claude Code 2.1.280–2.1.286).
    keychainLogins: ['Claude Code-credentials', 'Claude Code'],
  }),
  entry({
    id: 'claude-desktop',
    name: 'Claude app',
    kind: 'app',
    match: [
      { teamIds: ['Q6L2SF6YDW'], signingIds: ['com.anthropic.claudefordesktop'] },
      { paths: appGlobs('Claude') },
    ],
    installPaths: appInstalls('Claude'),
  }),
  entry({
    id: 'codex',
    name: 'Codex CLI',
    kind: 'cli',
    match: [
      { teamIds: ['2DC432GLL2'], signingIds: ['codex'] },
      // The standalone install links ~/.local/bin/codex to
      // ~/.codex/packages/standalone/current/bin/codex. The Codex app runs its own copy
      // (ChatGPT.app/…/CodexCLI.app/Contents/MacOS/codex), which the name also fits.
      { names: ['codex'] },
      { paths: ['~/.codex/packages/standalone/**'] },
      { names: ['node'], argGlobs: ['*@openai/codex*'] }, // VERIFY
    ],
    installPaths: [
      '~/.local/bin/codex',
      '~/.codex/packages/standalone/current/bin/codex',
      '/opt/homebrew/bin/codex',
      '/usr/local/bin/codex',
    ],
  }),
  entry({
    id: 'codex-app',
    name: 'Codex app',
    kind: 'app',
    match: [
      { teamIds: ['2DC432GLL2'], signingIds: ['com.openai.codex'] },
      // The Codex desktop app ships as ChatGPT.app (bundle com.openai.codex); its helpers are
      // named "Codex (Renderer)" and "Codex (Service)". Codex.app is kept in case it is renamed.
      { paths: [...appGlobs('ChatGPT'), ...appGlobs('Codex')] },
    ],
    installPaths: [...appInstalls('ChatGPT'), ...appInstalls('Codex')],
    note: 'Installed as ChatGPT.app.',
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
    // Unsigned: ~/.local/bin/cursor-agent links to ~/.local/share/cursor-agent/versions/<v>/cursor-agent.
    match: [{ names: ['cursor-agent'] }],
    installPaths: ['~/.local/bin/cursor-agent'],
  }),
  entry({
    id: 'opencode',
    name: 'opencode',
    kind: 'cli',
    // Ad hoc signed, installed by its script to ~/.opencode/bin.
    match: [{ names: ['opencode'] }, { paths: ['~/.opencode/bin/*'] }],
    installPaths: [
      '~/.opencode/bin/opencode',
      '/opt/homebrew/bin/opencode',
      '/usr/local/bin/opencode',
    ],
  }),
  // IDEs start off: people type their own commands in the built-in terminal.
  entry({
    id: 'cursor',
    name: 'Cursor',
    kind: 'ide',
    watch: false,
    match: [
      { teamIds: ['VDXQ22DGB9'], signingIds: ['com.todesktop.230313mzl4w4u92'] },
      { paths: appGlobs('Cursor') },
    ],
    installPaths: appInstalls('Cursor'),
    note: "Off by default: commands you type in its terminal would count as the agent's.",
  }),
  entry({
    id: 'vscode',
    name: 'Visual Studio Code',
    kind: 'ide',
    watch: false,
    match: [{ paths: appGlobs('Visual Studio Code') }], // VERIFY
    installPaths: appInstalls('Visual Studio Code'),
    note: "Off by default: commands you type in its terminal would count as the agent's.",
  }),
  // Runtimes are listed so you can see them; they never tag anything.
  entry({
    id: 'ollama',
    name: 'Ollama',
    kind: 'runtime',
    watch: false,
    match: [
      { teamIds: ['3MU9H2V9Y9'], signingIds: ['com.electron.ollama', 'ai.ollama.ollama'] },
      { paths: appGlobs('Ollama') },
      { names: ['ollama'] },
    ],
    installPaths: [
      ...appInstalls('Ollama'),
      '/opt/homebrew/bin/ollama',
      '/usr/local/bin/ollama',
      '~/.local/bin/ollama',
    ],
  }),
];
