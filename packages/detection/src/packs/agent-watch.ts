import type { Condition, DetectionRuleInput } from '../types.js';
import {
  CREDENTIAL_STORE_GLOBS,
  SCRIPT_RUNNERS,
  SHELLS,
  SUSPEND,
  UNTRUSTED_SIGNING,
} from './macos-core.js';

/**
 * Agent watch: what AI agents on this Mac (Claude Code, Codex, Cursor's
 * agent...) and the programs they start actually do.
 *
 * Vigil's process tracker tags each event with the agent it runs under
 * (`process.agent`) before rules run, so these rules see only agent
 * activity: a person's own terminal is never tagged. Depth 0 is the agent
 * itself; everything it starts is one level deeper.
 *
 * No rule here blocks. Pausing is only offered on launches below the agent
 * (depth > 0) and always names that program, never the agent: stopping the
 * agent would lose the person's session, and its children are what act.
 */

/** When this pack version was written. Rules carry it as createdAt/updatedAt. */
const PACK_DATE = Date.UTC(2026, 9, 1);

type PackRule = Omit<DetectionRuleInput, 'version' | 'origin' | 'createdAt' | 'updatedAt'> & {
  version?: number;
};

function rule(r: PackRule): DetectionRuleInput {
  return { version: 1, origin: 'builtin', createdAt: PACK_DATE, updatedAt: PACK_DATE, ...r };
}

/** The event runs under a watched agent (or Vigil's own helpers). */
const AGENT = { field: 'process.agent.id', op: 'exists' } as const;
/** Started by the agent, not the agent itself. */
const CHILD = { field: 'process.agent.depth', op: 'gt', value: 0 } as const;

/**
 * The shell an agent runs, or one of these tools started directly (not via a
 * shell, so one command raises one alert, on the shell that holds all of it).
 */
const via = (names: string[]): Condition => ({
  any: [
    { field: 'process.name', op: 'in', value: SHELLS },
    {
      all: [
        { field: 'process.name', op: 'in', value: names },
        { not: { field: 'process.parentName', op: 'in', value: SHELLS } },
      ],
    },
  ],
});

/** The command line matches any of these regexes. */
const cmd = (...patterns: string[]): Condition => ({
  field: 'process.commandLine',
  op: 'regex',
  value: patterns,
});

/** Credential files named in a command: cloud keys, SSH private keys, token files. */
export const SECRET_PATH_RE = String.raw`(\.aws/(credentials|config|sso/cache)|\.ssh/id_(rsa|ed25519|ecdsa|dsa)($|[\s"';|&)])|\.config/gcloud/|\.kube/config|\.netrc|\.npmrc|\.docker/config\.json|\.azure/)`;
/** The same files opened directly, plus the browser and keychain stores. */
export const SECRET_FILE_GLOBS = [
  '~/.aws/credentials',
  '~/.aws/config',
  '~/.aws/sso/cache/**',
  '~/.config/gcloud/**',
  '~/.kube/config',
  '~/.netrc',
  '~/.docker/config.json',
  '~/.azure/**',
  ...CREDENTIAL_STORE_GLOBS,
];
/** curl and friends sending data: a form, an upload, a request body. */
export const UPLOAD_RE = String.raw`(\s-[FT]\s?|\s--form\s|\s--upload-file\s|\s--data(-binary|-raw|-urlencode)?\s|\s-d\s)`;
/** Output piped into a network tool, or copied to another host. */
export const NET_SINK_RE = String.raw`(\|\s*(curl|wget|nc|ncat|socat)\b|\b(scp|rsync)\s[^|;&]*:)`;
/** Paste sites, file drops and request catchers. */
export const PASTE_HOST_RE = String.raw`(pastebin\.com|paste\.ee|hastebin\.|0x0\.st|transfer\.sh|termbin\.com|ix\.io|dpaste\.|file\.io|webhook\.site|requestbin\.|pipedream\.net|ngrok(-free)?\.(io|app)|bashupload\.com|temp\.sh)`;
/**
 * Every environment variable piped somewhere. On an exec the command follows
 * `zsh -c ` or a quote, so whitespace and quotes count as a start too.
 */
export const ENV_DUMP_RE = String.raw`(^|[\s;&|('"/])(env|printenv)\s*\|`;
/**
 * Loading a launch item, installing a crontab (`crontab -` reads it from a
 * pipe), or writing into a LaunchAgents folder. Verbs are whole words, so a
 * home folder like /Users/mvalle does not count as `mv`.
 */
export const PERSIST_RE = String.raw`(launchctl\s+(load|bootstrap|submit|enable)\b|crontab\s+(-e|-r|-(\s|$)|[^-\s])|(\b(cp|mv|tee|ln)\b|>)\s*[^|;&]*Library/Launch(Agents|Daemons)/)`;
/**
 * Stopping or editing Vigil or Santa, or switching off macOS protections.
 * Case-insensitive. Paths may escape their spaces (`Vigil\ at\ Home`).
 */
export const TAMPER_RES_NOCASE = [
  String.raw`(^|[\s;&|(])(kill|killall|pkill)\s[^|;&]*(vigil|santa)`,
  String.raw`launchctl\s+(bootout|unload|remove|disable|kill)\b[^|;&]*(vigil|santa)`,
  String.raw`santactl\s+rule\b[^|;&]*--(allow|remove|whitelist)`,
  String.raw`spctl\s+--(master-disable|global-disable|disable|add)\b`,
  String.raw`(tccutil\s+reset|csrutil\s+disable)\b`,
  String.raw`(\b(rm|mv|cp|sqlite3|truncate|chmod|chown|tee)\b|>)\s*[^|;&]*(Vigil\\? at\\? Home|vigil-helper|com\.vigilathome|/var/db/santa)`,
];
/** Case-sensitive: `pfctl -d` turns the firewall off and `-F` flushes it; `pfctl -f` loads rules and is fine. */
export const TAMPER_RE_CASED = String.raw`pfctl\s+-(d\b|F)`;
/** Agent settings files, where hooks, permissions and MCP servers are configured. */
export const AGENT_CONFIG_RE = String.raw`(\.claude/settings[A-Za-z.]*\.json|\.codex/config\.toml|\.mcp\.json|\.cursor/(hooks|mcp)\.json|claude_desktop_config\.json)`;
/** Ways a command changes a file. */
export const WRITE_VERB_RE = String.raw`(sed\s+-i|\btee\b|\bmv\b|\bcp\b|\brm\b|\bln\b|>\s*\S*\.(json|toml)|python3?\s+-c|node\s+-e|perl\s+-[a-z]*i)`;
export const AGENT_CONFIG_GLOBS = [
  '~/.claude/settings*.json',
  '**/.claude/settings*.json',
  '**/.mcp.json',
  '~/.codex/config.toml',
  '~/.cursor/**',
  '**/.cursor/hooks.json',
  '~/Library/Application Support/Claude/claude_desktop_config.json',
];

/** `field` tampers with Vigil, Santa or a macOS protection. */
export const tamper = (field: string): Condition => ({
  any: [
    { field, op: 'regex', value: TAMPER_RES_NOCASE, nocase: true },
    { field, op: 'regex', value: [TAMPER_RE_CASED] },
  ],
});

/** One alert per agent session and command. */
const perCommand = (windowSec: number) => ({
  key: ['process.agent.session', 'process.commandLine'],
  windowSec,
});

export const agentWatchRules: DetectionRuleInput[] = [
  // ------------------------------------------------------------------ alert
  rule({
    id: 'agent-secret-read',
    name: 'AI agent opened a credential file',
    description:
      'An AI agent, or a program it started, opened cloud keys, an SSH private key, a token file, saved browser passwords or the keychain. The tools that use these files (aws, ssh, git, docker...) are left out.',
    mode: 'alert',
    severity: 'high',
    fidelity: 'medium',
    eventKinds: ['file'],
    // Depth 0 counts: the agent's own Read tool opens files as the agent.
    condition: {
      all: [
        AGENT,
        { field: 'op', op: 'in', value: ['open', 'write', 'rename'] },
        { field: 'path', op: 'glob', value: SECRET_FILE_GLOBS },
      ],
    },
    exclusions: [
      {
        field: 'process.name',
        op: 'in',
        value: [
          'aws',
          'gcloud',
          'kubectl',
          'ssh',
          'ssh-add',
          'ssh-keygen',
          'git',
          'git-remote-https',
          'docker',
          'docker-credential-desktop',
          'docker-credential-osxkeychain',
          'az',
          'terraform',
          'gh',
        ],
      },
      { field: 'path', op: 'glob', value: ['~/.ssh/*.pub'] },
    ],
    reasons: [
      '{{process.name}}, running under {{process.agent.id}}, opened {{path}}.',
      'Agents rarely need this file. Text hidden in a web page or a repository can tell one to read it.',
    ],
    dedupe: { key: ['process.agent.session', 'path'], windowSec: 3600 },
    tags: ['agent-watch', 'attack.credential_access', 'attack.t1552.001'],
  }),
  rule({
    id: 'agent-secret-command',
    name: 'AI agent ran a command that reads a credential file',
    description:
      'A command an AI agent ran prints, copies or packs a file holding cloud keys, an SSH private key or a token.',
    mode: 'alert',
    severity: 'medium',
    fidelity: 'medium',
    eventKinds: ['process.exec'],
    condition: {
      all: [
        AGENT,
        CHILD,
        via([
          'cat',
          'less',
          'more',
          'head',
          'tail',
          'cp',
          'base64',
          'xxd',
          'strings',
          'tar',
          'zip',
          'grep',
        ]),
        cmd(SECRET_PATH_RE),
      ],
    },
    reasons: [
      '{{process.agent.id}} ran: {{process.commandLine}}',
      'The command reads a file that holds keys or tokens.',
    ],
    dedupe: perCommand(3600),
    tags: ['agent-watch', 'attack.credential_access', 'attack.t1552.001'],
  }),
  rule({
    id: 'agent-secret-upload',
    name: 'AI agent sending credentials off this Mac',
    description:
      'A command an AI agent ran sends a credential file, or every environment variable, to another computer (a curl upload, a pipe into nc, scp).',
    mode: 'alert',
    severity: 'high',
    fidelity: 'medium',
    eventKinds: ['process.exec'],
    condition: {
      all: [
        AGENT,
        CHILD,
        via(['curl', 'wget', 'nc', 'ncat', 'scp', 'rsync', 'nscurl']),
        {
          any: [
            { all: [cmd(SECRET_PATH_RE), cmd(UPLOAD_RE, NET_SINK_RE)] },
            { all: [cmd(ENV_DUMP_RE), cmd(String.raw`\b(curl|wget|nc)\b`)] },
          ],
        },
      ],
    },
    response: [SUSPEND],
    reasons: [
      '{{process.agent.id}} ran: {{process.commandLine}}',
      'It sends keys or tokens to another computer. Pause it unless you asked for exactly this.',
    ],
    dedupe: perCommand(600),
    tags: ['agent-watch', 'attack.exfiltration', 'attack.t1048'],
  }),
  rule({
    id: 'agent-paste-upload',
    name: 'AI agent uploading to a paste or file-drop site',
    description:
      'A command an AI agent ran uploads data to a paste site, a file drop or a request catcher, a common way to take data out.',
    mode: 'alert',
    severity: 'high',
    fidelity: 'medium',
    eventKinds: ['process.exec'],
    condition: {
      all: [
        AGENT,
        CHILD,
        via(['curl', 'wget', 'nc']),
        cmd(UPLOAD_RE),
        { field: 'process.commandLine', op: 'regex', value: [PASTE_HOST_RE], nocase: true },
      ],
    },
    response: [SUSPEND],
    reasons: [
      '{{process.agent.id}} ran: {{process.commandLine}}',
      'Paste and file-drop sites keep whatever is sent to them where anyone with the link can read it.',
    ],
    dedupe: perCommand(600),
    tags: ['agent-watch', 'attack.exfiltration', 'attack.t1567'],
  }),
  rule({
    id: 'agent-persistence-command',
    name: 'AI agent set something to run at login',
    description:
      'A command an AI agent ran loads a launch agent, installs a crontab, or writes into a LaunchAgents or LaunchDaemons folder.',
    mode: 'alert',
    severity: 'high',
    fidelity: 'medium',
    eventKinds: ['process.exec'],
    condition: {
      all: [AGENT, CHILD, via(['launchctl', 'crontab', 'cp', 'mv', 'tee', 'ln']), cmd(PERSIST_RE)],
    },
    reasons: [
      '{{process.agent.id}} ran: {{process.commandLine}}',
      "What it sets up keeps running after the agent's session ends.",
    ],
    dedupe: perCommand(3600),
    tags: ['agent-watch', 'attack.persistence', 'attack.t1543.001'],
  }),
  rule({
    id: 'agent-guard-tamper',
    name: 'AI agent tampering with Vigil or macOS protections',
    description:
      'A command an AI agent ran stops Vigil or Santa, changes their files, turns off Gatekeeper or the firewall, or resets privacy permissions.',
    mode: 'alert',
    severity: 'high',
    fidelity: 'medium',
    eventKinds: ['process.exec'],
    condition: { all: [AGENT, CHILD, tamper('process.commandLine')] },
    response: [SUSPEND],
    reasons: [
      '{{process.agent.id}} ran: {{process.commandLine}}',
      'It would weaken the protections that watch the agent.',
    ],
    dedupe: perCommand(3600),
    tags: ['agent-watch', 'attack.defense_evasion', 'attack.t1562.001'],
  }),
  rule({
    id: 'agent-hook-config-edit',
    name: "AI agent changing an agent's settings",
    description:
      'A command an AI agent ran edits Claude Code, Codex, Cursor or MCP settings, where hooks, permissions and MCP servers are configured.',
    mode: 'alert',
    severity: 'medium',
    fidelity: 'medium',
    eventKinds: ['process.exec'],
    condition: { all: [AGENT, CHILD, cmd(AGENT_CONFIG_RE), cmd(WRITE_VERB_RE)] },
    reasons: [
      '{{process.agent.id}} ran: {{process.commandLine}}',
      "These settings can switch off Vigil's pre-flight check or give the agent new tools.",
    ],
    dedupe: perCommand(3600),
    tags: ['agent-watch', 'attack.defense_evasion', 'attack.persistence'],
  }),
  rule({
    id: 'agent-keychain-secret',
    name: 'AI agent reading a keychain password',
    description:
      'A command an AI agent ran prints a saved password from the keychain (security find-generic-password -w) or exports keychain items.',
    mode: 'alert',
    severity: 'high',
    fidelity: 'medium',
    eventKinds: ['process.exec'],
    condition: {
      all: [
        AGENT,
        CHILD,
        via(['security']),
        cmd(String.raw`security\s+(find-(generic|internet)-password\b[^|;&]*\s-w\b|export\b)`),
      ],
    },
    response: [SUSPEND],
    reasons: [
      '{{process.agent.id}} ran: {{process.commandLine}}',
      'It prints a saved password where the agent can read it.',
    ],
    dedupe: perCommand(3600),
    tags: ['agent-watch', 'attack.credential_access', 'attack.t1555.001'],
  }),

  // ----------------------------------------------------------------- shadow
  rule({
    id: 'agent-escapes-tree',
    name: 'AI agent started something that outlives it',
    description:
      'A command an AI agent ran detaches from the agent (nohup, setsid, tmux or screen in the background, at, launchctl submit) or hands it to Terminal or AppleScript. Common for dev servers, so it only records.',
    mode: 'shadow',
    severity: 'medium',
    fidelity: 'low',
    eventKinds: ['process.exec'],
    condition: {
      all: [
        AGENT,
        CHILD,
        cmd(
          String.raw`(^|[\s;&|(])(nohup|setsid|disown)\b`,
          String.raw`(screen\s+-[a-zA-Z]*d|tmux\s+new(-session)?\s[^|;&]*-d\b|\bat\s+(now|-f)\b)`,
          String.raw`(launchctl\s+(submit|asuser)\b|open\s+-a\s+"?(Terminal|iTerm)|osascript\b[^|;&]*do\s+(shell\s+)?script)`,
        ),
      ],
    },
    reasons: [
      '{{process.agent.id}} ran: {{process.commandLine}}',
      "What it starts may no longer be tracked as the agent's.",
    ],
    dedupe: perCommand(3600),
    tags: ['agent-watch', 'attack.defense_evasion'],
  }),
  rule({
    id: 'agent-unsigned-first-exec',
    name: 'AI agent ran a new unsigned program from a download or temp folder',
    description:
      'An AI agent started an unsigned program from a temporary or Downloads folder for the first time. Agents build and fetch tools often, so it only records.',
    mode: 'shadow',
    severity: 'medium',
    fidelity: 'low',
    eventKinds: ['process.exec'],
    condition: {
      all: [
        AGENT,
        CHILD,
        { field: 'process.signing', op: 'in', value: UNTRUSTED_SIGNING },
        {
          field: 'process.path',
          op: 'glob',
          value: ['/tmp/**', '/private/tmp/**', '/private/var/folders/**', '~/Downloads/**'],
        },
        { firstSeen: { key: ['process.path'] } },
      ],
    },
    reasons: [
      '{{process.agent.id}} started {{process.path}}, which is not signed.',
      'It is the first time this program ran on this Mac.',
    ],
    tags: ['agent-watch', 'attack.execution'],
  }),
  rule({
    id: 'vigil-ai-spawned-process',
    name: "Vigil's own AI helper started a program",
    description:
      "Vigil's explainer, labeller and rule reviewer run with every tool switched off, so a shell, script or downloader below them means something went wrong. Recorded only, for now.",
    mode: 'shadow',
    severity: 'high',
    fidelity: 'medium',
    eventKinds: ['process.exec'],
    condition: {
      all: [
        { field: 'process.agent.id', op: 'eq', value: 'vigil-self' },
        // Depth 1 is the helper itself (claude, codex); depth 2 is what it starts.
        { field: 'process.agent.depth', op: 'gt', value: 1 },
        {
          field: 'process.name',
          op: 'in',
          value: [...SCRIPT_RUNNERS, 'wget', 'nc', 'scp', 'node', 'npx', 'uvx'],
        },
      ],
    },
    reasons: [
      "{{process.parentName|'An AI helper'}} started {{process.commandLine}} under Vigil.",
      "Vigil's AI helpers have no tools, so they should never start programs.",
    ],
    dedupe: perCommand(3600),
    tags: ['agent-watch', 'attack.execution'],
  }),
];
