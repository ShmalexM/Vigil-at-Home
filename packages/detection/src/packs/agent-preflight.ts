import type { Condition, DetectionRuleInput } from '../types.js';
import {
  AGENT_CONFIG_GLOBS,
  AGENT_CONFIG_RE,
  agentWatchRules,
  ENV_DUMP_RE,
  KEYCHAIN_SECRET_RE,
  NET_SINK_RE,
  PASTE_HOST_RE,
  PERSIST_RE,
  SECRET_FILE_GLOBS,
  SECRET_PATH_RE,
  tamper,
  UPLOAD_RE,
  WRITE_VERB_RE,
} from './agent-watch.js';
import { macosCoreRules, PIPE_TO_SHELL_RE } from './macos-core.js';

/**
 * Pre-flight rules: an agent's hook (Claude Code's PreToolUse) asks Vigil
 * before a tool runs, and these rules answer. Block mode denies the step,
 * alert mode asks the person, shadow only records, and no match leaves the
 * agent's own permission prompt in charge. Vigil never answers "allow".
 *
 * Each request is checked with `engine.check`, which leaves no trace, so
 * these rules cannot run actions, count, or learn what is "first seen"
 * (the linter enforces it). Only two rules deny out of the box: sending
 * credentials away and switching off the protections that watch the agent.
 */

/** When this pack version was written. Rules carry it as createdAt/updatedAt. */
const PACK_DATE = Date.UTC(2026, 9, 1);

type PackRule = Omit<
  DetectionRuleInput,
  'version' | 'origin' | 'createdAt' | 'updatedAt' | 'eventKinds' | 'response' | 'tags'
> & { version?: number };

function rule(r: PackRule): DetectionRuleInput {
  return {
    version: 1,
    origin: 'builtin',
    createdAt: PACK_DATE,
    updatedAt: PACK_DATE,
    eventKinds: ['agent.tool_request'],
    response: [],
    tags: ['agent-preflight'],
    ...r,
  };
}

/** Counted by Vigil's agent service, not matched here; see the rule below. */
export const PREFLIGHT_PROBING_RULE_ID = 'preflight-probing';

const BASH = { field: 'tool', op: 'eq', value: 'Bash' } as const;
const WRITES: Condition = {
  field: 'tool',
  op: 'in',
  value: ['Write', 'Edit', 'MultiEdit', 'NotebookEdit'],
};

/** The Bash command matches any of these regexes. */
const command = (...patterns: string[]): Condition => ({
  field: 'command',
  op: 'regex',
  value: patterns,
});
const filePath = (globs: string[]): Condition => ({ field: 'filePath', op: 'glob', value: globs });

export const agentPreflightRules: DetectionRuleInput[] = [
  // ------------------------------------------------------------- block: deny
  rule({
    id: 'preflight-secret-exfil',
    name: 'Agent step would send credentials off this Mac',
    description:
      'Before a Bash step runs: the command reads a credential file and uploads it, pipes it to the network or posts it to a paste site, or sends every environment variable out. Vigil stops the step.',
    mode: 'block',
    severity: 'critical',
    fidelity: 'high',
    condition: {
      any: [
        {
          all: [
            BASH,
            command(SECRET_PATH_RE),
            {
              any: [
                command(UPLOAD_RE, NET_SINK_RE),
                { field: 'command', op: 'regex', value: [PASTE_HOST_RE], nocase: true },
              ],
            },
          ],
        },
        { all: [BASH, command(ENV_DUMP_RE), command(String.raw`\b(curl|wget|nc)\b`)] },
      ],
    },
    reasons: ['The command would send keys or tokens from this Mac to another computer.'],
  }),
  rule({
    id: 'preflight-security-tamper',
    name: 'Agent step would switch off Vigil or macOS protections',
    description:
      "Before a step runs: the command stops or edits Vigil or Santa, turns off Gatekeeper or the firewall, or resets privacy permissions, or the step writes into Vigil's or Santa's files. Vigil stops the step.",
    mode: 'block',
    severity: 'high',
    fidelity: 'high',
    condition: {
      any: [
        { all: [BASH, tamper('command')] },
        {
          all: [
            WRITES,
            filePath([
              '~/Library/Application Support/Vigil at Home/**',
              '/var/run/vigil-helper.sock',
              '/var/db/santa/**',
              '/Applications/Vigil at Home.app/**',
            ]),
          ],
        },
      ],
    },
    reasons: ['The step would weaken the protections that watch the agent.'],
  }),

  // ------------------------------------------------------------- alert: ask
  rule({
    id: 'preflight-agent-config-write',
    name: "Agent step would change an agent's settings",
    description:
      'Before a step runs: it writes Claude Code, Codex, Cursor or MCP settings, where hooks, permissions and MCP servers are configured. Vigil asks you first.',
    mode: 'alert',
    severity: 'high',
    fidelity: 'high',
    condition: {
      any: [
        { all: [WRITES, filePath(AGENT_CONFIG_GLOBS)] },
        { all: [BASH, command(AGENT_CONFIG_RE), command(WRITE_VERB_RE)] },
      ],
    },
    reasons: [
      "The step would change {{filePath|'agent settings'}}, which can switch off this check or add tools.",
    ],
  }),
  rule({
    id: 'preflight-secret-access',
    name: 'Agent step would read a credential file',
    description:
      'Before a step runs: it opens cloud keys, an SSH private key, a token file, saved browser passwords or the keychain. Vigil asks you first.',
    mode: 'alert',
    severity: 'medium',
    fidelity: 'medium',
    condition: {
      any: [
        {
          all: [
            { field: 'tool', op: 'in', value: ['Read', 'Write', 'Edit', 'MultiEdit'] },
            filePath(SECRET_FILE_GLOBS),
          ],
        },
        { all: [BASH, command(SECRET_PATH_RE, KEYCHAIN_SECRET_RE)] },
      ],
    },
    exclusions: [filePath(['~/.ssh/*.pub'])],
    reasons: ["The step would open {{filePath|'a file'}} that holds keys or tokens."],
  }),
  rule({
    id: 'preflight-pipe-to-shell',
    name: 'Agent step would run a downloaded script',
    description:
      'Before a Bash step runs: the command downloads code and runs it straight away, or decodes hidden text into a shell. Vigil asks you first.',
    mode: 'alert',
    severity: 'medium',
    fidelity: 'medium',
    condition: {
      all: [
        BASH,
        {
          any: [
            command(PIPE_TO_SHELL_RE),
            { field: 'command', op: 'contains', value: ['$(curl', '$(wget'] },
            command(String.raw`base64\s+(-d|--decode|-D)[^|]*\|\s*(ba|z|da)?sh\b`),
          ],
        },
      ],
    },
    reasons: ['The command downloads code and runs it straight away.'],
  }),
  rule({
    id: 'preflight-persistence',
    name: 'Agent step would set something to run at login',
    description:
      'Before a step runs: it writes a launch item, loads one, or installs a crontab. Vigil asks you first.',
    mode: 'alert',
    severity: 'high',
    fidelity: 'medium',
    condition: {
      any: [
        {
          all: [
            WRITES,
            filePath([
              '~/Library/LaunchAgents/**',
              '/Library/LaunchAgents/**',
              '/Library/LaunchDaemons/**',
            ]),
          ],
        },
        { all: [BASH, command(PERSIST_RE)] },
      ],
    },
    reasons: [
      "The step would add {{filePath|'a launch item or cron job'}}, which keeps running after the session ends.",
    ],
  }),
  rule({
    id: 'preflight-long-command',
    name: 'Agent step too long to check',
    description:
      'Before a Bash step runs: the command is longer than the 4 KB Vigil reads, so the rest could hide anything. Vigil asks you first.',
    mode: 'alert',
    severity: 'low',
    fidelity: 'low',
    condition: { all: [BASH, { field: 'commandBytes', op: 'gt', value: 4096 }] },
    reasons: ['This command is longer than Vigil checks (4 KB).'],
  }),

  // ----------------------------------------------------------------- shadow
  rule({
    id: 'preflight-shell-profile',
    name: 'Agent step would change a shell startup file',
    description:
      'Before a step runs: it edits or appends to .zshrc, .bashrc or another file every new terminal runs. Common in setup steps, so it only records.',
    mode: 'shadow',
    severity: 'low',
    fidelity: 'low',
    condition: {
      any: [
        {
          all: [
            WRITES,
            filePath([
              '~/.zshrc',
              '~/.zprofile',
              '~/.zshenv',
              '~/.bashrc',
              '~/.bash_profile',
              '~/.profile',
            ]),
          ],
        },
        {
          all: [
            BASH,
            command(String.raw`>>?\s*\S*\.(zshrc|zprofile|zshenv|bashrc|bash_profile|profile)\b`),
          ],
        },
      ],
    },
    reasons: [
      "The step would change {{filePath|'a shell startup file'}}, which runs in every new terminal.",
    ],
  }),

  // ------------------------------------------------- counted by the app (S4)
  rule({
    id: PREFLIGHT_PROBING_RULE_ID,
    name: 'Agent keeps hitting stopped steps',
    description:
      'Counted by Vigil: 5 or more stopped requests in one agent session within 10 minutes.',
    mode: 'alert',
    severity: 'high',
    fidelity: 'medium',
    // A sentinel no tool name can match (they start with a letter). The
    // agent service raises this rule itself; turning it off here stops that.
    condition: { field: 'tool', op: 'eq', value: '#probe' },
    reasons: [
      'Vigil stopped 5 or more steps from one agent session within 10 minutes.',
      'The agent may be looking for a way around your rules.',
    ],
  }),
];

/** Every rule Vigil ships: the macOS core pack, agent watch and pre-flight. */
export const builtinRules: DetectionRuleInput[] = [
  ...macosCoreRules,
  ...agentWatchRules,
  ...agentPreflightRules,
];
