import type {
  ApiKeyProvider,
  CheckId,
  SetupMode,
  SettingsPane,
  StepGroup,
} from '../../shared/setup.js';

/**
 * The small model offered for "run it on this Mac": qwen2.5:1.5b (about 1 GB)
 * with 16 GB of memory or more, qwen2.5:0.5b (about 400 MB) below that. Same
 * rule as `recommendedClassifierModel` in @vigil/ai, which replaces this once
 * that package is in the app.
 */
export const LOCAL_MODEL = 'qwen2.5:1.5b';
export const LOCAL_MODEL_SMALL = 'qwen2.5:0.5b';
const GB = 1024 ** 3;

export function localModelFor(totalMemBytes: number): string {
  return totalMemBytes < 16 * GB ? LOCAL_MODEL_SMALL : LOCAL_MODEL;
}

export interface StepCommand {
  /** What this line does, shown above it. */
  label: string;
  /** Exactly what the user pastes into Terminal. Vigil never runs it. */
  cmd: string;
}

export interface ManualStep {
  text: string;
  pane?: SettingsPane;
}

export interface StepDef {
  id: string;
  group: StepGroup;
  title: string;
  /** One sentence on why Vigil needs this. */
  why: string;
  modes: readonly SetupMode[];
  /** Optional steps never hold up finishing setup. */
  optional?: boolean;
  commands: StepCommand[];
  /** Things only the user can click in System Settings. */
  manual?: ManualStep[];
  /** The check that says the step is done. Unset when Vigil knows itself (`result`). */
  check?: CheckId;
  /** Done or not, from what Vigil itself saw rather than a check of the Mac. */
  result?: { ok: boolean; detail?: string };
  /** What Vigil looks at to decide the step is done, shown to the user. */
  checks: string;
  /** Steps that have to be done first. */
  after?: string[];
  /** Why the step has nothing to run yet, when it has no command or click. */
  unavailable?: string;
}

const ALL: readonly SetupMode[] = ['local', 'cloud', 'both'];
const LOCAL_AI: readonly SetupMode[] = ['local', 'both'];
const CLOUD_AI: readonly SetupMode[] = ['cloud', 'both'];

/** Which package manager a Linux computer uses, from /etc/os-release. */
export type LinuxDistro = 'debian' | 'fedora' | 'other';

/** Debian, Ubuntu and their relatives use apt; Fedora, RHEL and theirs use dnf. */
export function linuxDistro(osRelease: string): LinuxDistro {
  const field = (name: string) =>
    osRelease.match(new RegExp(`^${name}=["']?([^"'\\n]*)`, 'm'))?.[1]?.toLowerCase() ?? '';
  const ids = `${field('ID')} ${field('ID_LIKE')}`.split(/\s+/);
  if (ids.some((id) => id === 'debian' || id === 'ubuntu')) return 'debian';
  if (ids.some((id) => ['fedora', 'rhel', 'centos'].includes(id))) return 'fedora';
  return 'other';
}

export interface PlanInputs {
  /** Which computer the steps are for; defaults to a Mac. */
  platform?: NodeJS.Platform;
  /** On Linux, which package manager the install commands use. */
  distro?: LinuxDistro;
  /** Model to pull; defaults to the one for this Mac's memory. */
  localModel?: string;
  /** Command that installs Vigil's root helper; unset until the helper ships in the app. */
  helperInstallCommand?: string;
  /** Where the Santa configuration profile was written; unset until blocking ships. */
  santaProfilePath?: string;
  /**
   * Set once Claude Code is installed or has been seen on this Mac, which
   * offers its pre-flight hook; `connected` while pre-flight is on and the
   * hook was heard from in the last 7 days; `off` when it was heard from but
   * pre-flight is off.
   */
  claudePreflight?: { connected: boolean; off?: true };
}

/**
 * Every setup step, in order. Protection is the same whichever way the AI
 * runs: Santa, osquery and the helper are always local. The mode only
 * changes which AI steps appear.
 */
export function setupPlan(inputs: PlanInputs = {}): StepDef[] {
  const linux = inputs.platform === 'linux';
  return [
    ...(linux ? linuxProtection(inputs) : macProtection(inputs)),
    ...aiSteps(inputs, linux),
    ...(inputs.claudePreflight ? [claudePreflightStep(inputs.claudePreflight)] : []),
  ];
}

function macProtection(inputs: PlanInputs): StepDef[] {
  return [
    {
      id: 'homebrew',
      group: 'protection',
      title: 'Homebrew',
      why: 'The package manager the other install commands use.',
      modes: ALL,
      commands: [
        {
          label: 'Install Homebrew (it asks for your Mac password)',
          cmd: '/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"',
        },
      ],
      check: 'homebrew',
      checks: 'brew in /opt/homebrew/bin or /usr/local/bin',
    },
    {
      id: 'santa',
      group: 'protection',
      title: 'Santa',
      why: 'Stops a program before it starts when Vigil has a block rule for it. Open source, from North Pole Security.',
      modes: ALL,
      commands: [{ label: 'Install Santa', cmd: 'brew install --cask santa' }],
      check: 'santa.installed',
      checks: '/Applications/Santa.app exists',
      after: ['homebrew'],
    },
    {
      id: 'santa-approve',
      group: 'protection',
      title: 'Allow Santa to run',
      why: 'macOS keeps new security extensions switched off until you allow them.',
      modes: ALL,
      commands: [],
      manual: [
        {
          text: 'Turn on Santa under Login Items & Extensions › Endpoint Security Extensions.',
          pane: 'extensions',
        },
        {
          text: 'Turn on Santa’s extension (com.northpolesec.santa.daemon) under Full Disk Access.',
          pane: 'fullDiskAccess',
        },
      ],
      check: 'santa.running',
      checks: 'santactl status answers',
      after: ['santa'],
    },
    {
      id: 'osquery',
      group: 'protection',
      title: 'osquery',
      why: 'Shows which programs connect where, what listens for connections and which browser extensions you have.',
      modes: ALL,
      commands: [{ label: 'Install osquery', cmd: 'brew install --cask osquery' }],
      check: 'osquery',
      checks: 'osqueryi is installed',
      after: ['homebrew'],
    },
    {
      id: 'helper',
      group: 'protection',
      title: 'Vigil helper',
      why: 'The small root service that carries out blocks, pauses and quarantines, and feeds Santa its rules. Undoing a block always asks for your password.',
      modes: ALL,
      commands: inputs.helperInstallCommand
        ? [
            {
              label: 'Install the helper (asks for your Mac password once)',
              cmd: inputs.helperInstallCommand,
            },
          ]
        : [],
      check: 'helper',
      checks: 'the helper’s socket at /var/run/vigil-helper.sock',
      after: ['santa-approve', 'osquery'],
      unavailable:
        'This build of Vigil doesn’t include the helper. Install Vigil from its DMG, or run pnpm build:helper in the repo and restart Vigil.',
    },
    {
      id: 'santa-profile',
      group: 'protection',
      title: 'Connect Santa to Vigil',
      why: 'Santa only reads its settings from a configuration profile. Vigil’s profile points Santa at the helper on this Mac and keeps it in monitor mode, so it only blocks what Vigil has rules for.',
      modes: ALL,
      commands: inputs.santaProfilePath
        ? [
            {
              label: 'Open Vigil’s Santa profile',
              cmd: `open ${shellQuote(inputs.santaProfilePath)}`,
            },
          ]
        : [],
      manual: inputs.santaProfilePath
        ? [{ text: 'Approve the “Vigil Santa” profile under Device Management.', pane: 'profiles' }]
        : [],
      check: 'santa.profile',
      checks: 'santactl status shows the sync server at 127.0.0.1',
      after: ['helper'],
      unavailable:
        'Vigil makes this profile once the helper is running. It should appear in a few seconds.',
    },
  ];
}

function aiSteps(inputs: PlanInputs, linux: boolean): StepDef[] {
  const model = inputs.localModel ?? LOCAL_MODEL;
  const size = model === LOCAL_MODEL_SMALL ? 'about 400 MB' : 'about 1 GB';
  const computer = linux ? 'computer' : 'Mac';
  const brew = linux ? {} : { after: ['homebrew'] };
  return [
    {
      id: 'ollama',
      group: 'ai',
      title: 'Ollama',
      why: `Runs a small AI model on this ${computer}, so event summaries never leave it.`,
      modes: LOCAL_AI,
      commands: linux
        ? [
            {
              label: 'Install Ollama; it runs in the background, now and after a restart',
              cmd: 'curl -fsSL https://ollama.com/install.sh | sh',
            },
          ]
        : [
            { label: 'Install Ollama', cmd: 'brew install ollama' },
            {
              label: 'Start it in the background, now and at login',
              cmd: 'brew services start ollama',
            },
          ],
      check: 'ollama',
      checks: 'Ollama answers on 127.0.0.1:11434',
      ...brew,
    },
    {
      id: 'ollama-model',
      group: 'ai',
      title: 'Local model',
      why: `${model} is ${size}, picked for this ${computer}’s memory, and only uses memory while it works. Vigil uses a model you already have instead, if there is one.`,
      modes: LOCAL_AI,
      commands: [{ label: 'Download the model', cmd: `ollama pull ${model}` }],
      check: 'ollama.model',
      checks: 'Ollama lists a model',
      after: ['ollama'],
    },
    {
      id: 'claude',
      group: 'ai',
      title: 'Claude Code',
      why: 'Off unless you turn it on. Lets Vigil use your Claude plan, but only when you ask it to explain an alert; everything Vigil does on its own uses an API key, Jev or the local model. Vigil runs your own Claude Code with no file or shell access and never sees your login.',
      modes: CLOUD_AI,
      optional: true,
      commands: [
        { label: 'Install Claude Code', cmd: 'curl -fsSL https://claude.ai/install.sh | bash' },
        { label: 'Sign in with your Claude account', cmd: 'claude auth login' },
      ],
      check: 'claude',
      checks: 'claude is installed and claude auth status says you are signed in',
    },
    {
      id: 'codex',
      group: 'ai',
      title: 'Codex',
      why: 'Uses your ChatGPT plan. Vigil keeps its own Codex folder, so your Codex settings and tools never load, and you sign it in once from Vigil.',
      modes: CLOUD_AI,
      optional: true,
      commands: [
        linux
          ? { label: 'Install Codex (needs Node.js)', cmd: 'sudo npm install -g @openai/codex' }
          : { label: 'Install Codex', cmd: 'brew install --cask codex' },
      ],
      check: 'codex',
      checks: 'codex is installed',
      ...brew,
    },
  ];
}

/** fapolicyd's rules that let everything run that Vigil hasn't blocked. */
export const FAPOLICYD_ALLOW_RULES = '/etc/fapolicyd/rules.d/06-vigil-allow.rules';

/**
 * Loads the rules and starts fapolicyd. "trust = file" first: with the
 * allow-all rule nothing consults fapolicyd's trust list, and the package
 * backends (debdb above all) hash every installed package on each start,
 * for minutes, enforcing nothing until done. The kill skips a stop that
 * would otherwise wait out that hashing (the install may have started it).
 */
export const FAPOLICYD_START =
  "sudo sed -i 's/^trust *=.*/trust = file/' /etc/fapolicyd/fapolicyd.conf; " +
  'sudo systemctl kill --signal=SIGKILL fapolicyd 2>/dev/null; ' +
  'sudo fagenrules --load; sudo systemctl enable fapolicyd && sudo systemctl restart fapolicyd';

/**
 * Linux: fapolicyd blocks by hash before a program runs, osquery watches,
 * and the helper (systemd) carries out blocks and writes both their configs.
 */
function linuxProtection(inputs: PlanInputs): StepDef[] {
  const distro = inputs.distro ?? 'other';
  const install = (pkg: string) =>
    distro === 'debian' ? `sudo apt-get install -y ${pkg}` : `sudo dnf install -y ${pkg}`;
  const osquery: StepCommand[] =
    distro === 'debian'
      ? [
          {
            label: 'Trust osquery’s signing key (fetched by its fingerprint)',
            cmd: 'gpg --keyserver hkps://keyserver.ubuntu.com --recv-keys 1484120AC4E9F8A1A577AEEE97A80C63C9D8B80B && sudo install -d -m 755 /etc/apt/keyrings && gpg --export 1484120AC4E9F8A1A577AEEE97A80C63C9D8B80B | sudo tee /etc/apt/keyrings/osquery.gpg >/dev/null',
          },
          {
            label: 'Add osquery’s package repository',
            cmd: 'echo "deb [signed-by=/etc/apt/keyrings/osquery.gpg] https://pkg.osquery.io/deb deb main" | sudo tee /etc/apt/sources.list.d/osquery.list',
          },
          {
            label: 'Install osquery',
            cmd: 'sudo apt-get update && sudo apt-get install -y osquery',
          },
        ]
      : [
          {
            label: 'Trust osquery’s signing key',
            cmd: 'curl -fsSL https://pkg.osquery.io/rpm/GPG | sudo tee /etc/pki/rpm-gpg/RPM-GPG-KEY-osquery >/dev/null',
          },
          {
            label: 'Add osquery’s package repository',
            cmd: 'curl -fsSL https://pkg.osquery.io/rpm/osquery-s3-rpm.repo | sudo tee /etc/yum.repos.d/osquery.repo >/dev/null',
          },
          {
            label: 'Install osquery',
            cmd: 'sudo dnf install -y --enablerepo=osquery-s3-rpm-repo osquery',
          },
        ];
  return [
    {
      id: 'fapolicyd',
      group: 'protection',
      title: 'fapolicyd',
      why: 'Stops a program before it starts when Vigil has a block rule for it. It comes with your distribution. Vigil sets it to allow everything else, so it only blocks what you block in Vigil.',
      modes: ALL,
      commands: [
        {
          label: 'Let everything run that Vigil hasn’t blocked (do this before installing)',
          cmd: `sudo mkdir -p /etc/fapolicyd/rules.d && echo 'allow perm=any all : all' | sudo tee ${FAPOLICYD_ALLOW_RULES} >/dev/null`,
        },
        ...(distro === 'other' ? [] : [{ label: 'Install fapolicyd', cmd: install('fapolicyd') }]),
        {
          label:
            distro === 'other'
              ? 'Install fapolicyd with your package manager, then load the rules and start it'
              : 'Load the rules and start it, now and after a restart',
          cmd: FAPOLICYD_START,
        },
      ],
      check: 'fapolicyd',
      checks: `fapolicyd is running and ${FAPOLICYD_ALLOW_RULES} exists`,
    },
    {
      id: 'osquery',
      group: 'protection',
      title: 'osquery',
      why: 'Shows which programs start, connect where, what listens for connections and which browser extensions you have.',
      modes: ALL,
      commands: distro === 'other' ? [] : osquery,
      check: 'osquery',
      checks: 'osqueryd is installed in /opt/osquery/bin or /usr/bin',
      ...(distro === 'other'
        ? { unavailable: 'Install osquery from https://osquery.io/downloads, then check again.' }
        : {}),
    },
    {
      id: 'helper',
      group: 'protection',
      title: 'Vigil helper',
      why: 'The small root service that carries out blocks, pauses and quarantines, writes fapolicyd’s block rules and starts osquery. Undoing a block always asks for your password.',
      modes: ALL,
      commands: inputs.helperInstallCommand
        ? [
            {
              label: 'Install the helper (asks for your password once)',
              cmd: inputs.helperInstallCommand,
            },
          ]
        : [],
      check: 'helper',
      checks: 'the helper answers on /run/vigil-helper.sock',
      after: ['fapolicyd', 'osquery'],
      unavailable:
        'This build of Vigil doesn’t include the helper. Install Vigil from its .deb or AppImage, or run pnpm build:helper in the repo and restart Vigil.',
    },
  ];
}

/**
 * Optional, whatever the AI mode: it is about the Claude Code the user runs,
 * not the AI Vigil uses. The hooks are pasted by the user; Vigil never reads
 * or writes Claude Code's own settings.
 */
function claudePreflightStep(p: { connected: boolean; off?: true }): StepDef {
  return {
    id: 'claude-preflight',
    group: 'ai',
    title: 'Claude Code pre-flight checks',
    why: 'Claude Code asks Vigil before it runs a command, writes a file or fetches a page, and Vigil’s rules answer: stop the step, ask you, or leave it to Claude Code. Rules decide, never an AI, and Vigil never answers “allow”.',
    modes: ALL,
    optional: true,
    commands: [],
    manual: [
      {
        text: 'Turn on pre-flight checks, copy the hooks and paste them into your Claude Code settings yourself. Vigil never opens that file.',
      },
      { text: 'Start a new Claude Code session. Vigil shows Connected once the hook says hello.' },
    ],
    result: p.connected
      ? { ok: true, detail: 'The hook checked in within the last 7 days' }
      : p.off
        ? {
            ok: false,
            detail:
              'Pre-flight checks are off. Turn them on below, or remove the hooks from Claude Code.',
          }
        : { ok: false },
    checks:
      'pre-flight checks are on and the hook said hello or asked about a tool call in the last 7 days',
  };
}

export interface KeyDef {
  provider: ApiKeyProvider;
  name: string;
  /** Where to create a key. */
  url?: string;
  /** What Vigil uses it for, in one line. */
  use: string;
  /** Keys from this provider start with this, used to catch pasting the wrong thing. */
  prefix?: string;
  /** The provider needs a base URL too (any OpenAI-compatible gateway). */
  needsBaseUrl?: boolean;
  /** Shown under "More options": OpenRouter is the one key most people need. */
  more?: boolean;
}

/**
 * API keys the cloud setup asks for. All optional: a signed-in Codex needs
 * none, and a Claude plan only answers alerts the user asks about. OpenRouter is the main path, since it also carries Jev;
 * the rest sit under "More options".
 */
export const API_KEYS: readonly KeyDef[] = [
  {
    provider: 'openrouter',
    name: 'OpenRouter',
    url: 'https://openrouter.ai/settings/keys',
    use: 'One key for many models, billed per use, including TypeSafe’s Jev for fast event labelling. Good if you have no Claude or ChatGPT plan.',
    prefix: 'sk-or-',
  },
  {
    provider: 'anthropic',
    name: 'Anthropic API',
    url: 'https://console.anthropic.com/settings/keys',
    use: 'Claude billed per use. Lets Claude explain new alerts on its own and label events with Claude Haiku; your Claude plan is only for alerts you ask about.',
    prefix: 'sk-ant-',
    more: true,
  },
  {
    provider: 'openai',
    name: 'OpenAI API',
    url: 'https://platform.openai.com/api-keys',
    use: 'OpenAI models billed per use, instead of your ChatGPT plan.',
    prefix: 'sk-',
    more: true,
  },
  {
    provider: 'typesafe',
    name: 'TypeSafe key for Jev',
    url: 'https://typesafe.ai',
    more: true,
    use: 'Not needed if you use OpenRouter. Only for calling TypeSafe’s Jev directly. Jev labels events as benign, unusual or suspicious in under a second, and Vigil uses the local model when there’s no key. Vigil sends it event lines, which include file paths and host names. TypeSafe doesn’t train on API data, but it keeps what it receives under its normal retention policy (zero retention is enterprise-only).',
  },
  {
    provider: 'custom',
    name: 'Other OpenAI-compatible gateway',
    use: 'Any gateway that speaks the OpenAI API, such as a company proxy. Needs its address too.',
    needsBaseUrl: true,
    more: true,
  },
];

export function stepsFor(mode: SetupMode, inputs: PlanInputs = {}): StepDef[] {
  return setupPlan(inputs).filter((s) => s.modes.includes(mode));
}

function shellQuote(s: string): string {
  return `'${s.replaceAll("'", `'\\''`)}'`;
}
