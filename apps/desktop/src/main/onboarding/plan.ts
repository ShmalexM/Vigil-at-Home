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
  check: CheckId;
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

export interface PlanInputs {
  /** Model to pull; defaults to the one for this Mac's memory. */
  localModel?: string;
  /** Command that installs Vigil's root helper; unset until the helper ships in the app. */
  helperInstallCommand?: string;
  /** Where the Santa configuration profile was written; unset until blocking ships. */
  santaProfilePath?: string;
}

/**
 * Every setup step, in order. Protection is the same whichever way the AI
 * runs: Santa, osquery and the helper are always local. The mode only
 * changes which AI steps appear.
 */
export function setupPlan(inputs: PlanInputs = {}): StepDef[] {
  const model = inputs.localModel ?? LOCAL_MODEL;
  const size = model === LOCAL_MODEL_SMALL ? 'about 400 MB' : 'about 1 GB';
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
    {
      id: 'ollama',
      group: 'ai',
      title: 'Ollama',
      why: 'Runs a small AI model on this Mac, so event summaries never leave it.',
      modes: LOCAL_AI,
      commands: [
        { label: 'Install Ollama', cmd: 'brew install ollama' },
        {
          label: 'Start it in the background, now and at login',
          cmd: 'brew services start ollama',
        },
      ],
      check: 'ollama',
      checks: 'Ollama answers on 127.0.0.1:11434',
      after: ['homebrew'],
    },
    {
      id: 'ollama-model',
      group: 'ai',
      title: 'Local model',
      why: `${model} is ${size}, picked for this Mac’s memory, and only uses memory while it works. Vigil uses a model you already have instead, if there is one.`,
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
      commands: [{ label: 'Install Codex', cmd: 'brew install --cask codex' }],
      check: 'codex',
      checks: 'codex is installed',
      after: ['homebrew'],
    },
  ];
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
