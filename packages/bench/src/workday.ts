import type { AgentTag, PreflightRequest, ProcessRef, SensorEvent } from '@vigil/core';
import { sessionId, toolRequestEvent } from '@vigil/detection';
import { CLAUDE_CODE, HOME } from './attacks.js';
import { rng, type Rng } from './rng.js';

/**
 * A normal day on a Mac, as sensor events. Two people:
 *
 * - `everyday`: browser, mail, Slack, Zoom, Office, Spotify.
 * - `developer`: all that plus terminals, Homebrew tools (ad-hoc signed on
 *   Apple silicon), builds, dev servers, the odd install script, and Claude
 *   Code sessions (its commands, file edits and pre-flight requests).
 *
 * Most events are routine. A few are legitimate but look like an attack
 * (`lookalike`): a curl | sh installer, `xattr -cr` on an open-source app,
 * a test binary in /tmp, an agent deploying with `scp -i`. Their daily rates
 * are estimates, stated below, so the false-alert numbers are only as good as
 * those rates.
 */
export type Profile = 'everyday' | 'developer';

export interface WorkEvent {
  event: SensorEvent;
  /** Set for legitimate activity that resembles an attack technique. */
  lookalike?: string;
}

const DAY = 86_400_000;
const LAUNCHD = '/sbin/launchd';
const TERMINALS = [
  '/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal',
  '/Applications/iTerm.app/Contents/MacOS/iTerm2',
  '/Applications/Visual Studio Code.app/Contents/MacOS/Electron',
];

const APPLE_DAEMONS = [
  '/usr/libexec/xpcproxy',
  '/System/Library/Frameworks/CoreServices.framework/Frameworks/Metadata.framework/Versions/A/Support/mdworker_shared',
  '/usr/sbin/cfprefsd',
  '/usr/libexec/trustd',
  '/usr/libexec/runningboardd',
  '/System/Library/PrivateFrameworks/SkyLight.framework/Resources/WindowServer',
  '/usr/libexec/lsd',
  '/System/Library/CoreServices/Spotlight.app/Contents/MacOS/Spotlight',
  '/usr/libexec/nsurlsessiond',
  '/System/Library/PrivateFrameworks/CloudDocsDaemon.framework/Versions/A/Support/bird',
  '/usr/libexec/sharingd',
  '/usr/sbin/mDNSResponder',
  '/System/Library/CoreServices/softwareupdated',
  '/usr/libexec/biometrickitd',
];

interface App {
  path: string;
  teamId: string;
  helpers: string[];
}

const APPS: Record<string, App> = {
  chrome: {
    path: '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
    teamId: 'EQHXZ8M8AV',
    helpers: [
      '/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework/Versions/131.0.6778.86/Helpers/Google Chrome Helper (Renderer).app/Contents/MacOS/Google Chrome Helper (Renderer)',
      '/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework/Versions/131.0.6778.86/Helpers/Google Chrome Helper (GPU).app/Contents/MacOS/Google Chrome Helper (GPU)',
    ],
  },
  slack: {
    path: '/Applications/Slack.app/Contents/MacOS/Slack',
    teamId: 'BQR82RBBHL',
    helpers: [
      '/Applications/Slack.app/Contents/Frameworks/Slack Helper (Renderer).app/Contents/MacOS/Slack Helper (Renderer)',
    ],
  },
  zoom: {
    path: '/Applications/zoom.us.app/Contents/MacOS/zoom.us',
    teamId: 'BJ4HAAB9B3',
    helpers: ['/Applications/zoom.us.app/Contents/Frameworks/CptHost.app/Contents/MacOS/CptHost'],
  },
  word: {
    path: '/Applications/Microsoft Word.app/Contents/MacOS/Microsoft Word',
    teamId: 'UBF8T346G9',
    helpers: [
      '/Applications/Microsoft Word.app/Contents/SharedSupport/Microsoft Error Reporting.app/Contents/MacOS/Microsoft Error Reporting',
    ],
  },
  spotify: {
    path: '/Applications/Spotify.app/Contents/MacOS/Spotify',
    teamId: '2FNC3A47ZF',
    helpers: [
      '/Applications/Spotify.app/Contents/Frameworks/Spotify Helper (Renderer).app/Contents/MacOS/Spotify Helper (Renderer)',
    ],
  },
  vscode: {
    path: '/Applications/Visual Studio Code.app/Contents/MacOS/Electron',
    teamId: 'UBF8T346G9',
    helpers: [
      '/Applications/Visual Studio Code.app/Contents/Frameworks/Code Helper (Plugin).app/Contents/MacOS/Code Helper (Plugin)',
    ],
  },
  docker: {
    path: '/Applications/Docker.app/Contents/MacOS/com.docker.backend',
    teamId: '9BNSXJN65R',
    helpers: ['/Applications/Docker.app/Contents/MacOS/com.docker.vmnetd'],
  },
};

const EVERYDAY_APPS = ['chrome', 'slack', 'zoom', 'word', 'spotify'] as const;
const DEV_APPS = ['chrome', 'slack', 'zoom', 'spotify', 'vscode', 'docker'] as const;

const SHELL_COMMANDS = [
  'git status',
  'git pull --rebase',
  'ls -la',
  'npm run build',
  'pnpm test',
  'curl -s https://api.github.com/repos/nodejs/node/releases/latest | jq .tag_name',
  'brew update',
  'python3 -m venv .venv',
  'docker ps',
  'make -j8',
  'grep -rn TODO src',
  'open .',
  'kubectl get pods',
  'ssh devbox uptime',
];

const APPLE_TOOLS = [
  ['/usr/bin/git', 'git', 'status'],
  ['/usr/bin/ssh', 'ssh', 'devbox'],
  ['/usr/bin/make', 'make'],
  ['/usr/bin/curl', 'curl', '-sL', 'https://registry.npmjs.org/react'],
  ['/usr/bin/osascript', 'osascript', '-e', 'tell application "Spotify" to playpause'],
  [
    '/usr/bin/osascript',
    'osascript',
    '-e',
    'display notification "Build finished" with title "make"',
  ],
  ['/usr/bin/security', 'security', 'find-internet-password', '-s', 'github.com', '-w'],
  ['/usr/bin/xattr', 'xattr', '-l', 'README.md'],
  ['/usr/bin/python3', 'python3', 'manage.py', 'runserver'],
];

const BREW_TOOLS = [
  '/opt/homebrew/bin/node',
  '/opt/homebrew/bin/rg',
  '/opt/homebrew/bin/fd',
  '/opt/homebrew/bin/jq',
  '/opt/homebrew/bin/gh',
  '/opt/homebrew/Cellar/python@3.13/3.13.1/Frameworks/Python.framework/Versions/3.13/bin/python3.13',
  '/opt/homebrew/bin/go',
  '/opt/homebrew/bin/terraform',
];

const INSTALL_ONE_LINERS = [
  '/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"',
  "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh",
  'curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.1/install.sh | bash',
  'sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)"',
  'curl -fsSL https://bun.sh/install | bash',
];

const OSS_APPS = ['Rectangle', 'Stats', 'Maccy', 'AltTab', 'Hidden Bar', 'LibreWolf'];

/** The project the developer's coding agent works in. */
const PROJECT = `${HOME}/code/api`;

/** A command a coding agent runs: the shell gets the command, then starts `programs`. */
interface AgentCommand {
  command: string;
  programs: Array<[path: string, args: string[], signing: ProcessRef['signing']]>;
  /** Files a program opens: the first one, or `programs[opener]`. */
  opens?: string[];
  opener?: number;
  lookalike?: string;
  /** How often it comes up, against the others in its list (1 when unset). */
  weight?: number;
}

const GIT = '/usr/bin/git';
const SSH = '/usr/bin/ssh';
const NODE = '/opt/homebrew/bin/node';
const SSH_KEY = `${HOME}/.ssh/id_ed25519`;

/** What a coding agent runs most of the time, weighted by how often (an estimate). */
const AGENT_COMMANDS: AgentCommand[] = [
  { command: 'git status', programs: [[GIT, ['git', 'status'], 'apple']], weight: 5 },
  { command: 'git diff --stat', programs: [[GIT, ['git', 'diff', '--stat'], 'apple']], weight: 3 },
  { command: 'git diff src/', programs: [[GIT, ['git', 'diff', 'src/'], 'apple']], weight: 2 },
  {
    command: 'git log --oneline -10',
    programs: [[GIT, ['git', 'log', '--oneline', '-10'], 'apple']],
    weight: 2,
  },
  {
    command: 'git add -A && git commit -m "Fix the users route"',
    programs: [
      [GIT, ['git', 'add', '-A'], 'apple'],
      [GIT, ['git', 'commit', '-m', 'Fix the users route'], 'apple'],
    ],
    weight: 2,
  },
  {
    command: 'rg -n "TODO" src',
    programs: [['/opt/homebrew/bin/rg', ['rg', '-n', 'TODO', 'src'], 'adhoc']],
    weight: 4,
  },
  { command: 'ls -la', programs: [['/bin/ls', ['ls', '-la'], 'apple']], weight: 2 },
  {
    command: 'npm test',
    programs: [[NODE, ['node', '/opt/homebrew/bin/npm', 'test'], 'adhoc']],
    weight: 5,
  },
  {
    command: 'npm run build',
    programs: [[NODE, ['node', '/opt/homebrew/bin/npm', 'run', 'build'], 'adhoc']],
    weight: 2,
  },
  {
    command: 'npx tsc --noEmit',
    programs: [[NODE, ['node', '/opt/homebrew/bin/npx', 'tsc', '--noEmit'], 'adhoc']],
    weight: 2,
  },
  { command: 'cat README.md', programs: [['/bin/cat', ['cat', 'README.md'], 'apple']] },
  {
    command: 'cat package.json',
    programs: [['/bin/cat', ['cat', 'package.json'], 'apple']],
    weight: 2,
  },
  {
    command: "sed -n '1,80p' src/server.ts",
    programs: [['/usr/bin/sed', ['sed', '-n', '1,80p', 'src/server.ts'], 'apple']],
    weight: 2,
  },
  {
    command: 'find src -name "*.ts" | head -50',
    programs: [
      ['/usr/bin/find', ['find', 'src', '-name', '*.ts'], 'apple'],
      ['/usr/bin/head', ['head', '-50'], 'apple'],
    ],
  },
];

/**
 * The share of agent commands that are look-alikes, about one in fourteen (an
 * estimate). Each shares words with credential theft or tampering but is
 * ordinary work, so neither pre-flight nor agent watch should say anything.
 */
const AGENT_LOOKALIKE_SHARE = 0.07;
const AGENT_LOOKALIKES: AgentCommand[] = [
  {
    command: 'aws sts get-caller-identity',
    programs: [['/usr/local/bin/aws', ['aws', 'sts', 'get-caller-identity'], 'developer_id']],
    opens: [`${HOME}/.aws/config`, `${HOME}/.aws/credentials`],
    lookalike: 'agent runs the aws CLI, which reads its keys',
    weight: 2,
  },
  // An SSH key handed to the tool that uses it.
  {
    command: 'ssh -i ~/.ssh/id_ed25519 -T git@github.com',
    programs: [[SSH, ['ssh', '-i', SSH_KEY, '-T', 'git@github.com'], 'apple']],
    opens: [SSH_KEY],
    lookalike: 'agent tests an SSH key (ssh -i)',
    weight: 2,
  },
  {
    command: 'scp -i ~/.ssh/id_ed25519 ./dist/app.tgz deploy@staging.example.com:/srv/releases/',
    programs: [
      [
        '/usr/bin/scp',
        ['scp', '-i', SSH_KEY, './dist/app.tgz', 'deploy@staging.example.com:/srv/releases/'],
        'apple',
      ],
      [
        SSH,
        [
          'ssh',
          '-i',
          SSH_KEY,
          '-l',
          'deploy',
          'staging.example.com',
          'scp',
          '-t',
          '/srv/releases/',
        ],
        'apple',
      ],
    ],
    opens: [SSH_KEY],
    opener: 1,
    lookalike: 'agent deploys with scp -i',
  },
  {
    command:
      'rsync -av -e "ssh -i ~/.ssh/id_ed25519" ./build/ deploy@staging.example.com:/srv/app/',
    programs: [
      [
        '/usr/bin/rsync',
        [
          'rsync',
          '-av',
          '-e',
          'ssh -i ~/.ssh/id_ed25519',
          './build/',
          'deploy@staging.example.com:/srv/app/',
        ],
        'apple',
      ],
      [
        SSH,
        ['ssh', '-i', SSH_KEY, '-l', 'deploy', 'staging.example.com', 'rsync', '--server'],
        'apple',
      ],
    ],
    opens: [SSH_KEY],
    opener: 1,
    lookalike: 'agent deploys with rsync -e "ssh -i"',
  },
  {
    // git runs GIT_SSH_COMMAND through sh.
    command: 'GIT_SSH_COMMAND="ssh -i ~/.ssh/id_ed25519" git push origin main',
    programs: [
      [GIT, ['git', 'push', 'origin', 'main'], 'apple'],
      [
        '/bin/sh',
        [
          '/bin/sh',
          '-c',
          'ssh -i ~/.ssh/id_ed25519 "$@"',
          'ssh -i ~/.ssh/id_ed25519',
          'git@github.com',
        ],
        'apple',
      ],
      [SSH, ['ssh', '-i', SSH_KEY, 'git@github.com', "git-receive-pack 'sam/api.git'"], 'apple'],
    ],
    opens: [SSH_KEY],
    opener: 2,
    lookalike: 'agent pushes with GIT_SSH_COMMAND="ssh -i"',
  },
  {
    command: 'ssh-add --apple-use-keychain ~/.ssh/id_ed25519',
    programs: [['/usr/bin/ssh-add', ['ssh-add', '--apple-use-keychain', SSH_KEY], 'apple']],
    opens: [SSH_KEY],
    lookalike: 'agent adds an SSH key to the agent (ssh-add)',
  },
  {
    command: 'ssh-keygen -y -f ~/.ssh/id_ed25519 > ~/.ssh/id_ed25519.pub',
    programs: [['/usr/bin/ssh-keygen', ['ssh-keygen', '-y', '-f', SSH_KEY], 'apple']],
    opens: [SSH_KEY],
    lookalike: 'agent rebuilds a public key (ssh-keygen -y)',
  },
  {
    command: 'chmod 600 ~/.ssh/id_ed25519',
    programs: [['/bin/chmod', ['chmod', '600', SSH_KEY], 'apple']],
    lookalike: 'agent fixes an SSH key mode (chmod 600)',
  },
  {
    command: 'kubectl --kubeconfig ~/.kube/config get pods',
    programs: [
      [
        '/opt/homebrew/bin/kubectl',
        ['kubectl', '--kubeconfig', `${HOME}/.kube/config`, 'get', 'pods'],
        'adhoc',
      ],
    ],
    opens: [`${HOME}/.kube/config`],
    lookalike: 'agent runs kubectl --kubeconfig',
  },
  // The environment filtered, and a network call that is a separate command.
  {
    command: 'env | grep -i proxy; curl -sI https://registry.npmjs.org',
    programs: [
      ['/usr/bin/env', ['env'], 'apple'],
      ['/usr/bin/grep', ['grep', '-i', 'proxy'], 'apple'],
      ['/usr/bin/curl', ['curl', '-sI', 'https://registry.npmjs.org'], 'apple'],
    ],
    lookalike: 'agent checks proxy variables, then the registry',
  },
  {
    command: 'printenv | grep PORT && curl -s localhost:3000/health',
    programs: [
      ['/usr/bin/printenv', ['printenv'], 'apple'],
      ['/usr/bin/grep', ['grep', 'PORT'], 'apple'],
      ['/usr/bin/curl', ['curl', '-s', 'localhost:3000/health'], 'apple'],
    ],
    lookalike: 'agent checks the port, then the health endpoint',
  },
  {
    command: 'tccutil reset Camera com.example.myapp',
    programs: [['/usr/bin/tccutil', ['tccutil', 'reset', 'Camera', 'com.example.myapp'], 'apple']],
    lookalike: "agent resets the camera permission of the app it's building",
    weight: 0.5,
  },
  {
    command: "jq '.mcpServers | keys' .mcp.json > servers.json",
    programs: [['/opt/homebrew/bin/jq', ['jq', '.mcpServers | keys', '.mcp.json'], 'adhoc']],
    opens: [`${PROJECT}/.mcp.json`],
    lookalike: 'agent lists the MCP servers with jq',
    weight: 0.5,
  },
];

/**
 * Steps that name a credential file for another reason, about once a week
 * (`agentSecretPath`, an estimate). Pre-flight cannot tell them from a read
 * and asks; where a program then opens the file (awk, curl), agent watch
 * reports it too.
 */
const AGENT_SECRET_PATHS: AgentCommand[] = [
  {
    command: 'docker run -d -v ~/.kube/config:/root/.kube/config:ro bitnami/kubectl get pods',
    programs: [
      [
        '/usr/local/bin/docker',
        [
          'docker',
          'run',
          '-d',
          '-v',
          `${HOME}/.kube/config:/root/.kube/config:ro`,
          'bitnami/kubectl',
          'get',
          'pods',
        ],
        'developer_id',
      ],
    ],
    lookalike: 'agent mounts the kubeconfig into a container',
  },
  {
    // `test` is a shell builtin: nothing else starts.
    command: 'test -d ~/.config/gcloud/ && echo yes',
    programs: [],
    lookalike: 'agent checks that gcloud is set up',
  },
  {
    command: "awk -F= '/region/ {print $2}' ~/.aws/config",
    programs: [
      ['/usr/bin/awk', ['awk', '-F=', '/region/ {print $2}', `${HOME}/.aws/config`], 'apple'],
    ],
    opens: [`${HOME}/.aws/config`],
    lookalike: 'agent reads the AWS region from its config',
  },
  {
    command: 'curl --netrc-file ~/.netrc -s -d @body.json https://api.example.com/v1/items',
    programs: [
      [
        '/usr/bin/curl',
        [
          'curl',
          '--netrc-file',
          `${HOME}/.netrc`,
          '-s',
          '-d',
          '@body.json',
          'https://api.example.com/v1/items',
        ],
        'apple',
      ],
    ],
    opens: [`${HOME}/.netrc`],
    lookalike: 'agent logs in to an API from .netrc (curl --netrc-file)',
  },
];

/** One of `xs`, in proportion to its weight. */
function pickWeighted(r: Rng, xs: readonly AgentCommand[]): AgentCommand {
  let x = r.next() * xs.reduce((sum, c) => sum + (c.weight ?? 1), 0);
  for (const c of xs) if ((x -= c.weight ?? 1) < 0) return c;
  return xs[xs.length - 1]!;
}

/** The person asked the agent to install a tool the way its site says to. */
const AGENT_INSTALL: AgentCommand = {
  command: 'curl -fsSL https://bun.sh/install | bash',
  programs: [
    ['/usr/bin/curl', ['curl', '-fsSL', 'https://bun.sh/install'], 'apple'],
    ['/bin/bash', ['bash'], 'apple'],
  ],
  lookalike: 'agent runs an install one-liner you asked for (curl | bash)',
};

const AGENT_EDITS = ['src/server.ts', 'src/routes/users.ts', 'src/db.ts', 'test/users.test.ts'];
/** Seeds the agent sessions' own random stream (plus the day number). */
const AGENT_SEED = 0x5e55_1000;

function proc(r: Rng, path: string, over: Partial<ProcessRef> = {}): ProcessRef {
  const name = path.split('/').pop() ?? path;
  return { pid: r.int(300, 99_000), ppid: r.int(1, 4000), path, args: [name], uid: 501, ...over };
}

function appProc(r: Rng, app: App, helper = false): ProcessRef {
  const path = helper ? r.pick(app.helpers) : app.path;
  return proc(r, path, {
    signing: 'developer_id',
    teamId: app.teamId,
    signingId: `${app.teamId}.app`,
    parentPath: helper ? app.path : LAUNCHD,
  });
}

/** A time during the working day, in ms. */
function workTime(r: Rng, dayStart: number): number {
  // Mostly 9:00-18:00, some evening use.
  const hour = r.next() < 0.85 ? 9 + r.next() * 9 : 18 + r.next() * 5;
  return dayStart + Math.floor(hour * 3_600_000);
}

function anyTime(r: Rng, dayStart: number): number {
  return dayStart + Math.floor(r.next() * DAY);
}

let seq = 0;
const nextId = () => `wd-${++seq}`;

function exec(ts: number, process: ProcessRef): SensorEvent {
  return { id: nextId(), ts, source: 'santa', kind: 'process.exec', process };
}

function randomIp(r: Rng): string {
  // Public-looking addresses from big providers' ranges; never on the threat lists.
  const prefixes = [
    '142.250',
    '17.253',
    '151.101',
    '104.16',
    '52.84',
    '13.107',
    '140.82',
    '185.199',
  ];
  return `${r.pick(prefixes)}.${r.int(0, 255)}.${r.int(1, 254)}`;
}

/** Daily rates (events per day) for each profile. */
const RATES: Record<Profile, Record<string, number>> = {
  everyday: {
    appleDaemon: 6000,
    appHelper: 1800,
    appleTool: 60,
    shell: 20,
    brewTool: 0,
    build: 0,
    connection: 2500,
    browserFiles: 400,
    documents: 40,
    agentSession: 0,
    // Look-alikes (estimates)
    installOneLiner: 0,
    xattrClear: 1 / 90,
    tmpBinary: 0,
    unsignedOss: 1 / 60,
    brewPythonSshKey: 0,
    ytdlpCookies: 0,
    newLaunchAgent: 1 / 14,
    devServer: 0,
    newExtension: 1 / 30,
    grepDocuments: 0,
    agentInstall: 0,
    agentSecretPath: 0,
  },
  developer: {
    appleDaemon: 8000,
    appHelper: 3000,
    appleTool: 1500,
    shell: 1200,
    brewTool: 2500,
    build: 400,
    connection: 6000,
    browserFiles: 400,
    documents: 20,
    // Claude Code sessions of 10-30 commands and edits each: 100-200 tool calls a day.
    agentSession: 8,
    installOneLiner: 1 / 7,
    xattrClear: 1 / 7,
    tmpBinary: 0.7,
    unsignedOss: 1 / 14,
    brewPythonSshKey: 1 / 7,
    ytdlpCookies: 1 / 30,
    newLaunchAgent: 1 / 7,
    devServer: 2,
    newExtension: 1 / 30,
    grepDocuments: 1 / 14,
    agentInstall: 1 / 14,
    agentSecretPath: 1 / 7,
  },
};

export function workdayRates(profile: Profile): Readonly<Record<string, number>> {
  return RATES[profile];
}

/** One day of events for this profile, in time order. */
export function workday(profile: Profile, dayStart: number, r: Rng): WorkEvent[] {
  const rate = RATES[profile];
  const apps = (profile === 'developer' ? DEV_APPS : EVERYDAY_APPS).map((k) => APPS[k]!);
  const out: WorkEvent[] = [];
  const n = (k: string) => r.poisson(rate[k] ?? 0);
  const count = (k: string) => {
    // Poisson is slow for large rates; use a normal-ish spread instead.
    const x = rate[k] ?? 0;
    return x > 30 ? Math.max(0, Math.round(x + (r.next() - 0.5) * 2 * Math.sqrt(x))) : n(k);
  };
  const push = (event: SensorEvent, lookalike?: string) =>
    out.push(lookalike ? { event, lookalike } : { event });

  for (let i = count('appleDaemon'); i > 0; i--)
    push(
      exec(
        anyTime(r, dayStart),
        proc(r, r.pick(APPLE_DAEMONS), { signing: 'apple', ppid: 1, parentPath: LAUNCHD }),
      ),
    );
  for (let i = count('appHelper'); i > 0; i--)
    push(exec(workTime(r, dayStart), appProc(r, r.pick(apps), r.next() < 0.9)));
  for (let i = count('appleTool'); i > 0; i--) {
    const [path, ...args] = r.pick(APPLE_TOOLS);
    push(
      exec(
        workTime(r, dayStart),
        proc(r, path!, { args, signing: 'apple', parentPath: r.pick(['/bin/zsh', '/bin/bash']) }),
      ),
    );
  }
  for (let i = count('shell'); i > 0; i--)
    push(
      exec(
        workTime(r, dayStart),
        proc(r, '/bin/zsh', {
          args: ['zsh', '-c', r.pick(SHELL_COMMANDS)],
          signing: 'apple',
          parentPath: r.pick(TERMINALS),
        }),
      ),
    );
  for (let i = count('brewTool'); i > 0; i--)
    push(
      exec(
        workTime(r, dayStart),
        proc(r, r.pick(BREW_TOOLS), { signing: 'adhoc', parentPath: '/bin/zsh' }),
      ),
    );
  for (let i = count('build'); i > 0; i--)
    push(
      exec(
        workTime(r, dayStart),
        proc(
          r,
          r.next() < 0.5
            ? `${HOME}/code/api/target/debug/api`
            : `/private/var/folders/x7/k2m0v1s12_g1r8r2x0q0000gn/T/go-build${r.int(1e6, 9e6)}/b001/exe/main`,
          { signing: 'adhoc', parentPath: '/opt/homebrew/bin/go' },
        ),
      ),
    );
  for (let i = count('connection'); i > 0; i--) {
    const app = r.pick(apps);
    push({
      id: nextId(),
      ts: workTime(r, dayStart),
      source: 'osquery',
      kind: 'network.connection',
      direction: 'outbound',
      protocol: 'tcp',
      remoteAddress: randomIp(r),
      remotePort: 443,
      process: appProc(r, app, r.next() < 0.5),
    });
  }
  for (let i = count('browserFiles'); i > 0; i--) {
    const f = r.pick(['Cookies', 'Login Data', 'Web Data']);
    push({
      id: nextId(),
      ts: workTime(r, dayStart),
      source: 'santa',
      kind: 'file',
      op: 'open',
      path: `${HOME}/Library/Application Support/Google/Chrome/Default/${f}`,
      process: appProc(r, APPS['chrome']!),
    });
  }
  for (let i = count('documents'); i > 0; i--)
    push({
      id: nextId(),
      ts: workTime(r, dayStart),
      source: 'santa',
      kind: 'file',
      op: 'open',
      path: `${HOME}/Documents/Report ${r.int(1, 40)}.docx`,
      process: appProc(r, APPS['word']!),
    });

  // ------------------------------------------------------------ look-alikes
  for (let i = n('installOneLiner'); i > 0; i--)
    push(
      exec(
        workTime(r, dayStart),
        proc(r, '/bin/zsh', {
          args: ['zsh', '-c', r.pick(INSTALL_ONE_LINERS)],
          signing: 'apple',
          parentPath: r.pick(TERMINALS),
        }),
      ),
      'install one-liner (curl | sh)',
    );
  for (let i = n('xattrClear'); i > 0; i--)
    push(
      exec(
        workTime(r, dayStart),
        proc(r, '/usr/bin/xattr', {
          args: ['xattr', '-cr', `/Applications/${r.pick(OSS_APPS)}.app`],
          signing: 'apple',
          parentPath: '/bin/zsh',
        }),
      ),
      'xattr -cr on an open-source app',
    );
  for (let i = n('tmpBinary'); i > 0; i--)
    push(
      exec(
        workTime(r, dayStart),
        proc(r, `/private/tmp/t${r.int(1000, 9999)}/a.out`, {
          signing: 'adhoc',
          parentPath: '/bin/zsh',
        }),
      ),
      'test binary compiled into /tmp',
    );
  for (let i = n('unsignedOss'); i > 0; i--) {
    const name = r.pick(OSS_APPS);
    push(
      exec(
        workTime(r, dayStart),
        proc(r, `/Applications/${name}.app/Contents/MacOS/${name}`, {
          signing: 'adhoc',
          parentPath: LAUNCHD,
          ppid: 1,
          quarantine: { originUrl: `https://github.com/example/${name}/releases`, agent: 'Safari' },
        }),
      ),
      'unsigned open-source app from GitHub',
    );
  }
  for (let i = n('brewPythonSshKey'); i > 0; i--)
    push(
      {
        id: nextId(),
        ts: workTime(r, dayStart),
        source: 'santa',
        kind: 'file',
        op: 'open',
        path: `${HOME}/.ssh/id_ed25519`,
        process: proc(r, BREW_TOOLS[5]!, {
          args: ['python3.13', '-m', 'fabric', 'deploy'],
          signing: 'adhoc',
          parentPath: '/bin/zsh',
        }),
      },
      'deploy script (Homebrew Python) reads an SSH key',
    );
  for (let i = n('ytdlpCookies'); i > 0; i--)
    push(
      {
        id: nextId(),
        ts: workTime(r, dayStart),
        source: 'santa',
        kind: 'file',
        op: 'open',
        path: `${HOME}/Library/Application Support/Google/Chrome/Default/Cookies`,
        process: proc(r, BREW_TOOLS[5]!, {
          args: ['python3.13', '/opt/homebrew/bin/yt-dlp', '--cookies-from-browser', 'chrome'],
          signing: 'adhoc',
          parentPath: '/bin/zsh',
        }),
      },
      'yt-dlp --cookies-from-browser',
    );
  for (let i = n('newLaunchAgent'); i > 0; i--) {
    const item = r.pick([
      [
        'com.google.keystone.agent',
        '/Users/sam/Library/Google/GoogleSoftwareUpdate/GoogleSoftwareUpdate.bundle/Contents/Resources/GoogleSoftwareUpdateAgent.app/Contents/MacOS/GoogleSoftwareUpdateAgent',
      ],
      [
        'us.zoom.updater',
        '/Library/Application Support/zoom.us/ZoomUpdater.app/Contents/MacOS/ZoomUpdater',
      ],
      [
        'com.docker.helper',
        '/Applications/Docker.app/Contents/Library/LaunchServices/com.docker.vmnetd',
      ],
      ['com.spotify.webhelper', '/Applications/Spotify.app/Contents/MacOS/SpotifyWebHelper'],
      [
        `com.example.menubar${r.int(1, 99)}`,
        `/Applications/${r.pick(OSS_APPS)}.app/Contents/MacOS/Launcher`,
      ],
    ] as const);
    push(
      {
        id: nextId(),
        ts: workTime(r, dayStart),
        source: 'osquery',
        kind: 'persistence',
        change: 'added',
        mechanism: 'launch_agent',
        path: `${HOME}/Library/LaunchAgents/${item[0]}.plist`,
        label: item[0],
        program: item[1],
        programArgs: [item[1]],
      },
      'app installs an updater launch agent',
    );
  }
  for (let i = n('devServer'); i > 0; i--)
    push(
      {
        id: nextId(),
        ts: workTime(r, dayStart),
        source: 'osquery',
        kind: 'network.listen',
        protocol: 'tcp',
        localAddress: r.next() < 0.5 ? '0.0.0.0' : '::',
        localPort: r.next() < 0.7 ? r.pick([3000, 5173, 8000, 8080, 4200]) : r.int(3001, 9999),
        process: proc(r, BREW_TOOLS[0]!, { signing: 'adhoc', parentPath: '/bin/zsh' }),
      },
      'dev server on all interfaces',
    );
  for (let i = n('newExtension'); i > 0; i--) {
    const ext = r.pick([
      [
        'nngceckbapebfimnlniiiahkandclblb',
        'Bitwarden',
        ['<all_urls>', 'storage', 'nativeMessaging'],
      ],
      ['fmkadmapgofadopljbjfkapdkoienihi', 'React Developer Tools', ['<all_urls>', 'scripting']],
      ['cjpalhdlnbpafiamejdnhcphjbkeiagm', 'uBlock Origin', ['<all_urls>', 'webRequest']],
      ['aeblfdkhhhdcdjpifhhbdiojplfjncoa', '1Password', ['<all_urls>', 'nativeMessaging']],
    ] as const);
    push(
      {
        id: nextId(),
        ts: workTime(r, dayStart),
        source: 'osquery',
        kind: 'browser.extension',
        change: 'added',
        browser: 'chrome',
        extensionId: ext[0],
        name: ext[1],
        permissions: [...ext[2]],
      },
      'well-known extension installed',
    );
  }
  for (let i = n('grepDocuments'); i > 0; i--) {
    const t = workTime(r, dayStart);
    const p = proc(r, BREW_TOOLS[1]!, {
      args: ['rg', 'invoice', `${HOME}/Documents`],
      signing: 'adhoc',
    });
    for (let j = 0; j < 120; j++)
      push(
        {
          id: nextId(),
          ts: t + j * 50,
          source: 'santa',
          kind: 'file',
          op: 'open',
          path: `${HOME}/Documents/Archive/doc-${j}.pdf`,
          process: p,
        },
        'ripgrep search in Documents',
      );
  }

  // ------------------------------------------------------------ AI agents
  // Agent sessions draw from their own stream, seeded by the day, so adding
  // them left the rest of the workload exactly as it was. Their pids sit above
  // the random ones (300-99,000), so no other event's parent falls inside an
  // agent's tree: 200 per session, per day.
  const day = Math.floor(dayStart / DAY);
  const ra = rng(AGENT_SEED + day);
  const pidBase = 100_000 + (day % 100) * 10_000;
  let session = 0;
  for (let i = ra.poisson(rate['agentSession'] ?? 0); i > 0; i--) {
    const steps: Array<AgentCommand | string> = [];
    for (let j = ra.int(10, 30); j > 0; j--)
      steps.push(
        ra.next() < 0.3
          ? ra.pick(AGENT_EDITS)
          : pickWeighted(ra, ra.next() < AGENT_LOOKALIKE_SHARE ? AGENT_LOOKALIKES : AGENT_COMMANDS),
      );
    agentSession(ra, workTime(ra, dayStart), pidBase + 200 * session++, steps, push);
  }
  for (let i = ra.poisson(rate['agentInstall'] ?? 0); i > 0; i--)
    agentSession(ra, workTime(ra, dayStart), pidBase + 200 * session++, [AGENT_INSTALL], push);
  for (let i = ra.poisson(rate['agentSecretPath'] ?? 0); i > 0; i--)
    agentSession(
      ra,
      workTime(ra, dayStart),
      pidBase + 200 * session++,
      [ra.pick(AGENT_SECRET_PATHS)],
      push,
    );

  out.sort((a, b) => a.event.ts - b.event.ts);
  return out;
}

/**
 * One Claude Code session in a terminal. The agent starts, then works
 * through `steps`: a command goes to Vigil's pre-flight check first (its
 * hook), then runs as `zsh -c`; a file name is a Write or Edit in the
 * project. Pids are explicit, from `basePid` up: the terminal shell that
 * started the agent (never seen), the agent, then what it starts.
 */
function agentSession(
  r: Rng,
  start: number,
  basePid: number,
  steps: Array<AgentCommand | string>,
  push: (event: SensorEvent, lookalike?: string) => void,
): void {
  const agent: ProcessRef = {
    pid: basePid + 1,
    ppid: basePid,
    path: CLAUDE_CODE,
    args: ['claude'],
    uid: 501,
    signing: 'developer_id',
    parentPath: '/bin/zsh',
  };
  push(exec(start, agent));
  // What the tracker will tag the session with, for the hook's requests.
  const tag: AgentTag = {
    id: 'claude-code',
    session: sessionId('claude-code', agent.pid, start),
    depth: 0,
  };
  let pid = agent.pid;
  let t = start;
  const request = (ts: number, req: Pick<PreflightRequest, 'tool'> & Partial<PreflightRequest>) =>
    toolRequestEvent(
      {
        v: 1,
        method: 'preflight.check',
        host: 'claude-code',
        hookSession: `bench-${basePid}`,
        ppid: agent.pid,
        cwd: PROJECT,
        ...req,
      },
      { id: nextId(), ts, tag },
    );
  for (const step of steps) {
    t += r.int(5, 60) * 1000;
    if (typeof step === 'string') {
      const filePath = `${PROJECT}/${step}`;
      const contentBytes = r.int(200, 8000);
      push(request(t, { tool: r.next() < 0.5 ? 'Write' : 'Edit', filePath, contentBytes }));
      push({
        id: nextId(),
        ts: t + 50,
        source: 'santa',
        kind: 'file',
        op: 'write',
        path: filePath,
        process: agent,
      });
      continue;
    }
    const l = step.lookalike;
    push(
      request(t, {
        tool: 'Bash',
        command: step.command,
        commandBytes: Buffer.byteLength(step.command),
      }),
      l,
    );
    const shell: ProcessRef = {
      pid: ++pid,
      ppid: agent.pid,
      path: '/bin/zsh',
      args: ['/bin/zsh', '-c', step.command],
      uid: 501,
      signing: 'apple',
      parentPath: agent.path,
    };
    push(exec(t + 300, shell), l);
    const programs = step.programs.map(([path, args, signing], k) => {
      const p: ProcessRef = {
        pid: ++pid,
        ppid: shell.pid,
        path,
        args,
        uid: 501,
        signing,
        parentPath: shell.path,
      };
      push(exec(t + 350 + k * 10, p), l);
      return p;
    });
    for (const path of step.opens ?? [])
      push(
        {
          id: nextId(),
          ts: t + 500,
          source: 'santa',
          kind: 'file',
          op: 'open',
          path,
          process: programs[step.opener ?? 0]!,
        },
        l,
      );
  }
}
