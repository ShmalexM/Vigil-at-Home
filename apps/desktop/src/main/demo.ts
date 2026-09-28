import { newId, type Rule, type SensorEvent } from '@vigil/core';
import type { EventOutcome } from '../shared/ipc.js';
import type { VigilCore } from './service.js';

/**
 * Sample rules and one blocked detection, for UI work before the sensors and
 * rule packs land. Development builds only (`VIGIL_DEMO=1 pnpm dev`).
 */
export async function seedDemo(core: VigilCore, now = Date.now()): Promise<void> {
  const base = {
    version: 1,
    tags: [],
    createdAt: now,
    updatedAt: now,
    response: [],
    exclusions: [],
    reasons: [],
  };
  const rules: Rule[] = [
    {
      ...base,
      id: 'demo.unsigned-from-downloads',
      name: 'Unsigned program started from Downloads',
      description:
        'A program with no valid signature ran from ~/Downloads and made a network connection.',
      origin: 'builtin',
      mode: 'block',
      severity: 'high',
      fidelity: 'high',
      eventKinds: ['process.exec'],
      condition: {
        all: [
          { field: 'process.path', op: 'glob', value: '/Users/*/Downloads/**' },
          { field: 'process.signing', op: 'in', value: ['unsigned', 'adhoc', 'invalid'] },
        ],
      },
      response: [{ kind: 'process.suspend', pid: '{{process.pid}}' }],
      tags: ['T1204.002'],
    },
    {
      ...base,
      id: 'demo.launch-agent-curl',
      name: 'Launch agent that pipes curl to a shell',
      description: 'A new launch agent runs curl and pipes the result into sh or bash.',
      origin: 'builtin',
      mode: 'alert',
      severity: 'high',
      fidelity: 'medium',
      eventKinds: ['persistence'],
      condition: { field: 'programArgs', op: 'contains', value: 'curl' },
    },
    {
      ...base,
      id: 'demo.ai-node-postinstall-ssh',
      name: 'npm install script reads ~/.ssh',
      description: 'A node process started by npm install opened a file under ~/.ssh.',
      origin: 'ai',
      mode: 'shadow',
      severity: 'medium',
      fidelity: 'low',
      eventKinds: ['file'],
      condition: {
        all: [
          { field: 'path', op: 'glob', value: '/Users/*/.ssh/*' },
          { field: 'process.parentPath', op: 'endsWith', value: '/npm' },
        ],
      },
      provenance: {
        provider: 'claude',
        rationale:
          'Seen twice this week during package installs; no legitimate package needs SSH keys.',
        sampleEventIds: [],
      },
    },
  ];
  for (const r of rules) core.store.upsertRule(r);

  const events: SensorEvent[] = [
    {
      id: `demo-exec-${now}`,
      ts: now - 2000,
      source: 'osquery',
      kind: 'process.exec',
      process: {
        pid: 51234,
        ppid: 501,
        path: '/Users/you/Downloads/ZoomInstallerFull/zoom_update',
        args: ['zoom_update', '--silent', '--connect', '185.220.101.44:443'],
        signing: 'unsigned',
        sha256: '9f2c4e1b0d7a3c55e8f1a2b6c4d9e0f1a7b3c5d2e4f6a8b0c1d3e5f7a9b2c4d6',
        parentPath: '/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder',
        user: 'you',
      },
    },
    {
      id: `demo-net-${now}`,
      ts: now - 1500,
      source: 'osquery',
      kind: 'network.connection',
      direction: 'outbound',
      protocol: 'tcp',
      remoteAddress: '185.220.101.44',
      remotePort: 443,
      process: { pid: 51234, path: '/Users/you/Downloads/ZoomInstallerFull/zoom_update' },
    },
  ];
  const rule = rules[0]!;
  const checked = rules.length;
  seedFeed(core, now, checked, rules[2]!);
  for (const e of events) {
    core.ingest(e, {
      checked,
      matches: [{ ruleId: rule.id, ruleName: rule.name, mode: 'block' }],
    });
  }
  const alert = await core.alerts.raise({
    rule,
    events,
    actions: [
      {
        kind: 'process.suspend',
        pid: 51234,
        path: '/Users/you/Downloads/ZoomInstallerFull/zoom_update',
      },
      { kind: 'network.block', address: '185.220.101.44' },
    ],
    title: 'Unsigned "zoom_update" from Downloads connected out',
    summary:
      'An unsigned program in your Downloads folder, named like a Zoom updater, started and connected to 185.220.101.44. Vigil paused it and blocked that address.',
    subject: {
      kind: 'process',
      label: 'zoom_update',
      path: events[0]!.kind === 'process.exec' ? events[0]!.process.path : '',
    },
  });
  core.alerts.recordAssessment(alert.id, {
    provider: 'Claude',
    at: now,
    verdict: 'likely_malicious',
    confidence: 0.8,
    summary:
      'Real Zoom updates are signed by Zoom Video Communications and live in /Applications. This one is unsigned, sits in Downloads and talks to a Tor exit node. Keep it blocked.',
    proposalIds: [],
  });
}

// ---------------------------------------------------------------- the feed

const HOME = '/Users/you';
const APPS = {
  safari: '/Applications/Safari.app/Contents/MacOS/Safari',
  slack: '/Applications/Slack.app/Contents/MacOS/Slack',
  code: '/Applications/Visual Studio Code.app/Contents/Frameworks/Code Helper.app/Contents/MacOS/Code Helper',
  git: '/usr/bin/git',
  node: '/opt/homebrew/bin/node',
  npm: '/opt/homebrew/bin/npm',
  zsh: '/bin/zsh',
  mdworker:
    '/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/Metadata.framework/Versions/A/Support/mdworker_shared',
};

type Maker = (ts: number) => SensorEvent;

/** Ordinary things a Mac does all day, so the feed looks like a real one. */
const EVERYDAY: Maker[] = [
  (ts) => exec(ts, APPS.git, ['git', 'status'], 'apple', APPS.zsh),
  (ts) => exec(ts, APPS.git, ['git', 'fetch', 'origin'], 'apple', APPS.zsh),
  (ts) => exec(ts, APPS.node, ['node', 'server.js'], 'developer_id', APPS.zsh),
  (ts) => exec(ts, APPS.mdworker, ['mdworker_shared', '-s', 'mdworker'], 'apple', '/sbin/launchd'),
  (ts) => exec(ts, APPS.code, ['Code Helper', '--type=utility'], 'developer_id', APPS.code),
  (ts) => net(ts, APPS.slack, '3.33.186.1', 'wss-primary.slack.com', 443),
  (ts) => net(ts, APPS.safari, '17.253.144.10', 'www.apple.com', 443),
  (ts) => net(ts, APPS.git, '140.82.112.3', 'github.com', 443),
  (ts) => net(ts, APPS.node, '104.16.24.35', 'registry.npmjs.org', 443),
  (ts) => net(ts, APPS.code, '13.107.5.80', 'marketplace.visualstudio.com', 443),
  (ts) => ({
    id: newId(ts),
    ts,
    source: 'santa',
    kind: 'file',
    op: 'write',
    path: `${HOME}/Library/Application Support/Slack/Cookies`,
    process: { pid: 812, path: APPS.slack, signing: 'developer_id', teamId: 'BQR82RBBHL' },
  }),
];

function exec(
  ts: number,
  path: string,
  args: string[],
  signing: 'apple' | 'developer_id',
  parentPath: string,
): SensorEvent {
  return {
    id: newId(ts),
    ts,
    source: 'osquery',
    kind: 'process.exec',
    process: { pid: 20000 + (ts % 9000), path, args, signing, parentPath, user: 'you' },
  };
}

function net(ts: number, path: string, ip: string, host: string, port: number): SensorEvent {
  return {
    id: newId(ts),
    ts,
    source: 'osquery',
    kind: 'network.connection',
    direction: 'outbound',
    protocol: 'tcp',
    remoteAddress: ip,
    remoteHost: host,
    remotePort: port,
    process: { pid: 700 + (ts % 300), path },
  };
}

/** An hour of history, including a new login item and one shadow-rule match. */
function seedFeed(core: VigilCore, now: number, checked: number, shadow: Rule): void {
  const quiet: EventOutcome = { checked, matches: [] };
  for (let i = 90; i > 0; i--) {
    const ts = now - i * 40_000;
    core.ingest(EVERYDAY[i % EVERYDAY.length]!(ts), quiet);
  }
  core.ingest(
    {
      id: newId(now - 1_900_000),
      ts: now - 1_900_000,
      source: 'osquery',
      kind: 'persistence',
      change: 'added',
      mechanism: 'launch_agent',
      path: `${HOME}/Library/LaunchAgents/com.docker.helper.plist`,
      label: 'com.docker.helper',
      program: '/Applications/Docker.app/Contents/MacOS/com.docker.helper',
    },
    quiet,
  );
  core.ingest(
    {
      id: newId(now - 600_000),
      ts: now - 600_000,
      source: 'santa',
      kind: 'file',
      op: 'open',
      path: `${HOME}/.ssh/known_hosts`,
      process: {
        pid: 31337,
        path: APPS.node,
        args: ['node', 'install.js'],
        parentPath: APPS.npm,
        signing: 'developer_id',
      },
    },
    { checked, matches: [{ ruleId: shadow.id, ruleName: shadow.name, mode: 'shadow' }] },
  );
}

/** Keep the demo feed moving: one ordinary event every couple of seconds. */
export function startDemoFeed(core: VigilCore): () => void {
  let n = 0;
  const checked = core.store.listRules().filter((r) => r.mode !== 'disabled').length - 1;
  const timer = setInterval(() => {
    core.ingest(EVERYDAY[n++ % EVERYDAY.length]!(Date.now()), { checked, matches: [] });
  }, 2500);
  return () => clearInterval(timer);
}
