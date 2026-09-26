import type { Rule, SensorEvent } from '@vigil/core';
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
  const alert = await core.alerts.raise({
    rule,
    events,
    actions: [
      { kind: 'process.suspend', pid: 51234 },
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
