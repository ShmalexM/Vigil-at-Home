import type { Connectors } from './connectors.js';
import type { PackService } from './service.js';

/**
 * A pack with some history, for UI work and screenshots
 * (`VIGIL_DEMO=1 pnpm dev`). Development builds only.
 */
export function seedPackDemo(
  pack: PackService,
  connectors: Connectors,
  fixture: string,
  now = Date.now(),
): void {
  // A stand-in issue tracker (fixtures/demo-mcp.mjs) so the connector UI has tools to show.
  // Connector ids are new for each connector, so the demo finds its own by name.
  const github =
    connectors.list().find((c) => c.name === 'GitHub')?.id ??
    connectors.add({ kind: 'stdio', name: 'GitHub', command: 'node', args: [fixture] }).id;
  void pack.refreshConnector(github).catch(() => undefined);
  if (pack.notes({ limit: 1 }).length === 0) demoNotes(pack);
  if (pack.dogs().some((d) => d.role === 'pack')) {
    pack.demoMoods();
    return;
  }
  const bolt = pack.adopt(
    {
      name: 'Bolt',
      breed: 'husky',
      job: 'Every night, read the day’s coding-agent sessions (Claude Code, Codex) and tell me about anything that touched keys, startup items or Vigil itself.',
      schedule: 'nightly',
      tools: ['vigil.list_agents', 'vigil.get_agent_session', 'vigil.search_events'],
    },
    'lead',
  );
  const pip = pack.adopt(
    {
      name: 'Pip',
      breed: 'chihuahua',
      job: 'Every hour, check Downloads for new programs that ran and bark if any are unsigned.',
      schedule: 'hourly',
      tools: ['vigil.search_events', 'vigil.list_alerts'],
    },
    'you',
  );
  const noodle = pack.adopt(
    {
      name: 'Noodle',
      breed: 'dachshund',
      job: 'When asked, dig through the last week of network events for one program and list where it connected.',
      schedule: 'manual',
      tools: ['vigil.search_events'],
    },
    'lead',
  );
  pack.adopt(
    {
      name: 'Waffles',
      breed: 'corgi',
      job: 'Each morning, sum up yesterday’s alerts in three lines.',
      schedule: 'daily',
      tools: ['vigil.list_alerts', 'vigil.get_alert', 'vigil.vigil_status'],
    },
    'you',
  );
  pack.demoChat(now, { bolt: bolt.id, pip: pip.id, noodle: noodle.id, github });
  pack.demoMoods();
}

function demoNotes(pack: PackService): void {
  pack.helperNote('labeller', {
    kind: 'label',
    ok: true,
    ask: 'Label 6 new events',
    lookedAt: [
      'zoom.us started',
      'node connected to registry.npmjs.org',
      'Cursor Helper started',
      'curl connected to 185.220.101.4',
      'python3 touched id_ed25519',
      'Slack started',
    ],
    answer: '2 of 6 stood out',
    reasons: [
      'curl connected to 185.220.101.4 (suspicious): a bare IP on a hosting range, fetched by a shell right after a download.',
      'python3 touched id_ed25519 (unusual): a script reading an SSH key is rare for this Mac.',
    ],
  });
  pack.helperNote('explainer', {
    kind: 'explain',
    ok: true,
    ask: 'Explain the alert “Script read an SSH key”',
    lookedAt: ['The alert, its evidence and the program behind it'],
    answer:
      'Suspicious. A Python script in Downloads read your SSH key, then the same script opened a connection out.',
    reasons: [
      'The script was downloaded today and isn’t signed. Reading a private key and then connecting out is the pattern of a key stealer, though a backup tool could do the same.',
    ],
    provider: 'codex',
    model: 'gpt-5.5',
  });
}
