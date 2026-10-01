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
  if (!connectors.list().some((c) => c.id === 'github')) {
    connectors.add({ kind: 'stdio', name: 'GitHub', command: 'node', args: [fixture] });
  }
  void pack.refreshConnector('github').catch(() => undefined);
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
  pack.demoChat(now, { bolt: bolt.id, pip: pip.id, noodle: noodle.id });
  pack.demoMoods();
}
