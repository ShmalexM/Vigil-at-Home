import { readFileSync } from 'node:fs';
import type { Alert, EventOfKind, SensorEvent, ToolsReply } from '@vigil/core';
import { describe, expect, it, vi } from 'vitest';
import { VIGIL_TOOLS, type AgentSessionView, type AgentView } from '../../shared/agents.js';
import type { EventView } from '../../shared/ipc.js';
import {
  EVENT_DAYS,
  MAX_RESULT_BYTES,
  MAX_ROWS,
  VigilTools,
  eventRow,
  parseSince,
  type VigilToolsSource,
} from './tools.js';

const NOW = Date.UTC(2026, 9, 1, 15);
const DAY = 24 * 60 * 60 * 1000;
const SESSION = '0123456789abcdef';

const alert = (i: number, o: Partial<Alert> = {}): Alert => ({
  id: `a${i}`,
  createdAt: NOW - i * 60_000,
  updatedAt: NOW - i * 60_000,
  ruleId: 'agent-secret-read',
  ruleVersion: 1,
  title: `Claude Code read a cloud secret (${i})`,
  summary: 'cat read /Users/alex/.aws/credentials under Claude Code',
  severity: 'high',
  fidelity: 'medium',
  notify: 'popup',
  status: 'open',
  containment: 'none',
  eventIds: [`e${i}`],
  actionIds: [],
  ...o,
});

const exec = (i: number, command: string): EventOfKind<'process.exec'> => ({
  id: `e${i}`,
  ts: NOW - i * 1000,
  source: 'santa',
  kind: 'process.exec',
  process: {
    pid: 5000 + i,
    ppid: 4999,
    path: '/bin/cat',
    args: command.split(' '),
    parentPath: '/bin/zsh',
    ancestors: ['zsh', '2.0.14'],
    agent: { id: 'claude-code', session: SESSION, depth: 2 },
  },
});

const view = (event: SensorEvent): EventView => ({
  event,
  outcome: {
    checked: 4,
    matches: [{ ruleId: 'r', ruleName: 'Agent read a secret', mode: 'alert' }],
  },
});

const agent: AgentView = {
  id: 'claude-code',
  name: 'Claude Code',
  kind: 'cli',
  origin: 'builtin',
  status: 'active',
  watch: true,
  presence: 'running',
  lastSeenAt: NOW - 1000,
  sessionsToday: 1,
  matchesToday: 2,
  asksToday: 1,
  deniesToday: 1,
  preflightHost: 'claude-code',
  builtin: true,
  edited: false,
};

const session: AgentSessionView = {
  id: SESSION,
  agentId: 'claude-code',
  rootPid: 4000,
  rootPath: '/Users/alex/.local/share/claude/versions/2.0.14',
  startedAt: NOW - DAY / 2,
  lastAt: NOW - 1000,
  events: 3,
  matches: 1,
  asks: 0,
  denies: 0,
  seeded: false,
};

function source(o: Partial<VigilToolsSource> = {}): VigilToolsSource {
  const alerts = Array.from({ length: 60 }, (_, i) => alert(i));
  return {
    now: () => NOW,
    status: () => ({
      protection: {
        level: 'fair',
        reasons: ['The helper is not installed'],
        needsYou: 2,
        sensors: [{ id: 'santa', name: 'Santa', state: 'ok' }],
        simulated: true,
      },
      rules: { disabled: 1, shadow: 4, alert: 30, block: 3 },
      preflight: {
        on: true,
        hookConnected: true,
        lastHookAt: NOW - 1000,
        last24h: { deny: 1, ask: 2, none: 9 },
      },
    }),
    alerts: ({ limit, status }) =>
      alerts.filter((a) => !status || a.status === status).slice(0, limit),
    alert: (id) => alerts.find((a) => a.id === id),
    events: (ids) =>
      ids.map((id) => view(exec(Number(id.slice(1)), 'cat /Users/alex/.aws/credentials'))),
    ruleName: (id) => (id === 'agent-secret-read' ? 'Agent read a cloud or SSH secret' : undefined),
    searchEvents: ({ limit }) => ({
      views: Array.from({ length: limit }, (_, i) => view(exec(i, 'ls /Users/alex/code'))),
      partial: false,
    }),
    agents: () => [agent],
    agentSessions: () => [session],
    agentSession: (id, rows) =>
      id === SESSION
        ? {
            session,
            tree: Array.from({ length: Math.min(rows, 80) }, (_, i) => ({
              pid: 5000 + i,
              ppid: 4000,
              name: 'zsh',
              path: '/bin/zsh',
              ts: NOW - i,
              depth: 1,
              matched: i === 0,
            })),
            events: Array.from({ length: Math.min(rows, 80) }, (_, i) =>
              view(exec(i, 'cat README.md')),
            ),
          }
        : null,
    ...o,
  };
}

type Ok = Extract<ToolsReply, { ok: true }>;
function ok(r: ToolsReply): Record<string, unknown> {
  expect(r).toMatchObject({ v: 1, ok: true });
  return (r as Ok).result as Record<string, unknown>;
}

describe('VigilTools', () => {
  it('lists six read-only tools with JSON Schemas for their arguments', () => {
    const list = new VigilTools(source()).list();
    expect(list.map((t) => t.name)).toEqual(VIGIL_TOOLS.map((t) => t.name));
    for (const t of list) {
      expect(t.inputSchema).toMatchObject({ type: 'object', properties: expect.any(Object) });
      expect(t.inputSchema).not.toHaveProperty('$schema');
      expect(t.annotations).toEqual({
        readOnlyHint: true,
        destructiveHint: false,
        openWorldHint: false,
      });
      expect(t.name).not.toMatch(/allow|release|set|add|remove|delete|update|run|block|check/);
    }
    const get = list.find((t) => t.name === 'get_alert')!;
    expect(get.inputSchema['required']).toEqual(['id']);
  });

  it('caps every list at 50 rows and every result at 64 KB', () => {
    const tools = new VigilTools(source());
    const alerts = (args: Record<string, unknown>) =>
      ok(tools.call('list_alerts', args))['alerts'] as unknown[];
    expect(alerts({})).toHaveLength(20);
    expect(alerts({ limit: MAX_ROWS })).toHaveLength(MAX_ROWS);
    expect(ok(tools.call('list_alerts', { limit: 5 }))['more']).toBe(true);
    expect(tools.call('list_alerts', { limit: MAX_ROWS + 1 })).toMatchObject({ ok: false });

    // Fifty requests with long commands, paths and URLs don't fit in 64 KB:
    // rows come off the end.
    const request = (i: number): SensorEvent => ({
      id: `t${i}`,
      ts: NOW - i,
      source: 'vigil',
      kind: 'agent.tool_request',
      tool: 'Bash',
      command: `echo ${'x'.repeat(4000)}`,
      commandBytes: 4005,
      filePath: `/tmp/${'p'.repeat(1000)}`,
      url: `https://example.com/${'u'.repeat(2000)}`,
      cwd: `/tmp/${'c'.repeat(1000)}`,
      agent: { host: 'claude-code', id: 'claude-code', session: SESSION },
    });
    const long = new VigilTools(
      source({
        searchEvents: ({ limit }) => ({
          views: Array.from({ length: limit }, (_, i) => view(request(i))),
          partial: false,
        }),
      }),
    );
    const result = ok(long.call('search_events', { limit: MAX_ROWS }));
    expect(Buffer.byteLength(JSON.stringify(result))).toBeLessThanOrEqual(MAX_RESULT_BYTES);
    expect(result['truncated']).toBe(true);
    const events = result['events'] as Array<{ command: string; answer: string }>;
    expect(events.length).toBeGreaterThan(10);
    expect(events.length).toBeLessThan(MAX_ROWS);
    // Each long string is clipped too.
    expect(events[0]!.command.length).toBeLessThanOrEqual(1000);
    expect(events[0]!.answer).toBe('ask');

    const s = ok(tools.call('get_agent_session', { id: SESSION }));
    expect(s['tree']).toHaveLength(MAX_ROWS);
    expect(s['events']).toHaveLength(MAX_ROWS);
    expect(s['more']).toBe(true);
  });

  it('redacts home folders and secrets as Vigil’s own AI gets them', () => {
    const tools = new VigilTools(
      source({
        searchEvents: () => ({
          views: [
            view(
              exec(
                1,
                'curl -H Authorization:Bearer sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123 https://x',
              ),
            ),
          ],
          partial: false,
        }),
      }),
    );
    const results = [
      tools.call('list_alerts', {}),
      tools.call('get_alert', { id: 'a1' }),
      tools.call('search_events', { text: 'curl' }),
      tools.call('list_agents', {}),
      tools.call('get_agent_session', { id: SESSION }),
    ].map((r) => JSON.stringify(ok(r)));
    for (const text of results) {
      expect(text).not.toContain('/Users/alex');
      expect(text).not.toMatch(/\balex\b/);
      expect(text).not.toContain('sk-ant-');
    }
    expect(results[1]).toContain('/Users/<user>/.aws/credentials');
    expect(results[2]).toContain('<api-key>');
    expect(results[4]).toContain('/Users/<user>/.local/share/claude');
  });

  it('looks back 7 days at most for events', () => {
    const searchEvents = vi.fn<VigilToolsSource['searchEvents']>(() => ({
      views: [],
      partial: true,
    }));
    const tools = new VigilTools(source({ searchEvents }));
    const floor = NOW - EVENT_DAYS * DAY;
    ok(tools.call('search_events', { since: '30d', kind: 'agents', text: 'curl' }));
    expect(searchEvents).toHaveBeenLastCalledWith(
      expect.objectContaining({
        since: floor,
        kinds: ['agent.tool_request'],
        text: 'curl',
        limit: 20,
      }),
    );
    const r = ok(tools.call('search_events', { since: '2h', kind: 'file' }));
    expect(searchEvents).toHaveBeenLastCalledWith(
      expect.objectContaining({ since: NOW - 2 * 3_600_000, kinds: ['file'] }),
    );
    expect(r['note']).toMatch(/newest/);
    expect(parseSince('2026-10-01T09:00:00Z', NOW)).toBe(Date.UTC(2026, 9, 1, 9));
    expect(tools.call('search_events', { since: 'last tuesday' })).toMatchObject({ ok: false });
    expect(tools.call('search_events', { kind: 'everything' })).toMatchObject({ ok: false });
  });

  it('summarises alerts, status and agents without rule conditions', () => {
    const tools = new VigilTools(
      source({
        alert: (id) =>
          id === 'a1'
            ? alert(1, {
                ai: {
                  provider: 'claude',
                  at: NOW,
                  verdict: 'suspicious',
                  summary: 'An agent read cloud keys.',
                  details: 'It ran cat on the AWS credentials file.',
                  proposalIds: [],
                },
                decision: { at: NOW, verdict: 'expected', remember: false },
              })
            : undefined,
      }),
    );
    const a = ok(tools.call('get_alert', { id: 'a1' }));
    expect(a['alert']).toMatchObject({
      id: 'a1',
      rule: 'Agent read a cloud or SSH secret',
      severity: 'high',
      explanation: 'An agent read cloud keys.',
      explanationDetails: 'It ran cat on the AWS credentials file.',
      aiVerdict: 'suspicious',
      userVerdict: 'expected',
    });
    expect(a['events']).toEqual([
      expect.objectContaining({
        kind: 'process.exec',
        program: '/bin/cat',
        agent: { id: 'claude-code', session: SESSION, depth: 2 },
      }),
    ]);
    const text = JSON.stringify(a);
    for (const word of ['condition', 'exclusions', 'regex', 'glob', 'response']) {
      expect(text).not.toContain(word);
    }
    expect(tools.call('get_alert', { id: 'nope' })).toMatchObject({ ok: false });

    const status = ok(tools.call('vigil_status', {}));
    expect(status).toMatchObject({
      protection: 'fair',
      blocking: expect.stringMatching(/^simulated/),
      rules: { alert: 30, block: 3 },
      preflight: { on: true, last24h: { deny: 1 } },
    });
    const agents = ok(tools.call('list_agents', {}))['agents'] as Array<Record<string, unknown>>;
    expect(agents[0]).toMatchObject({
      id: 'claude-code',
      today: { denies: 1 },
      preflightHook: true,
      latestSessions: [expect.objectContaining({ id: SESSION, agent: 'claude-code' })],
    });
  });

  it('refuses unknown tools and bad arguments, and hides other failures', () => {
    const tools = new VigilTools(
      source({
        agents: () => {
          throw new Error('SQLITE_BUSY at /Users/alex/Library');
        },
      }),
    );
    expect(tools.call('release_block', {})).toMatchObject({ ok: false });
    expect(tools.call('get_alert', {})).toMatchObject({
      ok: false,
      error: expect.stringContaining('id'),
    });
    expect(tools.call('get_agent_session', { id: 'xyz' })).toMatchObject({ ok: false });
    expect(tools.call('list_agents', {})).toEqual({ v: 1, ok: false, error: 'list_agents failed' });
    // Extra arguments are ignored rather than refused.
    expect(tools.call('vigil_status', { verbose: true })).toMatchObject({ ok: true });
  });

  it('never answers with a decision, nor with allow', () => {
    const santa: SensorEvent = {
      id: 's1',
      ts: NOW,
      source: 'santa',
      kind: 'santa.decision',
      target: 'execution',
      decision: 'allow',
      reason: 'ALLOW_CERTIFICATE',
      process: { pid: 7, path: '/Applications/Safari.app/Contents/MacOS/Safari' },
    };
    expect(JSON.stringify(eventRow(santa))).not.toMatch(/allow/i);
    expect(eventRow(santa)).toMatchObject({ santa: 'ran' });

    const tools = new VigilTools(
      source({
        searchEvents: () => ({ views: [{ event: santa, outcome: null }], partial: false }),
      }),
    );
    let seed = 7;
    const rnd = (n: number) => {
      seed = (seed * 1103515245 + 12345) % 2 ** 31;
      return seed % n;
    };
    const pick = <T>(xs: readonly T[]): T => xs[rnd(xs.length)]!;
    const names = [...VIGIL_TOOLS.map((t) => t.name), 'allow', 'allow_all', 'x'];
    const values = [undefined, 1, 0, -1, 51, 'allow', '24h', 'open', 'a1', SESSION, 'file', {}, []];
    const keys = ['id', 'since', 'limit', 'kind', 'text', 'status', 'decision'];
    for (let i = 0; i < 500; i++) {
      const args = Object.fromEntries(
        Array.from({ length: rnd(3) }, () => [pick(keys), pick(values)]),
      );
      const reply = tools.call(pick(names), args);
      expect(Object.keys(reply).sort()).toEqual(
        reply.ok ? ['ok', 'result', 'v'] : ['error', 'ok', 'v'],
      );
      expect(JSON.stringify(reply)).not.toMatch(/allow/i);
    }
  });
});

describe('the tools module source', () => {
  it('reads only: no alerts, helper, executor, rule editor or settings writes', () => {
    const src = readFileSync(new URL('./tools.ts', import.meta.url), 'utf8');
    const imports = [...src.matchAll(/from '([^']+)'/g)].map((m) => m[1]!);
    expect(imports).toEqual([
      '@vigil/core',
      '@vigil/ai/redact',
      'zod',
      '../../shared/agents.js',
      '../../shared/ipc.js',
    ]);
    for (const banned of [
      'AlertService',
      'HelperLink',
      'Executor',
      'RuleEditor',
      'Detector',
      'Store',
      '.run(',
      '.raise(',
      '.decide(',
      '.save(',
      'setMode',
      'setRuleMode',
      'setSetting',
      'insert',
      'upsert',
      'registry',
    ]) {
      expect(src.includes(banned), banned).toBe(false);
    }
  });
});
