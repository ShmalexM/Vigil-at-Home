// The Agents page's plain helpers and tool-rule templates. They live in the
// renderer, which has no Node test setup of its own, so they are checked here
// against the real rule language: every template must save as a valid rule
// that lints clean and asks on the step it was written for.
import { describe, expect, it } from 'vitest';
import { AgentId, AgentMatcher, type PreflightRequest } from '@vigil/core';
import {
  AGENT_CATALOG,
  DetectionEngine,
  DetectionRule,
  compileRule,
  decide,
  lintRule,
  memoryStores,
  toolRequestEvent,
} from '@vigil/detection';
import type { AgentMatcherView, TreeNode } from '../shared/agents.js';
import { Route } from '../shared/ipc.js';
import { TOOL_RULE_TEMPLATES, uniqueRuleId } from '../renderer/src/agent-templates.js';
import {
  activityRoute,
  agentIdFor,
  agentRoute,
  describeMatcher,
  matchersFromRows,
  originLabel,
  parseActivityParam,
  parseAgentParam,
  rowsFromMatchers,
  treeOrder,
} from '../renderer/src/views/agents-format.js';

const T = Date.UTC(2026, 9, 1);
const CWD = '/Users/sam/code/shop';

/** A template's JSON as the rule editor saves it (it adds the bookkeeping fields). */
function saved(json: string): DetectionRule {
  const draft = JSON.parse(json) as Record<string, unknown>;
  return DetectionRule.parse({ ...draft, version: 1, origin: 'user', createdAt: T, updatedAt: T });
}

function template(id: string) {
  return TOOL_RULE_TEMPLATES.find((t) => t.id === id)!;
}

let n = 0;
function answer(rule: DetectionRule, req: Partial<PreflightRequest> & { tool: string }) {
  const engine = new DetectionEngine([rule], memoryStores());
  const event = toolRequestEvent(
    { v: 1, method: 'preflight.check', host: 'claude-code', cwd: CWD, ...req },
    { id: `req-${n++}`, ts: T },
  );
  return decide(engine.check(event), () => rule.name).decision;
}

describe('tool-rule templates', () => {
  const samples: Record<
    string,
    { value?: string; bad: PreflightRequest[]; good: PreflightRequest[] }
  > = {};
  const req = (r: Partial<PreflightRequest> & { tool: string }): PreflightRequest => ({
    v: 1,
    method: 'preflight.check',
    host: 'claude-code',
    cwd: CWD,
    ...r,
  });
  samples['force-push'] = {
    bad: [
      req({ tool: 'Bash', command: 'git push --force origin main' }),
      req({ tool: 'Bash', command: 'git push -f' }),
      req({ tool: 'Bash', command: 'git push origin +main --force-with-lease' }),
    ],
    good: [
      req({ tool: 'Bash', command: 'git push origin main' }),
      req({ tool: 'Bash', command: 'git push origin feature-fix' }),
      req({ tool: 'Bash', command: 'git fetch --force' }),
    ],
  };
  samples['outside-project'] = {
    bad: [
      req({ tool: 'Write', filePath: '/Users/sam/.zshrc' }),
      req({ tool: 'Edit', filePath: '/Users/sam/code/shop-other/a.ts' }),
    ],
    good: [
      req({ tool: 'Write', filePath: `${CWD}/src/a.ts` }),
      req({ tool: 'Read', filePath: '/Users/sam/.zshrc' }),
    ],
  };
  samples['mcp-server'] = {
    value: 'github',
    bad: [req({ tool: 'mcp__github__create_issue' })],
    good: [
      req({ tool: 'mcp__gitlab__create_issue' }),
      req({ tool: 'Bash', command: 'gh pr list' }),
    ],
  };
  samples['domain'] = {
    value: 'example.com',
    bad: [
      req({ tool: 'WebFetch', url: 'https://example.com/docs' }),
      req({ tool: 'WebFetch', url: 'https://api.example.com/v1?q=1' }),
      req({ tool: 'WebFetch', url: 'https://example.com' }),
    ],
    good: [
      req({ tool: 'WebFetch', url: 'https://notexample.com/x' }),
      req({ tool: 'WebFetch', url: 'https://example.com.evil.test/x' }),
    ],
  };

  it('has samples for every template', () => {
    expect(Object.keys(samples).sort()).toEqual(TOOL_RULE_TEMPLATES.map((t) => t.id).sort());
  });

  for (const t of TOOL_RULE_TEMPLATES) {
    it(`${t.id}: saves as a pre-flight rule that lints clean`, () => {
      const rule = saved(t.json(new Set(), samples[t.id]?.value));
      expect(rule.eventKinds).toEqual(['agent.tool_request']);
      expect(rule.mode).toBe('alert');
      expect(rule.response).toEqual([]);
      expect(rule.tags).toContain('agent-preflight');
      expect(lintRule(rule)).toEqual({ errors: [], warnings: [] });
      expect(() => compileRule(rule)).not.toThrow();
    });

    it(`${t.id}: asks on its bad samples and stays quiet on look-alikes`, () => {
      const s = samples[t.id]!;
      const rule = saved(t.json(new Set(), s.value));
      for (const r of s.bad) expect(answer(rule, r), JSON.stringify(r)).toBe('ask');
      for (const r of s.good) expect(answer(rule, r), JSON.stringify(r)).toBe('none');
    });
  }

  it('never takes an id you already use', () => {
    const t = template('force-push');
    expect(saved(t.json(new Set())).id).toBe('ask-force-push');
    expect(saved(t.json(new Set(['ask-force-push']))).id).toBe('ask-force-push-2');
    expect(uniqueRuleId('x', new Set(['x', 'x-2']))).toBe('x-3');
    expect(saved(template('domain').json(new Set(), 'api.example.co.uk')).id).toBe(
      'ask-fetch-api-example-co-uk',
    );
  });

  it('cleans what was typed, and refuses what it cannot use', () => {
    const domain = template('domain').input!;
    expect(domain.clean('https://Docs.Example.com/path?q=1')).toBe('docs.example.com');
    expect(domain.clean('*.example.com')).toBe('example.com');
    expect(domain.clean('not a domain')).toBeUndefined();
    expect(domain.clean('localhost')).toBeUndefined();
    const mcp = template('mcp-server').input!;
    expect(mcp.clean('mcp__github__create_issue')).toBe('github');
    expect(mcp.clean(' linear ')).toBe('linear');
    expect(mcp.clean('two words')).toBeUndefined();
  });
});

describe('agent routes', () => {
  it('round-trip, and fit the routes main accepts', () => {
    const session = '0123456789abcdef';
    for (const r of [agentRoute('claude-code'), agentRoute('claude-code', session)]) {
      expect(Route.safeParse(r).success).toBe(true);
    }
    expect(parseAgentParam(agentRoute('claude-code', session).split('/')[1])).toEqual({
      id: 'claude-code',
      session,
    });
    expect(parseAgentParam('claude-code')).toEqual({ id: 'claude-code' });
    expect(parseAgentParam('claude-code_nothex')).toEqual({ id: 'claude-code' });
    expect(parseAgentParam('Bad_Id')).toEqual({});
    expect(parseAgentParam(undefined)).toEqual({});

    const a = activityRoute({ agent: 'codex' });
    const s = activityRoute({ session });
    expect(Route.safeParse(a).success && Route.safeParse(s).success).toBe(true);
    expect(parseActivityParam(a.split('/')[1])).toEqual({ agent: 'codex' });
    expect(parseActivityParam(s.split('/')[1])).toEqual({ session });
    expect(parseActivityParam('session-xyz')).toEqual({});
    expect(parseActivityParam(undefined)).toEqual({});
  });
});

describe('treeOrder', () => {
  const node = (pid: number, ppid: number, ts: number, depth: number): TreeNode => ({
    pid,
    ppid,
    name: `p${pid}`,
    path: `/bin/p${pid}`,
    ts,
    depth,
    matched: false,
  });

  it('puts each program under the one that started it, oldest first', () => {
    const root = node(100, 1, 0, 0);
    const order = treeOrder([
      root,
      node(101, 100, 1, 1), // zsh
      node(103, 100, 3, 1), // a second zsh
      node(102, 101, 2, 2), // git, under the first zsh
      node(104, 103, 4, 2), // curl, under the second
    ]).map((x) => x.pid);
    expect(order).toEqual([100, 101, 102, 103, 104]);
  });

  it('hangs a process whose parent it never saw under the agent', () => {
    const order = treeOrder([node(100, 1, 0, 0), node(200, 999, 1, 2), node(101, 100, 2, 1)]);
    expect(order.map((x) => x.pid)).toEqual([100, 200, 101]);
    expect(order[1]!.depth).toBe(2);
  });

  it('follows the newest process when a pid is reused', () => {
    const order = treeOrder([
      node(100, 1, 0, 0),
      node(101, 100, 1, 1),
      node(102, 101, 2, 2),
      node(101, 100, 3, 1), // pid 101 again, a new program
      node(103, 101, 4, 2), // its child
    ]);
    expect(order.map((x) => `${x.pid}@${x.ts}`)).toEqual([
      '100@0',
      '101@1',
      '102@2',
      '101@3',
      '103@4',
    ]);
  });

  it('keeps every node, and an empty tree stays empty', () => {
    const nodes = [
      node(1, 0, 0, 0),
      ...Array.from({ length: 50 }, (_, i) => node(i + 2, i + 1, i + 1, i + 1)),
    ];
    expect(treeOrder(nodes)).toHaveLength(51);
    expect(treeOrder([])).toEqual([]);
  });
});

describe('matcher rows', () => {
  it('round-trip every built-in agent into valid matchers', () => {
    for (const a of AGENT_CATALOG) {
      // As main sends them: JSON, so no keys left undefined.
      const match = JSON.parse(JSON.stringify(a.match)) as AgentMatcherView[];
      const { rows, kept } = rowsFromMatchers(match);
      const back = matchersFromRows(rows, kept);
      expect(back.errors, a.id).toEqual([]);
      expect(back.match, a.id).toEqual(match);
      for (const m of back.match) expect(AgentMatcher.safeParse(m).success, a.id).toBe(true);
    }
  });

  it('keeps a matcher that tests two identities at once as it is', () => {
    const odd = { teamIds: ['ABCDE12345'], paths: ['/opt/x/**'] };
    const { rows, kept } = rowsFromMatchers([odd, { names: ['goose'] }]);
    expect(kept).toEqual([odd]);
    expect(matchersFromRows(rows, kept).match).toEqual([odd, { names: ['goose'] }]);
  });

  it('turns typed rows into matchers main accepts', () => {
    const { match, errors } = matchersFromRows([
      { field: 'names', value: 'node', args: '*@sourcegraph/amp*' },
      { field: 'teamIds', value: 'abcde12345', args: '' },
      { field: 'paths', value: '~/.local/bin/goose, /opt/goose/bin/goose', args: '' },
      { field: 'names', value: '  ', args: '' },
    ]);
    expect(errors).toEqual([]);
    expect(match).toEqual([
      { names: ['node'], argGlobs: ['*@sourcegraph/amp*'] },
      { teamIds: ['ABCDE12345'] },
      { paths: ['~/.local/bin/goose', '/opt/goose/bin/goose'] },
    ]);
    for (const m of match) expect(AgentMatcher.safeParse(m).success).toBe(true);
  });

  it('says what is wrong instead of sending it', () => {
    const errors = (
      field: 'names' | 'paths' | 'teamIds' | 'signingIds',
      value: string,
      args = '',
    ) => matchersFromRows([{ field, value, args }]).errors;
    expect(errors('names', '/usr/local/bin/goose')[0]).toMatch(/is a path/);
    expect(errors('teamIds', 'SHORT')[0]).toMatch(/10 letters/);
    expect(errors('paths', '/x')[0]).toMatch(/3 to 256/);
    expect(errors('names', 'node', '*')[0]).toMatch(/3 to 256/);
    expect(errors('names', '', '*codex*')[0]).toMatch(/needs a program name/);
    expect(matchersFromRows([]).errors).toEqual(['Add at least one way to recognise the program.']);
    const five = Array.from({ length: 5 }, (_, i) => ({
      field: 'names' as const,
      value: `a${i}`,
      args: '',
    }));
    expect(matchersFromRows(five).errors).toEqual(['At most 4 ways per agent.']);
  });

  it('describes a matcher in words', () => {
    expect(describeMatcher({ names: ['node'], argGlobs: ['*@openai/codex*'] })).toBe(
      'named node, with a command line like *@openai/codex*',
    );
    expect(describeMatcher({ paths: ['/Applications/Cursor.app/**'] })).toBe(
      'at /Applications/Cursor.app/**',
    );
  });
});

describe('agentIdFor', () => {
  it('makes a valid id that is not taken and not Vigil’s own', () => {
    expect(agentIdFor('Goose', new Set())).toBe('goose');
    expect(agentIdFor('Goose', new Set(['goose', 'goose-2']))).toBe('goose-3');
    expect(agentIdFor('Vigil self', new Set())).toBe('vigil-self-2');
    expect(agentIdFor('  ✨ ', new Set())).toBe('agent');
    const long = agentIdFor('A really long agent name that keeps going and going', new Set());
    for (const id of ['goose', long, agentIdFor('Café Bot', new Set())]) {
      expect(AgentId.safeParse(id).success, id).toBe(true);
    }
  });
});

describe('originLabel', () => {
  it('names where an agent came from', () => {
    const at = (origin: 'builtin' | 'user' | 'suggested', status = 'active', presence = 'seen') =>
      originLabel({
        origin,
        status: status as 'active',
        presence: presence as 'seen',
      }).label;
    expect(at('builtin')).toBe('Detected');
    expect(at('builtin', 'active', 'not-found')).toBe('Built-in');
    expect(at('user')).toBe('Added by you');
    expect(at('suggested', 'suggested')).toBe('Suggested');
    expect(at('suggested', 'active')).toBe('Detected');
  });
});
