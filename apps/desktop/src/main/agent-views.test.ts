// The renderer's plain helpers for agent rules and tool-request evidence: the
// words each page uses for a rule's modes, how an alert shows a stopped step,
// and the replay preview of a tool rule. The renderer has no Node test setup
// of its own, so they are checked here, against the real rules and events.
import { describe, expect, it } from 'vitest';
import type { PreflightRequest, SensorEvent } from '@vigil/core';
import {
  builtinRules,
  DetectionRule,
  memoryStores,
  PREFLIGHT_PROBING_RULE_ID,
  PREFLIGHT_SOCKET_RULE_ID,
  PREFLIGHT_SOCKET_TOOL,
  replayRule,
  toolRequestEvent,
} from '@vigil/detection';
import type { ReplayPreview } from '../shared/ipc.js';
import { TOOL_RULE_TEMPLATES } from '../renderer/src/agent-templates.js';
import {
  evidenceSub,
  excludeScopes,
  isHookRequest,
  realProcess,
  STOPPED_ANSWER,
  toolRequestRows,
} from '../renderer/src/evidence.js';
import {
  confirmsFirst,
  draftIsToolRule,
  groupAgentRules,
  matchText,
  modeLabel,
  modesFor,
  RAISED_BY_VIGIL,
  replayLine,
  replaySampleRow,
} from '../renderer/src/rule-modes.js';

const T = Date.UTC(2026, 9, 1);
const CWD = '/Users/sam/code/shop';
let n = 0;

function request(r: Partial<PreflightRequest> & { tool: string }, tag?: { session: string }) {
  return toolRequestEvent(
    { v: 1, method: 'preflight.check', host: 'claude-code', cwd: CWD, ...r },
    {
      id: `req-${n++}`,
      ts: T + n,
      ...(tag ? { tag: { id: 'claude-code', session: tag.session, depth: 0 } } : {}),
    },
  );
}

const exec: SensorEvent = {
  id: 'exec-1',
  ts: T,
  source: 'test',
  kind: 'process.exec',
  process: { pid: 42, path: '/usr/bin/curl', teamId: 'ABCDE12345', signingId: 'com.x.curl' },
};

const preflight = builtinRules.filter((r) => r.tags?.includes('agent-preflight'));
const toolRule = { id: 'ask-force-push', eventKinds: ['agent.tool_request'] };
const watchRule = { id: 'agent-reads-ssh-keys', eventKinds: ['file'] };

describe('rule modes', () => {
  it('names the rules Vigil raises itself as the detection package does', () => {
    expect([...RAISED_BY_VIGIL].sort()).toEqual(
      [PREFLIGHT_PROBING_RULE_ID, PREFLIGHT_SOCKET_RULE_ID].sort(),
    );
    for (const id of RAISED_BY_VIGIL) expect(preflight.map((r) => r.id)).toContain(id);
  });

  it('offers each kind of rule its own modes, in its own words', () => {
    const labels = (r: { id: string; eventKinds: string[] }) => modesFor(r).map((m) => m.label);
    expect(labels(toolRule)).toEqual(['Off', 'Record', 'Ask', 'Deny']);
    expect(labels(watchRule)).toEqual(['Off', 'Shadow', 'Alert', 'Block']);
    // Probing raises an alert and never answers a step, so it has no Deny.
    const probing = { id: PREFLIGHT_PROBING_RULE_ID, eventKinds: ['agent.tool_request'] };
    expect(labels(probing)).toEqual(['Off', 'Record', 'Alert']);

    expect(modeLabel(toolRule, 'block')).toBe('Deny');
    expect(modeLabel(toolRule, 'alert')).toBe('Ask');
    expect(modeLabel(watchRule, 'block')).toBe('Block');
    expect(modeLabel(probing, 'alert')).toBe('Alert');
    // Set to block elsewhere it still only alerts, so it says so.
    expect(modeLabel(probing, 'block')).toBe('Alert');
  });

  it('asks for a hold only to turn on Block, and any other pick drops the question', () => {
    expect(confirmsFirst('alert', 'block')).toBe(true);
    expect(confirmsFirst('block', 'block')).toBe(false);
    // Picking Deny, then Ask: the Deny confirmation must go away.
    expect(confirmsFirst('alert', 'alert')).toBe(false);
    expect(confirmsFirst('alert', 'shadow')).toBe(false);
  });

  it('keeps Vigil’s own checks out of the steps an agent asks about', () => {
    const watch = builtinRules.filter((r) => r.tags?.includes('agent-watch'));
    const all = [...watch, ...preflight].map((r) => ({ id: r.id, name: r.name, mode: r.mode }));
    const kinds = new Map([...watch, ...preflight].map((r) => [r.id, r.eventKinds]));
    const groups = groupAgentRules(all, (id) => kinds.get(id));
    expect(groups.raised.map((r) => r.id).sort()).toEqual([...RAISED_BY_VIGIL].sort());
    expect(groups.tool.length).toBeGreaterThan(0);
    for (const r of groups.tool) expect(kinds.get(r.id)).toContain('agent.tool_request');
    for (const r of groups.watch) expect(kinds.get(r.id)).not.toContain('agent.tool_request');
    // Every built-in pre-flight rule in alert mode, but probing and the socket check, asks.
    const asks = groups.tool.filter((r) => r.mode === 'alert').length;
    expect(asks).toBe(
      preflight.filter((r) => r.mode === 'alert' && !RAISED_BY_VIGIL.has(r.id)).length,
    );
    // While the rule list loads, a rule Vigil doesn't know yet stays with what the agent starts.
    expect(groupAgentRules([{ id: 'x' }], () => undefined).watch).toEqual([{ id: 'x' }]);
  });

  it('describes a tool request’s matches in the words of its answer', () => {
    const outcome = {
      checked: 9,
      matches: [
        {
          ruleId: 'a',
          ruleName: 'Agent step would run a downloaded script',
          mode: 'alert' as const,
        },
        { ruleId: 'b', ruleName: 'Agent step would change agent settings', mode: 'block' as const },
      ],
    };
    expect(matchText(outcome, true, ', ')).toBe(
      'Agent step would run a downloaded script (Ask), Agent step would change agent settings (Deny)',
    );
    expect(matchText(outcome, false, '\n')).toBe(
      'Agent step would run a downloaded script (alert)\nAgent step would change agent settings (block)',
    );
  });
});

describe('tool-rule replay preview', () => {
  it('knows a tool rule from its JSON', () => {
    for (const t of TOOL_RULE_TEMPLATES)
      expect(draftIsToolRule(t.json(new Set(), 'x.com'))).toBe(true);
    expect(draftIsToolRule(JSON.stringify({ eventKinds: ['process.exec'] }))).toBe(false);
    expect(draftIsToolRule(JSON.stringify({ eventKinds: ['agent.tool_request', 'file'] }))).toBe(
      false,
    );
    expect(draftIsToolRule('{ not json')).toBe(false);
    expect(draftIsToolRule('null')).toBe(false);
  });

  it('counts steps and shows the command, not alerts, programs or the stand-in shell', () => {
    const json = TOOL_RULE_TEMPLATES.find((t) => t.id === 'force-push')!.json(new Set());
    const rule = DetectionRule.parse({
      ...(JSON.parse(json) as object),
      version: 1,
      origin: 'user',
      createdAt: T,
      updatedAt: T,
    });
    const stores = memoryStores();
    for (let i = 0; i < 6; i++)
      stores.history.append(request({ tool: 'Bash', command: `git push -f origin b${i}` }));
    stores.history.append(request({ tool: 'Bash', command: 'git push origin main' }));
    const { report } = replayRule(
      rule,
      { history: stores.history, lists: stores.lists, userExceptions: stores.exceptions },
      { from: T - 1, to: T + 1000 },
    );
    const preview = report as ReplayPreview;
    expect(preview.hits).toBe(6);

    const line = replayLine(preview, true);
    expect(line).toMatch(/^Would have matched 6 steps in the last 14 days/);
    expect(line).not.toMatch(/alert|program/);
    const rows = preview.samples.map((s) => replaySampleRow(s, true));
    expect(rows[0]).toEqual({ what: 'git push -f origin b0', note: 'Bash' });
    for (const r of rows) expect(r.what).not.toContain('/bin/zsh');

    // Other rules keep their wording.
    expect(replayLine(preview, false)).toMatch(/with \d+ alerts?, across \d+ programs?\./);
  });
});

describe('tool-request evidence', () => {
  it('never shows the stand-in shell as a program that ran', () => {
    const bash = request({ tool: 'Bash', command: 'git push -f' });
    expect(bash.process?.path).toBe('/bin/zsh');
    expect(realProcess(bash)).toBeUndefined();
    expect(realProcess(exec)?.path).toBe('/usr/bin/curl');
  });

  it('shows what a stopped step asked for, and which agent asked', () => {
    const bash = request({ tool: 'Bash', command: 'git push -f' }, { session: '0123456789abcdef' });
    expect(toolRequestRows(bash)).toEqual([
      { label: 'Tool', code: 'Bash' },
      { label: 'Command', code: 'git push -f' },
      { label: 'In folder', code: CWD },
      { label: 'Agent', agent: { id: 'claude-code', session: '0123456789abcdef' } },
    ]);

    const write = request({
      tool: 'Write',
      filePath: '/Users/sam/Library/Application Support/Vigil at Home/rules.json',
      contentBytes: 12,
    });
    const rows = toolRequestRows(write);
    expect(rows.map((r) => r.label)).toEqual(['Tool', 'File', 'In folder', 'Content', 'Agent']);
    expect(rows[1]).toEqual({
      label: 'File',
      code: '/Users/sam/Library/Application Support/Vigil at Home/rules.json',
    });
    expect(rows.at(-1)).toEqual({
      label: 'Agent',
      text: 'Claude Code (Vigil didn’t see which session started it)',
    });

    const fetch = toolRequestRows(request({ tool: 'WebFetch', url: 'https://example.com/x' }));
    expect(fetch).toContainEqual({ label: 'Address', code: 'https://example.com/x' });
    const mcp = toolRequestRows(request({ tool: 'mcp__github__create_issue' }));
    expect(mcp).toContainEqual({ label: 'MCP server', code: 'github' });

    const long = 'x'.repeat(4096);
    const clipped = toolRequestRows(request({ tool: 'Bash', command: long, commandBytes: 9000 }));
    expect(clipped).toContainEqual({
      label: 'Command size',
      text: '9000 bytes; Vigil checked the first 4,096 characters',
    });
  });

  it('tells the socket check apart from a hook request', () => {
    const socket: SensorEvent = {
      id: 's1',
      ts: T,
      source: 'vigil',
      kind: 'agent.tool_request',
      tool: PREFLIGHT_SOCKET_TOOL,
      filePath: '/Users/sam/Library/Application Support/Vigil at Home/run/agent.sock',
      agent: { host: 'claude-code' },
    };
    expect(isHookRequest(socket)).toBe(false);
    expect(toolRequestRows(socket)).toEqual([
      {
        label: 'Socket',
        code: '/Users/sam/Library/Application Support/Vigil at Home/run/agent.sock',
      },
    ]);
    expect(evidenceSub([socket])).toBe('1 event from the sensors');
  });

  it('says where the evidence came from', () => {
    const a = request({ tool: 'Bash', command: 'git push -f' });
    const b = request({ tool: 'Write', filePath: '/tmp/x' });
    expect(isHookRequest(a)).toBe(true);
    expect(evidenceSub([a])).toBe('1 request from Claude Code’s hook');
    expect(evidenceSub([a, b])).toBe('2 requests from Claude Code’s hook');
    expect(evidenceSub([a, exec])).toBe('2 events from the sensors');
    expect(evidenceSub([exec])).toBe('1 event from the sensors');
    expect(STOPPED_ANSWER).toBe('Stopped before it ran');
  });

  it('offers no exclusion from an alert on a tool request', () => {
    // "This program" would be /bin/zsh, and would silence the rule for every Bash step.
    expect(excludeScopes(request({ tool: 'Bash', command: 'git push -f' }))).toEqual([]);
    expect(excludeScopes(request({ tool: 'Write', filePath: '/tmp/x' }))).toEqual([]);
    expect(excludeScopes(exec).map((s) => s.scope)).toEqual(['this_binary', 'this_signer']);
  });
});
