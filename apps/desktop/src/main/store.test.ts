import { copyFileSync, mkdtempSync, readdirSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { DatabaseSync } from 'node:sqlite';
import type { AgentToolRequestEvent, EventOfKind, SensorEvent } from '@vigil/core';
import { TEXT_SEARCH_WINDOW_MS, type EventOutcome } from '../shared/ipc.js';
import { describe, expect, it } from 'vitest';
import { z } from 'zod';
import { migrations } from './db/schema.js';
import { Store, eventViewsQuery } from './db/store.js';
import { makeExec, makeRule, memoryStore } from './testing.js';

describe('Store', () => {
  it('nests transactions as savepoints and rolls back only the inner one', () => {
    const store = memoryStore();
    const a = makeExec();
    const b = makeExec();
    store.tx(() => {
      store.insertEvent(a);
      expect(() =>
        store.tx(() => {
          store.insertEvent(b);
          throw new Error('inner');
        }),
      ).toThrow('inner');
      store.insertEvents([{ event: b }]);
    });
    expect(store.getEvents([a.id, b.id]).map((e) => e.id)).toEqual([a.id, b.id]);
  });

  it('recovers from a transaction left open outside tx', () => {
    const db = new DatabaseSync(':memory:');
    const store = new Store(db);
    const a = makeExec();
    db.exec('BEGIN');
    store.insertEvent(a);
    const b = makeExec();
    expect(() => store.insertEvents([{ event: b }])).not.toThrow();
    expect(db.isTransaction).toBe(false);
    expect(store.getEvents([a.id, b.id])).toHaveLength(2);
  });

  it('round-trips events, rules and settings', () => {
    const s = memoryStore();
    const e = makeExec();
    s.insertEvent(e);
    s.insertEvent(e); // idempotent
    expect(s.getEvent(e.id)).toEqual(e);
    expect(s.recentEvents({ kind: 'process.exec' })).toHaveLength(1);

    s.upsertRule(makeRule());
    s.upsertRule(makeRule({ version: 2, mode: 'shadow' }));
    expect(s.getRule('test.rule')?.version).toBe(2);
    expect(s.listRules('shadow')).toHaveLength(1);

    expect(s.getSetting('theme', z.enum(['dark', 'light']), 'dark')).toBe('dark');
    s.setSetting('theme', 'light');
    expect(s.getSetting('theme', z.enum(['dark', 'light']), 'dark')).toBe('light');
    s.setSetting('theme', 42);
    expect(s.getSetting('theme', z.enum(['dark', 'light']), 'dark')).toBe('dark');
  });

  it('is idempotent across reopen (migrations run once)', () => {
    const s = memoryStore();
    s.upsertRule(makeRule());
    expect(s.listRules()).toHaveLength(1);
  });

  it('prunes old events except ones an alert references', () => {
    const s = memoryStore();
    const keep = makeExec();
    const drop = makeExec();
    s.insertEvent(keep);
    s.insertEvent(drop);
    s.saveAlert({
      id: 'a1',
      createdAt: 1,
      updatedAt: 1,
      ruleId: 'r',
      ruleVersion: 1,
      title: 't',
      summary: 's',
      severity: 'low',
      fidelity: 'low',
      notify: 'silent',
      status: 'open',
      containment: 'none',
      eventIds: [keep.id],
      actionIds: [],
    });
    expect(s.pruneEvents(Number.MAX_SAFE_INTEGER)).toBe(1);
    expect(s.getEvent(keep.id)).toBeDefined();
    expect(s.getEvent(drop.id)).toBeUndefined();
  });

  it('answers event counts and last-event times as the database would, through writes, rollbacks and prunes', () => {
    const db = new DatabaseSync(':memory:');
    const s = new Store(db);
    const direct = (since: number, source: string) => ({
      count: (
        db.prepare('SELECT COUNT(*) AS n FROM events WHERE ts >= ?').get(since) as { n: number }
      ).n,
      last: (
        db.prepare('SELECT MAX(ts) AS ts FROM events WHERE source = ?').get(source) as {
          ts: number | null;
        }
      ).ts,
    });
    const check = () => {
      for (const source of ['santa', 'osquery', 'test'])
        for (const since of [0, 1_050, 5_000]) {
          const want = direct(since, source);
          // Twice: the second answer may come from memory.
          for (let i = 0; i < 2; i++) {
            expect(s.countEventsSince(since)).toBe(want.count);
            expect(s.lastEventAt(source)).toBe(want.last);
          }
        }
    };
    let seed = 7;
    const rand = (n: number) => (seed = (seed * 1103515245 + 12345) & 0x7fffffff) % n;
    const event = (): SensorEvent => ({
      ...makeExec(),
      ts: 1_000 + rand(8_000),
      source: (['santa', 'osquery', 'test'] as const)[rand(3)]!,
    });
    check();
    for (let step = 0; step < 300; step++) {
      switch (rand(6)) {
        case 0:
          s.insertEvent(event());
          break;
        case 1:
          s.insertEvents([{ event: event() }, { event: event() }]);
          break;
        case 2:
          expect(() =>
            s.tx(() => {
              s.insertEvent(event());
              check();
              throw new Error('roll back');
            }),
          ).toThrow('roll back');
          break;
        case 3:
          s.pruneEvents(1_000 + rand(8_000));
          break;
        default:
          break;
      }
      check();
    }
  });

  it('counts rule matches since a time', () => {
    const s = memoryStore();
    for (const ts of [10, 20, 30]) {
      s.insertRuleMatch({
        id: `m${ts}`,
        ruleId: 'r',
        ruleVersion: 1,
        mode: 'shadow',
        ts,
        eventIds: ['e'],
      });
    }
    expect(s.ruleMatchCounts(15).get('r')).toBe(2);
  });

  it('counts every alert by status, past the newest page listAlerts returns', () => {
    const s = memoryStore();
    for (let i = 0; i < 205; i++) {
      s.saveAlert({
        id: `a-${i}`,
        createdAt: i,
        updatedAt: i,
        ruleId: 'test.rule',
        ruleVersion: 1,
        title: 't',
        summary: 's',
        severity: 'high',
        fidelity: 'high',
        notify: 'popup',
        status: i < 3 ? 'resolved' : 'open',
        containment: 'none',
        eventIds: ['e'],
        actionIds: [],
      });
    }
    expect(s.listAlerts({ status: 'open' })).toHaveLength(200);
    expect(s.countAlerts('open')).toBe(202);
    expect(s.countAlerts('resolved')).toBe(3);
  });

  it('keeps the database under a size cap by dropping the oldest events', () => {
    const s = memoryStore();
    const kept = makeExec();
    s.insertEvent(kept);
    s.saveAlert({
      id: 'a-cap',
      createdAt: 1,
      updatedAt: 1,
      ruleId: 'test.rule',
      ruleVersion: 1,
      title: 't',
      summary: 's',
      severity: 'high',
      fidelity: 'high',
      notify: 'popup',
      status: 'open',
      containment: 'none',
      eventIds: [kept.id],
      actionIds: [],
    });
    const many = Array.from({ length: 3000 }, (_, i) => ({
      ...makeExec(`/usr/bin/tool${i}`),
      process: { pid: i, path: `/usr/bin/tool${i}`, args: ['x'.repeat(200)] },
    }));
    expect(s.insertEvents(many.map((event) => ({ event })))).toBe(0);
    const full = s.usedBytes();
    const removed = s.pruneEventsToSize(full / 2);
    expect(removed).toBeGreaterThan(0);
    expect(s.usedBytes()).toBeLessThanOrEqual(full / 2);
    expect(s.getEvent(kept.id)).toBeDefined();
    // The newest events stay.
    expect(s.getEvent(many.at(-1)!.id)).toBeDefined();
  });

  it('lists the event feed with filters, paging and outcomes', () => {
    const s = memoryStore();
    const a = { ...makeExec('/Applications/Safari.app/Contents/MacOS/Safari'), ts: 1000 };
    const b = { ...makeExec('/tmp/100%_evil'), ts: 2000 };
    s.insertEvent(a, { checked: 3, matches: [] });
    s.insertEvent(b, {
      checked: 3,
      matches: [{ ruleId: 'r1', ruleName: 'Rule one', mode: 'alert' }],
    });
    s.insertEvent({
      id: 'net1',
      ts: 3000,
      source: 'osquery',
      kind: 'network.connection',
      direction: 'outbound',
      protocol: 'tcp',
      remoteAddress: '1.2.3.4',
    });

    expect(s.listEventViews().map((v) => v.event.ts)).toEqual([3000, 2000, 1000]);
    expect(s.listEventViews({ group: 'network' })).toHaveLength(1);
    expect(s.listEventViews({ matchedOnly: true }).map((v) => v.event.id)).toEqual([b.id]);
    // One rule's matches, for an alert's "its matches in Activity".
    expect(s.listEventViews({ rule: 'r1' }).map((v) => v.event.id)).toEqual([b.id]);
    expect(s.listEventViews({ rule: 'r2' })).toHaveLength(0);
    const { sql } = eventViewsQuery({ rule: 'r1' }, 10_000);
    const db = (s as unknown as { db: DatabaseSync }).db;
    const steps = (db.prepare(`EXPLAIN QUERY PLAN ${sql}`).all('r1', 200) as { detail: string }[])
      .map((r) => r.detail)
      .join('\n');
    expect(steps).toContain('events_matched_ts');
    expect(s.listEventViews({ text: 'safari' }, 5000).map((v) => v.event.id)).toEqual([a.id]);
    // % and _ are literal, not wildcards.
    expect(s.listEventViews({ text: '100%_' }, 5000).map((v) => v.event.id)).toEqual([b.id]);
    expect(s.listEventViews({ text: '%' }, 5000).map((v) => v.event.id)).toEqual([b.id]);
    expect(s.listEventViews({ before: 2000, limit: 5 }).map((v) => v.event.id)).toEqual([a.id]);
    expect(s.listEventViews({ group: 'network' })[0]?.outcome).toBeNull();
    // A search looks back one day from where the page starts.
    const dayLater = 1000 + TEXT_SEARCH_WINDOW_MS + 1;
    expect(s.listEventViews({ text: 'safari' }, dayLater)).toEqual([]);
    expect(s.listEventViews({ text: 'safari', before: 1500 }, dayLater)).toHaveLength(1);

    const stats = s.eventStats(1500);
    expect(stats).toMatchObject({
      lastHour: 2,
      matchedLastHour: 1,
      programsLastHour: 1,
      newest: 3000,
    });
    expect(stats.byGroup).toMatchObject({ programs: 1, network: 1, files: 0 });
  });

  it('pages the feed by (ts, id), so events sharing a ts are not skipped', () => {
    const s = memoryStore();
    const ids = ['e1', 'e2', 'e3', 'e4', 'e5'];
    s.insertEvents(ids.map((id, i) => ({ event: { ...makeExec(), id, ts: i < 4 ? 2000 : 1000 } })));
    const all: string[] = [];
    let last: { ts: number; id: string } | undefined;
    for (;;) {
      const page = s.listEventViews({
        limit: 2,
        ...(last ? { before: last.ts, beforeId: last.id } : {}),
      });
      if (page.length === 0) break;
      all.push(...page.map((v) => v.event.id));
      const e = page.at(-1)!.event;
      last = { ts: e.ts, id: e.id };
    }
    expect(all).toEqual(['e4', 'e3', 'e2', 'e1', 'e5']);
  });

  it('searches events since a time by kind and text, within a scan budget', () => {
    const s = memoryStore();
    const exec = (path: string, ts: number) => ({ ...makeExec(path), ts });
    const old = exec('/opt/tools/goose', 100);
    const goose = exec('/opt/tools/goose', 1000);
    const git = exec('/usr/bin/git', 2000);
    s.insertEvents([{ event: old }, { event: goose }, { event: git }]);
    s.insertEvent({
      id: 'f1',
      ts: 3000,
      source: 'santa',
      kind: 'file',
      op: 'open',
      path: '/Users/a/.aws/credentials',
    });
    const ids = (q: Partial<Parameters<typeof s.searchEvents>[0]>) =>
      s.searchEvents({ since: 500, limit: 10, scanRows: 100, ...q }).views.map((v) => v.event.id);

    expect(ids({})).toEqual(['f1', git.id, goose.id]);
    expect(ids({ kinds: ['process.exec'] })).toEqual([git.id, goose.id]);
    expect(ids({ text: 'goose' })).toEqual([goose.id]);
    expect(ids({ text: 'goose', since: 0 })).toEqual([goose.id, old.id]);
    expect(ids({ text: '.aws', kinds: ['file'] })).toEqual(['f1']);
    expect(ids({ limit: 1 })).toEqual(['f1']);
    // Text is looked for in the newest events only, and the answer says so.
    const partial = s.searchEvents({ since: 0, text: 'goose', limit: 10, scanRows: 2 });
    expect(partial).toEqual({ views: [], partial: true });
    expect(s.searchEvents({ since: 0, text: 'git', limit: 10, scanRows: 4 }).partial).toBe(false);
  });

  it('searches events by agent, rule matches and label', () => {
    const s = memoryStore();
    const agent = { id: 'claude-code', session: 'aaaaaaaaaaaaaaaa', depth: 1 };
    const exec = (path: string, ts: number, tagged = false) => {
      const e = { ...makeExec(path), ts };
      return tagged ? { ...e, process: { ...e.process, agent } } : e;
    };
    const npm = exec('/usr/local/bin/npm', 1000, true);
    const curl = exec('/usr/bin/curl', 2000);
    const ssh = exec('/usr/bin/ssh', 3000, true);
    const matches = [{ ruleId: 'r', ruleName: 'R', mode: 'alert' as const }];
    s.insertEvents([
      { event: npm },
      { event: curl, outcome: { checked: 1, matches } },
      { event: ssh, outcome: { checked: 1, matches: [] } },
    ]);
    const label = (l: 'unusual' | 'suspicious') => ({
      label: l,
      score: 0.5,
      reason: 'x',
      by: 'model' as const,
      at: 1,
    });
    s.setEventLabels([
      { eventId: npm.id, label: label('unusual') },
      { eventId: ssh.id, label: label('suspicious') },
    ]);
    const ids = (q: Partial<Parameters<typeof s.searchEvents>[0]>) =>
      s.searchEvents({ since: 0, limit: 10, scanRows: 100, ...q }).views.map((v) => v.event.id);

    expect(ids({ agent: 'claude-code' })).toEqual([ssh.id, npm.id]);
    expect(ids({ matchedOnly: true })).toEqual([curl.id]);
    expect(ids({ label: 'suspicious' })).toEqual([ssh.id]);
    expect(ids({ label: 'unusual', agent: 'claude-code', text: 'npm' })).toEqual([npm.id]);
    // Labels are looked for in the newest events only, like text.
    expect(s.searchEvents({ since: 0, label: 'unusual', limit: 10, scanRows: 1 })).toEqual({
      views: [],
      partial: true,
    });
  });

  it('fills in the outcome of an event an alert already stored, keeping its raw record', () => {
    const s = memoryStore();
    const e = { ...makeExec(), raw: { line: 'santa' } };
    s.insertEvent(e);
    s.insertEvents([{ event: { ...e, raw: undefined }, outcome: { checked: 2, matches: [] } }]);
    expect(s.getEvent(e.id)).toMatchObject({ raw: { line: 'santa' } });
    expect(s.listEventViews()[0]?.outcome).toEqual({ checked: 2, matches: [] });
  });

  it('marks batched events that matched a rule, including ones an alert stored first', () => {
    const s = memoryStore();
    const hit = makeExec();
    const plain = makeExec();
    const matches = [{ ruleId: 'r', ruleName: 'R', mode: 'alert' as const }];
    s.insertEvent(hit);
    s.insertEvents([
      { event: hit, outcome: { checked: 1, matches } },
      { event: plain, outcome: { checked: 1, matches: [] } },
    ]);
    expect(s.listEventViews({ matchedOnly: true }).map((v) => v.event.id)).toEqual([hit.id]);
  });
});

// ---------------------------------------------------------------- agents

const S1 = 'aaaaaaaaaaaaaaaa';
const S2 = 'bbbbbbbbbbbbbbbb';
const tag = (session: string, depth = 1, id = 'claude-code') => ({ id, session, depth });

function tagged(
  session: string,
  ts: number,
  pid: number,
  path = '/usr/bin/git',
  agent = 'claude-code',
): EventOfKind<'process.exec'> {
  return {
    ...makeExec(path, pid),
    ts,
    process: { pid, ppid: 100, path, signing: 'apple', agent: tag(session, 1, agent) },
  };
}

function toolRequest(
  id: string,
  ts: number,
  session: string | undefined,
  mode?: 'block' | 'alert' | 'shadow',
): { event: AgentToolRequestEvent; outcome: EventOutcome } {
  return {
    event: {
      id,
      ts,
      source: 'vigil',
      kind: 'agent.tool_request',
      tool: 'Bash',
      command: 'ls',
      agent: { host: 'claude-code', ...(session ? { id: 'claude-code', session } : {}) },
      process: { pid: 0, path: '/bin/zsh', args: ['zsh', '-c', 'ls'] },
    },
    outcome: { checked: 9, matches: mode ? [{ ruleId: 'r', ruleName: 'R', mode }] : [] },
  };
}

const quiet: EventOutcome = { checked: 1, matches: [] };
const hit: EventOutcome = { checked: 1, matches: [{ ruleId: 'r', ruleName: 'R', mode: 'alert' }] };

function sessionRow(id: string, startedAt: number, agentId = 'claude-code') {
  return {
    id,
    agentId,
    rootPid: 100,
    rootPath: '/Users/you/.local/share/claude/versions/2.0.14',
    startedAt,
    seeded: false,
  };
}

describe('Store: agents', () => {
  it('migrates a copy of a version 6 database, keeping its events', () => {
    const dir = mkdtempSync(join(tmpdir(), 'vigil-v6-'));
    const v6 = new DatabaseSync(join(dir, 'v6.db'));
    for (const m of migrations.slice(0, 6)) v6.exec(m);
    v6.exec('PRAGMA user_version = 6');
    const old = makeExec('/usr/bin/old');
    v6.prepare('INSERT INTO events (id, ts, kind, source, body) VALUES (?, ?, ?, ?, ?)').run(
      old.id,
      old.ts,
      old.kind,
      old.source,
      JSON.stringify(old),
    );
    v6.close();
    copyFileSync(join(dir, 'v6.db'), join(dir, 'copy.db'));

    const db = new DatabaseSync(join(dir, 'copy.db'));
    const s = new Store(db);
    expect(migrations).toHaveLength(7);
    expect(db.prepare('PRAGMA user_version').get()).toEqual({ user_version: 7 });
    const columns = (db.prepare('PRAGMA table_info(events)').all() as { name: string }[]).map(
      (c) => c.name,
    );
    expect(columns).toEqual(expect.arrayContaining(['agent_session', 'agent_id']));
    const indexes = (
      db.prepare(`SELECT name FROM sqlite_master WHERE type = 'index'`).all() as { name: string }[]
    ).map((r) => r.name);
    expect(indexes).toEqual(
      expect.arrayContaining([
        'agent_sessions_agent_started',
        'events_agent_session_ts',
        'events_agent_ts',
      ]),
    );
    expect(s.getEvent(old.id)).toEqual(old);
    expect(s.listEventViews({ agentSession: S1 })).toEqual([]);

    // New events fill the column; reopening runs nothing again.
    s.insertEvent(tagged(S1, 5000, 7));
    s.close();
    const again = new Store(new DatabaseSync(join(dir, 'copy.db')));
    expect(again.listEventViews({ agentSession: S1 })).toHaveLength(1);
    again.close();
  });

  it('stores sessions once and lists them with their counts, newest first', () => {
    const s = memoryStore();
    s.insertAgentSessions([sessionRow(S1, 1000), { ...sessionRow(S2, 2000), parentSession: S1 }]);
    s.insertAgentSessions([{ ...sessionRow(S1, 1000), rootPath: '/other' }]); // reported again
    s.insertEvents([
      { event: tagged(S1, 1100, 7), outcome: quiet },
      { event: tagged(S1, 1200, 8, '/bin/cat'), outcome: hit },
      toolRequest('t1', 1300, S1, 'block'),
      toolRequest('t2', 1400, S1, 'alert'),
      toolRequest('t3', 1500, S1),
      toolRequest('t4', 1600, S1, 'shadow'),
    ]);
    const [b, a] = s.listAgentSessions('claude-code');
    expect(b).toMatchObject({ id: S2, events: 0, lastAt: 2000, parentSession: S1 });
    expect(a).toMatchObject({
      id: S1,
      agentId: 'claude-code',
      rootPid: 100,
      rootPath: '/Users/you/.local/share/claude/versions/2.0.14',
      startedAt: 1000,
      lastAt: 1600,
      events: 6,
      matches: 4,
      asks: 1,
      denies: 1,
      seeded: false,
    });
    expect(s.listAgentSessions('claude-code', 2000).map((x) => x.id)).toEqual([S1]);
    expect(s.listAgentSessions('codex')).toEqual([]);
    expect(s.getAgentSession(S1)).toEqual(a);
    expect(s.getAgentSession('cccccccccccccccc')).toBeUndefined();

    expect(s.sessionEvents(S1).map((v) => v.event.ts)).toEqual([
      1600, 1500, 1400, 1300, 1200, 1100,
    ]);
    const execs = s.sessionEvents(S1, 10, { kind: 'process.exec', oldestFirst: true });
    expect(execs.map((v) => v.event.ts)).toEqual([1100, 1200]);
    expect([...s.sessionMatchedPids(S1)].sort()).toEqual([0, 8]);
  });

  it('filters the feed by agent and by session', () => {
    const s = memoryStore();
    s.insertAgentSessions([sessionRow(S1, 1000), sessionRow(S2, 1000, 'codex')]);
    s.insertEvent(tagged(S1, 1100, 7));
    s.insertEvent(tagged(S2, 1200, 8, '/usr/bin/git', 'codex'));
    s.insertEvent(makeExec('/usr/bin/plain'));
    const req = toolRequest('t1', 1300, S1, 'block');
    s.insertEvent(req.event, req.outcome);
    expect(s.listEventViews({ agent: 'claude-code' }).map((v) => v.event.id)).toEqual([
      't1',
      expect.any(String),
    ]);
    expect(s.listEventViews({ agent: 'codex' })).toHaveLength(1);
    expect(s.listEventViews({ agentSession: S2 })).toHaveLength(1);
    expect(s.listEventViews({ group: 'agents' }).map((v) => v.event.id)).toEqual(['t1']);
    expect(s.eventStats(0).byGroup).toMatchObject({ agents: 1, programs: 3 });
  });

  it('pages the feed by agent through an index, without sorting all its events', () => {
    const s = memoryStore();
    const db = (s as unknown as { db: DatabaseSync }).db;
    const plan = (q: Parameters<typeof eventViewsQuery>[0]) => {
      const { sql, args } = eventViewsQuery(q, 10_000);
      return (db.prepare(`EXPLAIN QUERY PLAN ${sql}`).all(...args) as { detail: string }[]).map(
        (r) => r.detail,
      );
    };
    for (const q of [
      { agent: 'claude-code' },
      { agent: 'claude-code', group: 'programs' as const },
      { agent: 'claude-code', before: 5000 },
      { agent: 'claude-code', before: 5000, beforeId: 'x' },
    ]) {
      const steps = plan(q);
      expect(steps.join('\n'), JSON.stringify(q)).toContain('events_agent_ts');
      // Ordering rows of equal ts by id is fine; sorting every row is not.
      expect(steps, JSON.stringify(q)).not.toContain('USE TEMP B-TREE FOR ORDER BY');
    }
    // The whole feed pages through the ts index too, sorting only ties by id.
    for (const q of [{ before: 5000 }, { before: 5000, beforeId: 'x' }]) {
      const steps = plan(q).join('\n');
      expect(steps, JSON.stringify(q)).toMatch(/USING INDEX \w*ts\w*/);
      expect(steps, JSON.stringify(q)).not.toContain('USE TEMP B-TREE FOR ORDER BY');
    }
    // The agent comes from the event's own tag, and a tool request's agent.
    s.insertEvents([
      { event: tagged(S1, 1100, 7), outcome: quiet },
      toolRequest('t1', 1200, S1, 'block'),
      toolRequest('t2', 1300, undefined, 'alert'),
    ]);
    expect(s.listEventViews({ agent: 'claude-code' }).map((v) => v.event.ts)).toEqual([1200, 1100]);
  });

  it('keeps session counts between reads and counts again only what changed', () => {
    const s = memoryStore();
    s.insertAgentSessions([sessionRow(S1, 1000), sessionRow(S2, 2000)]);
    s.insertEvents([
      { event: tagged(S1, 1100, 7), outcome: hit },
      { event: tagged(S2, 2100, 8), outcome: quiet },
    ]);
    expect(s.hasAgentSessions('claude-code')).toBe(true);
    expect(s.hasAgentSessions('codex')).toBe(false);
    const counts = () =>
      s.listAgentSessions('claude-code').map((v) => [v.id, v.events, v.matches, v.lastAt]);
    expect(counts()).toEqual([
      [S2, 1, 0, 2100],
      [S1, 1, 1, 1100],
    ]);
    // A new event in S1, its outcome filled in later, then a request in S2.
    const late = tagged(S1, 1200, 9);
    s.insertEvent(late);
    expect(counts()).toEqual([
      [S2, 1, 0, 2100],
      [S1, 2, 1, 1200],
    ]);
    s.insertEvents([{ event: late, outcome: hit }, toolRequest('t1', 2200, S2, 'block')]);
    expect(counts()).toEqual([
      [S2, 2, 1, 2200],
      [S1, 2, 2, 1200],
    ]);
    expect(s.getAgentSession(S2)).toMatchObject({ denies: 1, events: 2 });
    // Pruning forgets them all.
    s.pruneEvents(1150);
    expect(counts()).toEqual([
      [S2, 2, 1, 2200],
      [S1, 1, 1, 1200],
    ]);
  });

  it('keeps the session an alert stored first when the batch writes the event again', () => {
    const s = memoryStore();
    const e = tagged(S1, 1100, 7);
    s.insertEvent(e);
    s.insertEvents([{ event: e, outcome: hit }]);
    expect(s.listEventViews({ agentSession: S1 })[0]?.outcome).toEqual(hit);
  });

  it('counts each agent’s day: sessions, matches, asks and denies', () => {
    const s = memoryStore();
    s.insertAgentSessions([sessionRow(S1, 500), sessionRow(S2, 5000)]);
    s.insertEvents([
      { event: tagged(S1, 600, 7), outcome: hit }, // before the day starts
      { event: tagged(S1, 2100, 7), outcome: hit },
      { event: tagged(S2, 5100, 9), outcome: quiet },
      toolRequest('t1', 5200, S2, 'block'),
      toolRequest('t2', 5300, S2, 'alert'),
      toolRequest('t3', 5400, undefined, 'alert'), // no agent known
    ]);
    const stats = s.agentStats(2000);
    expect(stats.get('claude-code')).toEqual({
      sessions: 2,
      matches: 3,
      asks: 1,
      denies: 1,
      lastSeenAt: 5300,
    });
    expect(s.agentStats(6000).get('claude-code')).toMatchObject({ sessions: 0, matches: 0 });
    expect(s.toolRequestCounts(0)).toEqual({ deny: 1, ask: 2, none: 0 });
    expect(s.toolRequestCounts(5250)).toEqual({ deny: 0, ask: 2, none: 0 });
  });

  it('prunes sessions whose events are gone, and keeps the rest', () => {
    const s = memoryStore();
    s.insertAgentSessions([sessionRow(S1, 1000), sessionRow(S2, 1000)]);
    s.insertEvent(tagged(S2, 1100, 7));
    expect(s.pruneAgentSessions(5000)).toBe(1);
    expect(s.getAgentSession(S1)).toBeUndefined();
    expect(s.getAgentSession(S2)).toBeDefined();
    s.pruneEvents(5000);
    expect(s.pruneAgentSessions(500)).toBe(0); // too new
    expect(s.pruneAgentSessions(5000)).toBe(1);
  });

  it('lists recent programs that are not Apple’s, newest first', () => {
    const s = memoryStore();
    const run = (path: string, ts: number, signing: 'apple' | 'developer_id', teamId?: string) =>
      s.insertEvent({
        ...makeExec(path),
        ts,
        process: { pid: ts, path, signing, ...(teamId ? { teamId } : {}) },
      } satisfies SensorEvent);
    run('/usr/bin/git', 100, 'apple');
    run('/opt/homebrew/bin/aider', 200, 'developer_id', 'ABCDE12345');
    run('/opt/homebrew/bin/aider', 300, 'developer_id', 'ABCDE12345');
    run('/Users/you/.local/bin/goose', 400, 'developer_id');
    run('/opt/old/tool', 10, 'developer_id');
    expect(s.recentExecPrograms(50)).toEqual([
      { path: '/Users/you/.local/bin/goose', name: 'goose', lastSeen: 400, count: 1 },
      {
        path: '/opt/homebrew/bin/aider',
        name: 'aider',
        teamId: 'ABCDE12345',
        lastSeen: 300,
        count: 2,
      },
    ]);
    const rows = [...s.iterateExecEvents(50)];
    expect(rows.map((r) => r.path)).toEqual([
      '/Users/you/.local/bin/goose',
      '/opt/homebrew/bin/aider',
      '/opt/homebrew/bin/aider',
      '/usr/bin/git',
    ]);
    expect([...s.iterateExecEvents(0, 2)]).toHaveLength(2);
  });

  it('counts Vigil’s own AI runs by purpose', () => {
    const s = memoryStore();
    const run = (id: string, at: number, purpose: 'explain' | 'classify') =>
      s.addAiRun({
        id,
        at,
        provider: 'claude',
        purpose,
        ok: true,
        inputTokens: 1,
        cachedInputTokens: 0,
        outputTokens: 1,
        costUsd: null,
      });
    run('a', 100, 'explain');
    run('b', 900, 'explain');
    run('c', 50, 'classify');
    const stats = s.aiRunStats(500);
    expect(stats.get('explain')).toEqual({ runs: 1, lastAt: 900 });
    expect(stats.get('classify')).toEqual({ runs: 0, lastAt: 50 });
    expect(stats.has('analyze')).toBe(false);
  });
});

describe('Store: who writes events', () => {
  it('is the only code that changes the events table, so its memos stay right', () => {
    const root = fileURLToPath(new URL('../../../../', import.meta.url));
    const writes =
      /\b(?:INSERT\s+(?:OR\s+\w+\s+)?INTO|UPDATE|DELETE\s+FROM|REPLACE\s+INTO)\s+events\b/i;
    const found: string[] = [];
    const walk = (dir: string): void => {
      for (const d of readdirSync(dir, { withFileTypes: true })) {
        const path = join(dir, d.name);
        if (d.isDirectory()) walk(path);
        else if (/\.(?:ts|tsx|mjs|js)$/.test(d.name) && !/\.test\.tsx?$/.test(d.name)) {
          if (writes.test(readFileSync(path, 'utf8'))) found.push(relative(root, path));
        }
      }
    };
    // App and package code; measurement scripts (perf/) build their own tables.
    for (const top of ['apps', 'packages'])
      for (const d of readdirSync(join(root, top))) walk(join(root, top, d, 'src'));
    // Migrations run before a Store exists.
    expect(found.sort()).toEqual([
      'apps/desktop/src/main/db/schema.ts',
      'apps/desktop/src/main/db/store.ts',
    ]);
  });
});
