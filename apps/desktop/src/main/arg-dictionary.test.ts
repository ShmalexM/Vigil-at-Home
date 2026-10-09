import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import type { EventOfKind } from '@vigil/core';
import { describe, expect, it } from 'vitest';
import { ArgDictionary, MISSING_ARG, argIds, encodable } from './db/arg-dictionary.js';
import { migrations } from './db/schema.js';
import { Store } from './db/store.js';
import { makeExec } from './testing.js';

const HOUR = 3_600_000;
const none = { checked: 3, matches: [] };
const hit = { checked: 3, matches: [{ ruleId: 'r', ruleName: 'R', mode: 'alert' as const }] };

function open(): { db: DatabaseSync; s: Store } {
  const db = new DatabaseSync(':memory:');
  return { db, s: new Store(db) };
}

function launch(args: string[], ts = 10 * HOUR): EventOfKind<'process.exec'> {
  const e = makeExec('/bin/sh');
  return { ...e, ts, process: { ...e.process, args } };
}

function stored(db: DatabaseSync, id: string): { body: string; args: Uint8Array | null } {
  return db.prepare('SELECT body, args FROM events WHERE id = ?').get(id) as {
    body: string;
    args: Uint8Array | null;
  };
}

describe('ArgDictionary', () => {
  it('gives back exactly the arguments it was given', () => {
    const db = new DatabaseSync(':memory:');
    for (const m of migrations) db.exec(m);
    const d = new ArgDictionary(db);
    const tricky = ['', ' ', '-c', 'é', '😀', 'x'.repeat(100_000), '-c', '"quoted"', '\\%_'];
    const blob = d.encode(tricky, 1);
    expect(d.decode(blob)).toEqual(tricky);
    // A fresh reader with nothing cached reads the same text from disk.
    expect(new ArgDictionary(db).decode(blob)).toEqual(tricky);
  });

  it('leaves text SQLite would change to the body', () => {
    expect(encodable(['a', '😀'])).toBe(true);
    expect(encodable(['a\u0000b'])).toBe(false);
    expect(encodable(['\uD800'])).toBe(false);
    expect(encodable(['x\uDC00'])).toBe(false);
  });

  it('packs ids past one byte and keeps them distinct', () => {
    const db = new DatabaseSync(':memory:');
    for (const m of migrations) db.exec(m);
    const d = new ArgDictionary(db);
    const many = Array.from({ length: 20_000 }, (_, i) => `arg-${i}`);
    const blob = d.encode(many, 1);
    expect(new Set(argIds(blob)).size).toBe(many.length);
    expect(new ArgDictionary(db).decode(blob)).toEqual(many);
  });

  it('never reuses an id once its argument is pruned', () => {
    const db = new DatabaseSync(':memory:');
    for (const m of migrations) db.exec(m);
    const d = new ArgDictionary(db);
    const old = d.encode(['gone'], 0);
    d.prune(10 * HOUR);
    const fresh = d.encode(['new'], 10 * HOUR);
    expect(argIds(fresh)[0]).not.toBe(argIds(old)[0]);
    expect(d.decode(old)).toEqual([MISSING_ARG]);
  });
});

describe('Store: arguments as ids', () => {
  it('stores a launch no rule matched with ids, and reads it back whole everywhere', () => {
    const { db, s } = open();
    const e = launch(['-c', 'git status --porcelain', '-c', '']);
    s.insertEvents([{ event: e, outcome: none }]);
    const row = stored(db, e.id);
    expect(row.args).not.toBeNull();
    expect(JSON.parse(row.body).process.args).toBeUndefined();

    expect(s.getEvent(e.id)).toEqual(e);
    expect(s.getEvents([e.id])).toEqual([e]);
    expect([...s.eventsBetween(0, 20 * HOUR)]).toEqual([e]);
    expect(s.recentEvents({ kind: 'process.exec' })).toEqual([e]);
    expect(s.listEventViews({}, 10 * HOUR)[0]?.event).toEqual(e);
    expect([...s.iterateExecEvents(0)][0]?.args).toEqual(e.process.args);
  });

  it('keeps arguments with a NUL or a lone surrogate in the body, exactly', () => {
    const { db, s } = open();
    const e = launch(['a\u0000b', '\uD800']);
    s.insertEvents([{ event: e, outcome: none }]);
    expect(stored(db, e.id).args).toBeNull();
    expect(s.getEvent(e.id)).toEqual(e);
  });

  it('keeps arguments in the body for a launch a rule matched, and for an alert’s events', () => {
    const { db, s } = open();
    const matched = launch(['--evil']);
    s.insertEvents([{ event: matched, outcome: hit }]);
    expect(stored(db, matched.id).args).toBeNull();
    expect(JSON.parse(stored(db, matched.id).body).process.args).toEqual(['--evil']);

    const alerted = launch(['--also']);
    s.insertEvent(alerted);
    expect(stored(db, alerted.id).args).toBeNull();
  });

  it('ends with the arguments in the body whichever copy is written first', () => {
    for (const alertFirst of [true, false]) {
      const { db, s } = open();
      const e = launch(['curl', 'http://x']);
      const writes = [() => s.insertEvent(e), () => s.insertEvents([{ event: e, outcome: none }])];
      for (const w of alertFirst ? writes : writes.reverse()) w();
      const row = stored(db, e.id);
      expect(row.args).toBeNull();
      expect(JSON.parse(row.body).process.args).toEqual(['curl', 'http://x']);
      expect(s.getEvent(e.id)).toEqual(e);
      // The outcome is filled in either way.
      expect(s.listEventViews({}, e.ts)[0]?.outcome).toEqual(none);
    }
  });

  it('prunes arguments no remaining event uses, and keeps every one that is used', () => {
    const { db, s } = open();
    const old = launch(['only-old', 'shared'], 1 * HOUR);
    const kept = launch(['shared', 'only-new'], 5 * HOUR);
    // An alert keeps an old event past the cut.
    const alerted = launch(['alerted'], 1 * HOUR);
    s.insertEvents([
      { event: old, outcome: none },
      { event: kept, outcome: none },
      { event: alerted, outcome: none },
    ]);
    s.insertEvent(alerted);
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
      eventIds: [alerted.id],
      actionIds: [],
    });

    s.pruneEvents(4 * HOUR);
    expect(s.getEvent(old.id)).toBeUndefined();
    expect(s.getEvent(kept.id)).toEqual(kept);
    expect(s.getEvent(alerted.id)).toEqual(alerted);
    // 'shared' was last used at 5h, so it stays; 'only-old' is dropped.
    const values = (db.prepare('SELECT value FROM arg_strings').all() as { value: string }[]).map(
      (r) => r.value,
    );
    expect(values.sort()).toEqual(['only-new', 'shared']);
  });

  it('keeps arguments an older event still holds as ids', () => {
    const { db, s } = open();
    const e = launch(['held'], 1 * HOUR);
    s.insertEvents([{ event: e, outcome: none }]);
    // An alert references the event but its whole copy was never written.
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
      eventIds: [e.id],
      actionIds: [],
    });
    s.pruneEvents(10 * HOUR);
    expect(stored(db, e.id).args).not.toBeNull();
    expect(s.getEvent(e.id)).toEqual(e);
  });

  it('forgets cached ids when a transaction rolls back', () => {
    const { s } = open();
    const a = launch(['rolled-back']);
    expect(() =>
      s.tx(() => {
        s.insertEvents([{ event: a, outcome: none }]);
        throw new Error('undo');
      }),
    ).toThrow('undo');
    const b = launch(['rolled-back']);
    s.insertEvents([{ event: b, outcome: none }]);
    expect(s.getEvent(b.id)).toEqual(b);
  });

  it('finds launches by the text of their arguments', () => {
    const { s } = open();
    const e = launch(['--needle-in-args']);
    const other = launch(['--hay']);
    s.insertEvents([
      { event: e, outcome: none },
      { event: other, outcome: none },
    ]);
    expect(s.listEventViews({ text: 'needle' }, e.ts).map((v) => v.event.id)).toEqual([e.id]);
    expect(
      s
        .searchEvents({ since: 0, text: 'needle', limit: 10, scanRows: 100 })
        .views.map((v) => v.event.id),
    ).toEqual([e.id]);
    // LIKE wildcards in the search are literal.
    expect(s.listEventViews({ text: 'needle%' }, e.ts)).toEqual([]);
  });

  it('finds argument text the same way once a search has looked up many arguments', () => {
    const { s } = open();
    const many = Array.from({ length: 3_000 }, (_, i) => launch([`--plain-${i}`], 10 * HOUR + i));
    const target = launch(['--Needle-Late'], 10 * HOUR - 1); // checked after the rest
    s.insertEvents([...many, target].map((event) => ({ event, outcome: none })));
    const found = s.searchEvents({ since: 0, text: 'needle-l', limit: 5, scanRows: 10_000 });
    expect(found.views.map((v) => v.event.id)).toEqual([target.id]);
    // Wildcards stay literal on the dictionary path too.
    expect(s.searchEvents({ since: 0, text: 'needle_', limit: 5, scanRows: 10_000 }).views).toEqual(
      [],
    );
  });

  it('reads launches stored before the change, with arguments in the body', () => {
    const { db, s } = open();
    const e = launch(['legacy']);
    db.prepare(
      'INSERT INTO events (id, ts, kind, source, body, outcome) VALUES (?, ?, ?, ?, ?, ?)',
    ).run(e.id, e.ts, e.kind, e.source, JSON.stringify(e), JSON.stringify(none));
    expect(s.getEvent(e.id)).toEqual(e);
    expect([...s.iterateExecEvents(0)][0]?.args).toEqual(['legacy']);
    expect(s.listEventViews({ text: 'legacy' }, e.ts)).toHaveLength(1);
  });
});

describe('Store: who reads arguments', () => {
  // Every way an event leaves the store gives back its exact arguments.
  it('gives back the arguments through every reader', () => {
    const { s } = open();
    const args = ['-c', 'curl -s https://example.test | sh', '', 'é'];
    const base = launch(args);
    const e: EventOfKind<'process.exec'> = {
      ...base,
      process: {
        ...base.process,
        agent: { id: 'claude-code', session: '5e55105e55105e55', depth: 1 },
      },
    };
    s.insertEvent(e, none);
    s.setEventLabels([
      { eventId: e.id, label: { label: 'unusual', score: 0.5, reason: 'r', by: 'model', at: 1 } },
    ]);
    const got = (x: unknown) => (x as { process: { args?: string[] } }).process.args;
    const reads: [string, unknown][] = [
      ['getEvent', s.getEvent(e.id)],
      ['getEvents', s.getEvents([e.id])[0]],
      ['getEventViews', s.getEventViews([e.id])[0]?.event],
      ['eventsBetween', [...s.eventsBetween(0, 20 * HOUR)][0]],
      ['recentEvents', s.recentEvents({})[0]],
      ['recentEvents by kind', s.recentEvents({ kind: 'process.exec' })[0]],
      ['listEventViews', s.listEventViews({}, e.ts)[0]?.event],
      ['listEventViews text', s.listEventViews({ text: 'example.test' }, e.ts)[0]?.event],
      ['searchEvents', s.searchEvents({ since: 0, limit: 5, scanRows: 5 }).views[0]?.event],
      [
        'searchEvents text',
        s.searchEvents({ since: 0, text: 'EXAMPLE', limit: 5, scanRows: 5 }).views[0]?.event,
      ],
      ['sessionEvents', s.sessionEvents('5e55105e55105e55')[0]?.event],
      [
        'sessionEvents by kind',
        s.sessionEvents('5e55105e55105e55', 5, { kind: 'process.exec' })[0]?.event,
      ],
      ['iterateExecEvents', { process: { args: [...s.iterateExecEvents(0)][0]?.args } }],
    ];
    for (const [name, read] of reads) expect([name, read && got(read)]).toEqual([name, args]);
  });

  // Readers outside the store go through Store.event; this catches a query
  // that reads bodies without the packed arguments, or decodes them by hand.
  it('leaves no query outside the store reading event bodies without Store.event', () => {
    const root = join(__dirname, '..', '..', '..', '..');
    const files: string[] = [];
    const walk = (dir: string): void => {
      for (const name of readdirSync(dir)) {
        const p = join(dir, name);
        if (name === 'node_modules' || name === 'dist' || name === 'out') continue;
        if (statSync(p).isDirectory()) walk(p);
        else if (/\.(ts|tsx|js|mjs|cjs)$/.test(p) && !/\.test\./.test(p)) files.push(p);
      }
    };
    for (const top of ['apps', 'packages', 'scripts'])
      for (const pkg of readdirSync(join(root, top))) {
        const p = join(root, top, pkg);
        if (statSync(p).isDirectory()) walk(p);
        else if (/\.(ts|js|mjs|cjs)$/.test(p)) files.push(p);
      }
    expect(files.some((f) => f.endsWith(join('db', 'store.ts')))).toBe(true);
    const bad: string[] = [];
    for (const f of files) {
      if (f.endsWith(join('db', 'store.ts'))) continue;
      const text = readFileSync(f, 'utf8');
      for (const m of text.matchAll(/SELECT\s+([\s\S]*?)\s+FROM\s+events\b/g)) {
        const cols = m[1]!.replace(/json_extract\([^)]*\)/g, '');
        if (!/\bbody\b/.test(cols) && !m[0].includes('$.process.args')) continue;
        if (!/\bargs\b/.test(cols) || !text.includes('store.event('))
          bad.push(`${relative(root, f)}: ${m[0].slice(0, 80)}`);
      }
    }
    expect(bad).toEqual([]);
  });
});
