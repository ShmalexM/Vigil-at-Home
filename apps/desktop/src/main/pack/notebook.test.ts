import { DatabaseSync } from 'node:sqlite';
import { redactValue } from '@vigil/ai/redact';
import { describe, expect, it } from 'vitest';
import { NOTE_DAYS, Notebook } from './notebook.js';

const DAY = 24 * 60 * 60_000;

function setup() {
  let at = Date.UTC(2026, 9, 5, 12);
  const changes: number[] = [];
  const book = new Notebook(new DatabaseSync(':memory:'), {
    now: () => at,
    onChange: () => changes.push(at),
  });
  return { book, changes, tick: (ms: number) => (at += ms) };
}

const NOTE = { dog: 'lead', kind: 'chat', ok: true, ask: 'hi', answer: 'hello' } as const;

describe('Notebook', () => {
  it('lists notes newest first, by dog or by what they were about', () => {
    const { book, tick, changes } = setup();
    book.write({ ...NOTE, ask: 'first' });
    tick(1000);
    book.write({ ...NOTE, ask: 'second', subject: { kind: 'alert', id: 'a1' } });
    book.write({ ...NOTE, dog: 'helper-explainer', subject: { kind: 'alert', id: 'a1' } });
    expect(book.list({ dog: 'lead' }).map((n) => n.ask)).toEqual(['second', 'first']);
    expect(book.list({ subject: { kind: 'alert', id: 'a1' } })).toHaveLength(2);
    expect(book.list({ subject: { kind: 'rule', id: 'a1' } })).toHaveLength(0);
    expect(book.countsSince(0)).toEqual({ lead: 2, 'helper-explainer': 1 });
    expect(changes).toHaveLength(3);
    expect(book.tally(0)).toEqual(
      expect.arrayContaining([
        { dog: 'lead', kind: 'chat', n: 2, failed: 0 },
        { dog: 'helper-explainer', kind: 'chat', n: 1, failed: 0 },
      ]),
    );
    book.write({ ...NOTE, ok: false });
    expect(book.tally(0).find((t) => t.dog === 'lead')).toMatchObject({ n: 3, failed: 1 });
  });

  it('keeps notes short: long text and long lists are clipped', () => {
    const { book } = setup();
    const n = book.write({
      ...NOTE,
      answer: 'x'.repeat(5000),
      reasons: ['  ', ...Array.from({ length: 20 }, (_, i) => `r${i}`)],
      lookedAt: Array.from({ length: 20 }, (_, i) => `t${i}`),
    });
    expect(n.answer.length).toBe(2000);
    expect(n.reasons).toHaveLength(12);
    expect(n.reasons[0]).toBe('r0');
    expect(n.lookedAt).toHaveLength(12);
  });

  it(`forgets notes after ${NOTE_DAYS} days, and clears on request`, () => {
    const { book, tick } = setup();
    book.write(NOTE);
    tick((NOTE_DAYS + 1) * DAY);
    expect(book.list()).toHaveLength(0);
    book.write({ ...NOTE, dog: 'pip' });
    book.write(NOTE);
    expect(book.countsSince(0)).toEqual({ lead: 1, pip: 1 });
    book.clear('pip');
    expect(book.list().map((n) => n.dog)).toEqual(['lead']);
    book.clear();
    expect(book.list()).toHaveLength(0);
  });

  it('keeps tool calls and usage in shape, and reads notes written before they existed', () => {
    const db = new DatabaseSync(':memory:');
    const book = new Notebook(db, { now: () => Date.UTC(2026, 9, 5, 12) });
    const n = book.write({
      ...NOTE,
      calls: Array.from({ length: 30 }, (_, i) => ({
        tool: 'vigil.search_events',
        title: 'Vigil › Search events',
        args: 'a'.repeat(900),
        outcome: i % 2 ? ('not-run' as const) : ('ran' as const),
        ...(i % 2 ? { reason: 'r'.repeat(500) } : { result: 'z'.repeat(1200) }),
      })),
      usage: { inputTokens: 10.4, cachedInputTokens: -1, outputTokens: 5, costUsd: -2 },
    });
    expect(n.calls).toHaveLength(24);
    expect(n.calls![0]!.args).toHaveLength(600);
    expect(n.calls![0]!.result).toHaveLength(800);
    expect(n.calls![1]!.reason).toHaveLength(300);
    expect(n.usage).toEqual({
      inputTokens: 10,
      cachedInputTokens: 0,
      outputTokens: 5,
      costUsd: null,
    });
    expect(book.list()[0]).toEqual(n);

    // A note from an older Vigil: no calls, no usage. It reads back as it was.
    const old = {
      id: 'old-1',
      at: Date.UTC(2026, 9, 5, 11),
      dog: 'pip',
      kind: 'job',
      ok: true,
      ask: 'look',
      lookedAt: ['vigil.search_events'],
      answer: 'fine',
      reasons: [],
    };
    db.prepare('INSERT INTO pack_notes (id, ts, dog, subject, body) VALUES (?, ?, ?, ?, ?)').run(
      old.id,
      old.at,
      old.dog,
      null,
      JSON.stringify(old),
    );
    expect(book.list({ dog: 'pip' })).toEqual([old]);
    // A note without calls stores none.
    expect(book.write(NOTE)).not.toHaveProperty('calls');
  });

  it('trims old notes and over-full notebooks when it opens', () => {
    const db = new DatabaseSync(':memory:');
    let at = Date.UTC(2026, 9, 5, 12);
    const book = new Notebook(db, { now: () => at });
    book.write({ ...NOTE, dog: 'quiet' });
    at += (NOTE_DAYS + 1) * DAY;
    // Rows from before the cap, or written by an older build.
    const insert = db.prepare(
      'INSERT INTO pack_notes (id, ts, dog, subject, body) VALUES (?, ?, ?, ?, ?)',
    );
    for (let i = 0; i < 2005; i++)
      insert.run(
        `n${i}`,
        at - i,
        'busy',
        null,
        JSON.stringify({ ...NOTE, dog: 'busy', id: `n${i}` }),
      );
    const count = () =>
      db.prepare('SELECT dog, COUNT(*) AS n FROM pack_notes GROUP BY dog ORDER BY dog').all();
    expect(count()).toEqual([
      { dog: 'busy', n: 2005 },
      { dog: 'quiet', n: 1 },
    ]);
    new Notebook(db, { now: () => at });
    expect(count()).toEqual([{ dog: 'busy', n: 2000 }]);
  });

  it('drops every note of a dog that no longer exists when told which do, whatever its age', () => {
    const db = new DatabaseSync(':memory:');
    const changes: number[] = [];
    const book = new Notebook(db, { onChange: () => changes.push(1) });
    book.write(NOTE);
    book.write({ ...NOTE, dog: 'helper-explainer', kind: 'explain' });
    book.write({ ...NOTE, dog: 'pip', kind: 'job' });
    book.write({ ...NOTE, dog: 'gone', kind: 'judge' });
    changes.length = 0;
    book.prune(new Set(['lead', 'helper-explainer', 'pip']));
    expect(
      book
        .list()
        .map((n) => n.dog)
        .sort(),
    ).toEqual(['helper-explainer', 'lead', 'pip']);
    expect(changes).toHaveLength(1);
    // Without the list of dogs it only trims by age and size.
    book.write({ ...NOTE, dog: 'other' });
    book.prune();
    expect(book.list()).toHaveLength(4);
  });
});

/** Joined at run time so code scanning doesn't take the samples for real keys. */
const KEY = ['sk', 'ant', 'Abc123Def456Ghi789Jkl012Mno'].join('-');
const PASSWORD = ['hunter2', 'Plain', 'Word'].join('');
const TOKEN = ['tok', 'Plain', 'Value9'].join('');
/**
 * Whether the redactor in this tree withholds a value for its key's name
 * alone ({"password": ...}). main's doesn't yet; PR #133's does. Tests that
 * need it run only where it's there, and are named so.
 */
const KEY_AWARE =
  JSON.stringify(redactValue({ password: PASSWORD }, {})) !==
  JSON.stringify({ password: PASSWORD });

describe('Notebook redaction', () => {
  const rows = (db: DatabaseSync) =>
    JSON.stringify(db.prepare('SELECT body FROM pack_notes').all());

  it('redacts every field before it cuts it to size or stores it', () => {
    const db = new DatabaseSync(':memory:');
    const book = new Notebook(db);
    const n = book.write({
      ...NOTE,
      ask: `why does ${KEY} fail?`,
      // Cut first, the end of this key would be left too short to spot.
      answer: `${'x'.repeat(1990)} ${KEY}`,
      reasons: [`it read ${KEY}`],
      lookedAt: [`file with ${KEY}`],
      thinking: `the key ${KEY}`,
      calls: [
        {
          tool: 'github.search',
          title: `GitHub › Search ${KEY}`,
          args: { q: `owner ${KEY}`, nested: [{ auth: `Bearer ${KEY}` }] },
          outcome: 'failed',
          reason: `401: invalid key ${KEY}`,
        },
        {
          tool: 'github.read',
          title: 'GitHub › Read',
          args: `{"q":"${KEY}"}`,
          outcome: 'ran',
          result: { rows: [{ note: `${'y'.repeat(795)}${KEY}` }] },
        },
      ],
    });
    for (const text of [JSON.stringify(n), rows(db), JSON.stringify(book.list())]) {
      expect(text).not.toContain(KEY);
      expect(text).not.toContain('sk-ant');
    }
    expect(n.answer.length).toBeLessThanOrEqual(2000);
    expect(n.calls![1]!.result!.length).toBeLessThanOrEqual(800);
  });

  it('redacts notes stored before every field was, each time they are read', () => {
    const db = new DatabaseSync(':memory:');
    const book = new Notebook(db);
    const old = {
      id: 'old-1',
      at: Date.now(),
      dog: 'lead',
      kind: 'chat',
      ok: false,
      ask: `my key is ${KEY}`,
      lookedAt: [],
      answer: `I saw ${KEY}`,
      reasons: [`because ${KEY}`],
      calls: [
        {
          tool: 'github.read',
          title: `GitHub › ${KEY}`,
          args: `{"key":"${KEY}"}`,
          outcome: 'failed',
          reason: `rejected ${KEY}`,
          result: `{"echo":"${KEY}"}`,
        },
      ],
    };
    db.prepare('INSERT INTO pack_notes (id, ts, dog, subject, body) VALUES (?, ?, ?, ?, ?)').run(
      old.id,
      old.at,
      old.dog,
      null,
      JSON.stringify(old),
    );
    const [read] = book.list();
    expect(read).toMatchObject({ id: 'old-1', dog: 'lead', kind: 'chat', ok: false });
    expect(JSON.stringify(read)).not.toContain(KEY);
  });

  it.skipIf(!KEY_AWARE)(
    '[needs #133’s redactor] withholds values under credential-named keys, on write and on read',
    () => {
      const db = new DatabaseSync(':memory:');
      const book = new Notebook(db);
      book.write({
        ...NOTE,
        calls: [
          {
            tool: 'vigil.search_events',
            title: 'Vigil › Search events',
            args: { password: PASSWORD, limit: 5 },
            outcome: 'ran',
            result: { token: TOKEN, rows: [] },
          },
        ],
      });
      db.prepare('INSERT INTO pack_notes (id, ts, dog, subject, body) VALUES (?, ?, ?, ?, ?)').run(
        'old-2',
        Date.now(),
        'lead',
        null,
        JSON.stringify({
          ...NOTE,
          id: 'old-2',
          at: Date.now(),
          lookedAt: [],
          reasons: [],
          calls: [
            {
              tool: 't',
              title: 't',
              args: JSON.stringify({ password: PASSWORD }),
              outcome: 'ran',
              result: JSON.stringify({ token: TOKEN }),
            },
          ],
        }),
      );
      expect(rows(db).includes(PASSWORD) && rows(db).includes('old-2')).toBe(true);
      const text = JSON.stringify(book.list());
      expect(book.list()).toHaveLength(2);
      expect(text).not.toContain(PASSWORD);
      expect(text).not.toContain(TOKEN);
    },
  );
});
