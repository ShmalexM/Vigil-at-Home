import type { DatabaseSync } from 'node:sqlite';
import { newId } from '@vigil/core';
import type { DiaryTally, DogNote, DogNoteInput, NotesFilter } from '../../shared/pack.js';

/** Notes older than this are dropped. */
export const NOTE_DAYS = 30;
const DAY = 24 * 60 * 60_000;
/** Per dog, so a busy labeller can't push the others' notes out. */
const MAX_PER_DOG = 2000;
const TEXT = 2000;
const LIST = 12;

/**
 * Each dog's notebook: what an AI run was asked, what it looked at, what it
 * answered and the reasons it gave in that answer. Read-only for the user and
 * never read back by any decision: nothing here blocks, allows or changes a
 * rule. Kept in its own table, created here rather than by a migration, so
 * the pack can come and go without touching the main schema's numbering.
 */
export class Notebook {
  private readonly now: () => number;
  private readonly onChange: () => void;

  constructor(
    private readonly db: DatabaseSync,
    opts: { now?: () => number; onChange?: () => void } = {},
  ) {
    this.now = opts.now ?? (() => Date.now());
    this.onChange = opts.onChange ?? (() => {});
    db.exec(`
      CREATE TABLE IF NOT EXISTS pack_notes (
        id TEXT PRIMARY KEY,
        ts INTEGER NOT NULL,
        dog TEXT NOT NULL,
        subject TEXT,
        body TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS pack_notes_dog_ts ON pack_notes (dog, ts);
      CREATE INDEX IF NOT EXISTS pack_notes_subject ON pack_notes (subject);
    `);
  }

  write(input: DogNoteInput): DogNote {
    const note: DogNote = {
      id: newId(this.now()),
      at: this.now(),
      dog: input.dog,
      kind: input.kind,
      ok: input.ok,
      ask: clip(input.ask),
      ...(input.subject ? { subject: input.subject } : {}),
      lookedAt: (input.lookedAt ?? []).slice(0, LIST).map((s) => clip(s, 300)),
      answer: clip(input.answer),
      reasons: (input.reasons ?? [])
        .map((s) => s.trim())
        .filter(Boolean)
        .slice(0, LIST)
        .map((s) => clip(s, 600)),
      ...(input.thinking ? { thinking: clip(input.thinking, 4000) } : {}),
      ...(input.provider ? { provider: input.provider } : {}),
      ...(input.model ? { model: input.model } : {}),
    };
    this.db
      .prepare('INSERT INTO pack_notes (id, ts, dog, subject, body) VALUES (?, ?, ?, ?, ?)')
      .run(note.id, note.at, note.dog, subjectKey(note.subject), JSON.stringify(note));
    this.trim(note.dog);
    this.onChange();
    return note;
  }

  /** Newest first. */
  list(filter: NotesFilter = {}): DogNote[] {
    const limit = Math.min(Math.max(filter.limit ?? 50, 1), 200);
    const where: string[] = ['ts >= ?'];
    const args: (string | number)[] = [this.now() - NOTE_DAYS * DAY];
    if (filter.dog) {
      where.push('dog = ?');
      args.push(filter.dog);
    }
    if (filter.subject) {
      where.push('subject = ?');
      args.push(subjectKey(filter.subject)!);
    }
    const rows = this.db
      .prepare(
        `SELECT body FROM pack_notes WHERE ${where.join(' AND ')} ORDER BY ts DESC, id DESC LIMIT ?`,
      )
      .all(...args, limit) as { body: string }[];
    return rows.map((r) => JSON.parse(r.body) as DogNote);
  }

  /** Notes per dog since a time, for the diary. */
  countsSince(since: number): Record<string, number> {
    const rows = this.db
      .prepare('SELECT dog, COUNT(*) AS n FROM pack_notes WHERE ts >= ? GROUP BY dog')
      .all(since) as { dog: string; n: number }[];
    return Object.fromEntries(rows.map((r) => [r.dog, Number(r.n)]));
  }

  /** Runs per dog and kind since a time, for the pack diary on Home. */
  tally(since: number): DiaryTally[] {
    const rows = this.db
      .prepare(
        `SELECT dog, json_extract(body, '$.kind') AS kind, COUNT(*) AS n,
                SUM(CASE WHEN json_extract(body, '$.ok') THEN 0 ELSE 1 END) AS failed
           FROM pack_notes WHERE ts >= ? GROUP BY dog, kind`,
      )
      .all(since) as { dog: string; kind: DiaryTally['kind']; n: number; failed: number }[];
    return rows.map((r) => ({
      dog: r.dog,
      kind: r.kind,
      n: Number(r.n),
      failed: Number(r.failed),
    }));
  }

  clear(dog?: string): void {
    if (dog) this.db.prepare('DELETE FROM pack_notes WHERE dog = ?').run(dog);
    else this.db.exec('DELETE FROM pack_notes');
    this.onChange();
  }

  private trim(dog: string): void {
    this.db.prepare('DELETE FROM pack_notes WHERE ts < ?').run(this.now() - NOTE_DAYS * DAY);
    this.db
      .prepare(
        `DELETE FROM pack_notes WHERE dog = ? AND id NOT IN
           (SELECT id FROM pack_notes WHERE dog = ? ORDER BY ts DESC, id DESC LIMIT ?)`,
      )
      .run(dog, dog, MAX_PER_DOG);
  }
}

function subjectKey(s: DogNote['subject']): string | null {
  return s ? `${s.kind}:${s.id}` : null;
}

function clip(s: string, n = TEXT): string {
  const t = s.trim();
  return t.length > n ? `${t.slice(0, n - 1)}…` : t;
}
