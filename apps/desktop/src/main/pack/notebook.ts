import type { DatabaseSync } from 'node:sqlite';
import { newId } from '@vigil/core';
import type {
  DiaryTally,
  DogNote,
  DogNoteInput,
  NotesFilter,
  NoteToolCall,
  NoteToolCallInput,
  NoteUsage,
} from '../../shared/pack.js';
import { redactDataForPack, redactTextForPack } from './redaction.js';

/** Notes older than this are dropped. */
export const NOTE_DAYS = 30;
const DAY = 24 * 60 * 60_000;
/** Per dog, so a busy labeller can't push the others' notes out. */
const MAX_PER_DOG = 2000;
const TEXT = 2000;
const LIST = 12;
/** Tool calls kept per note. */
const CALLS = 24;

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
    // Writes trim the dog that wrote; this catches dogs that went quiet.
    this.prune();
  }

  /** Every text field is redacted here, before it is cut to size or stored. */
  write(input: DogNoteInput): DogNote {
    const note: DogNote = {
      id: newId(this.now()),
      at: this.now(),
      dog: input.dog,
      kind: input.kind,
      ok: input.ok,
      ask: clip(redactText(input.ask)),
      ...(input.subject ? { subject: input.subject } : {}),
      lookedAt: (input.lookedAt ?? []).slice(0, LIST).map((s) => clip(redactText(s), 300)),
      answer: clip(redactText(input.answer)),
      reasons: reasonList(input.reasons),
      ...(input.fromOutside ? { fromOutside: true } : {}),
      ...(input.readReasons?.length ? { readReasons: reasonList(input.readReasons) } : {}),
      ...(input.thinking ? { thinking: clip(redactText(input.thinking), 4000) } : {}),
      ...(input.provider ? { provider: input.provider } : {}),
      ...(input.model ? { model: input.model } : {}),
      ...(input.calls?.length ? { calls: input.calls.slice(0, CALLS).map(call) } : {}),
      ...(input.usage ? { usage: usage(input.usage) } : {}),
    };
    this.db
      .prepare('INSERT INTO pack_notes (id, ts, dog, subject, body) VALUES (?, ?, ?, ?, ?)')
      .run(note.id, note.at, note.dog, subjectKey(note.subject), JSON.stringify(note));
    this.trim(note.dog);
    this.onChange();
    return note;
  }

  /**
   * Newest first. Redacted again on the way out, so notes written before a
   * field was redacted, or before the redactor learned a secret, never reach
   * the page or its Copy buttons as they were stored.
   */
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
    return rows.map((r) => scrub(JSON.parse(r.body) as DogNote));
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

  /**
   * Drops notes past the age limit, and each dog's beyond its cap. Run at
   * startup. Given the dogs that exist, it also drops every note of a dog
   * that doesn't, whatever its age: one retired while its run was finishing.
   */
  prune(dogsHere?: ReadonlySet<string>): void {
    const dogs = this.db.prepare('SELECT DISTINCT dog FROM pack_notes').all() as { dog: string }[];
    let gone = false;
    for (const { dog } of dogs) {
      if (dogsHere && !dogsHere.has(dog)) {
        this.db.prepare('DELETE FROM pack_notes WHERE dog = ?').run(dog);
        gone = true;
      } else this.trim(dog);
    }
    if (gone) this.onChange();
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

/** A call as stored: every field redacted whole, then cut to size. */
function call(c: NoteToolCallInput): NoteToolCall {
  return {
    tool: clip(redactText(c.tool), 120),
    title: clip(redactText(c.title), 200),
    args: clip(redactData(c.args), 600),
    outcome: c.outcome,
    ...(c.reason ? { reason: clip(redactText(c.reason), 300) } : {}),
    ...(c.result !== undefined ? { result: clip(redactData(c.result), 800) } : {}),
  };
}

/** A stored note redacted again, field by field, for reading. */
function scrub(n: DogNote): DogNote {
  return {
    ...n,
    ask: redactText(n.ask),
    lookedAt: n.lookedAt.map(redactText),
    answer: redactText(n.answer),
    reasons: n.reasons.map(redactText),
    ...(n.readReasons ? { readReasons: n.readReasons.map(redactText) } : {}),
    ...(n.thinking !== undefined ? { thinking: redactText(n.thinking) } : {}),
    ...(n.calls
      ? {
          calls: n.calls.map((c) => ({
            ...c,
            tool: redactText(c.tool),
            title: redactText(c.title),
            args: redactText(c.args),
            ...(c.reason !== undefined ? { reason: redactText(c.reason) } : {}),
            ...(c.result !== undefined ? { result: redactText(c.result) } : {}),
          })),
        }
      : {}),
  };
}

/** Read by the redactor: twice the longest field kept, so a cut never shows. */
const READ = 8000;
const redactText = (text: string) => redactTextForPack(text, READ);
const redactData = (value: unknown) => redactDataForPack(value, READ);

function usage(u: NoteUsage): NoteUsage {
  const whole = (n: number) => (Number.isFinite(n) ? Math.max(0, Math.round(n)) : 0);
  return {
    inputTokens: whole(u.inputTokens),
    cachedInputTokens: whole(u.cachedInputTokens),
    outputTokens: whole(u.outputTokens),
    costUsd: typeof u.costUsd === 'number' && u.costUsd >= 0 ? u.costUsd : null,
  };
}

function clip(s: string, n = TEXT): string {
  const t = s.trim();
  return t.length > n ? `${t.slice(0, n - 1)}…` : t;
}

function reasonList(list: readonly string[] | undefined): string[] {
  return (list ?? [])
    .map((s) => s.trim())
    .filter(Boolean)
    .slice(0, LIST)
    .map((s) => clip(redactText(s), 600));
}
