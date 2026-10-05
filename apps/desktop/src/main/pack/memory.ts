import type { DatabaseSync } from 'node:sqlite';
import { newId } from '@vigil/core';
import { redactString } from '@vigil/ai/redact';
import {
  MEMORY_TOPIC_LABEL,
  MemoryInput,
  MemoryTopic,
  type MemoryEntry,
} from '../../shared/pack.js';

/** Enough for a person's lasting facts; past this the pack asks them to tidy up. */
export const MAX_MEMORIES = 100;
/** How much of the memory rides along with each run; the rest is one recall away. */
const PROMPT_CHARS = 6000;

/**
 * The pack's memory: lasting facts about the person, their Mac and how they
 * want the pack to work, one line each, with where each came from and when.
 * Shaped after Cognition's agent memory repo (a short MEMORY.md of one-line,
 * sourced entries, grouped by topic), with three changes for a security app:
 *
 * - Only the person's own words go in. The Lead dog notes a fact straight
 *   away only from an answer that used no tool; anything a tool, an alert or
 *   a connector returned could be written by an attacker, so changes from
 *   such an answer wait on a "Remember this?" card. Pack jobs and Vigil's
 *   helpers read it and never write it, and no AI tidies it in the
 *   background.
 * - It is background for answers, never a decision: nothing here blocks,
 *   allows, approves a tool call or changes a rule. Only PackService reads it.
 * - No secrets: a fact that looks like a key, token, password or email
 *   address is refused rather than stored.
 *
 * Kept in its own table, created here like the notebooks', so the pack can
 * come and go without touching the main schema's numbering.
 */
export class PackMemory {
  private readonly now: () => number;
  private readonly onChange: () => void;

  constructor(
    private readonly db: DatabaseSync,
    opts: { now?: () => number; onChange?: () => void } = {},
  ) {
    this.now = opts.now ?? (() => Date.now());
    this.onChange = opts.onChange ?? (() => {});
    db.exec(`
      CREATE TABLE IF NOT EXISTS pack_memory (
        id TEXT PRIMARY KEY,
        added INTEGER NOT NULL,
        topic TEXT NOT NULL,
        body TEXT NOT NULL
      );
    `);
  }

  /** Every entry, grouped by topic in a fixed order, oldest first within each. */
  list(): MemoryEntry[] {
    const rows = this.db
      .prepare('SELECT body FROM pack_memory ORDER BY added ASC, id ASC')
      .all() as { body: string }[];
    const order = MemoryTopic.options;
    return rows
      .map((r) => JSON.parse(r.body) as MemoryEntry)
      .sort((a, b) => order.indexOf(a.topic) - order.indexOf(b.topic));
  }

  count(): number {
    const row = this.db.prepare('SELECT COUNT(*) AS n FROM pack_memory').get() as { n: number };
    return Number(row.n);
  }

  get(id: string): MemoryEntry | undefined {
    const row = this.db.prepare('SELECT body FROM pack_memory WHERE id = ?').get(id) as
      { body: string } | undefined;
    return row ? (JSON.parse(row.body) as MemoryEntry) : undefined;
  }

  /**
   * Saves one fact. The same fact said again is not saved twice; `replaces`
   * crosses out the entry it updates, so the memory keeps one answer per
   * question rather than two that disagree.
   */
  remember(
    input: { fact: string; topic: string },
    meta: { from: MemoryEntry['from']; source?: string; replaces?: string },
  ): MemoryEntry {
    const { fact, topic } = MemoryInput.parse(input);
    if (looksSecret(fact)) throw new Error('Memory never keeps keys, passwords or email addresses');
    const same = this.list().find((e) => sameFact(e.fact, fact));
    if (same) {
      if (meta.replaces && meta.replaces !== same.id) this.drop(meta.replaces);
      this.onChange();
      return same;
    }
    const replacing = meta.replaces ? this.get(meta.replaces) : undefined;
    if (!replacing && this.count() >= MAX_MEMORIES)
      throw new Error(`The pack remembers up to ${MAX_MEMORIES} things; forget some first`);
    const entry: MemoryEntry = {
      id: newId(this.now()),
      fact,
      topic,
      from: meta.from,
      ...(meta.source ? { source: meta.source } : {}),
      added: this.now(),
    };
    this.db
      .prepare('INSERT INTO pack_memory (id, added, topic, body) VALUES (?, ?, ?, ?)')
      .run(entry.id, entry.added, entry.topic, JSON.stringify(entry));
    if (replacing) this.drop(replacing.id);
    this.onChange();
    return entry;
  }

  forget(id?: string): void {
    if (id) this.drop(id);
    else this.db.exec('DELETE FROM pack_memory');
    this.onChange();
  }

  /**
   * What rides along with a run: the newest entries that fit, and how many
   * more there are. Ids let the Lead dog replace or forget one.
   */
  forPrompt(): {
    entries: { id: string; topic: MemoryTopic; fact: string }[];
    notShown: number;
  } {
    const all = this.list().sort((a, b) => b.added - a.added);
    const entries: { id: string; topic: MemoryTopic; fact: string }[] = [];
    let chars = 0;
    for (const e of all) {
      chars += e.fact.length + e.id.length + 16;
      if (chars > PROMPT_CHARS) break;
      entries.push({ id: e.id, topic: e.topic, fact: e.fact });
    }
    return { entries, notShown: all.length - entries.length };
  }

  /** Entries whose words match, for a dog looking past what rode along. */
  recall(words: string, limit = 20): { id: string; topic: MemoryTopic; fact: string }[] {
    const terms = [...new Set(wordsOf(words))];
    return this.list()
      .map((e) => {
        const mine = new Set(wordsOf(`${e.topic} ${e.fact}`));
        return { e, score: terms.filter((t) => mine.has(t)).length };
      })
      .filter((x) => terms.length === 0 || x.score > 0)
      .sort((a, b) => b.score - a.score || b.e.added - a.e.added)
      .slice(0, limit)
      .map(({ e }) => ({ id: e.id, topic: e.topic, fact: e.fact }));
  }

  /**
   * The memory as Markdown, in the agent memory repo's shape: a MEMORY.md
   * with one section per topic and one sourced, dated line per fact.
   */
  markdown(): string {
    const lines = ['# MEMORY.md', '', 'What the Vigil pack remembers. One fact per line.', ''];
    for (const topic of MemoryTopic.options) {
      const mine = this.list().filter((e) => e.topic === topic);
      if (mine.length === 0) continue;
      lines.push(`## ${MEMORY_TOPIC_LABEL[topic]}`, '');
      for (const e of mine) {
        const source = e.from === 'you' ? 'you' : 'Lead dog, from your words';
        lines.push(`- ${e.fact} [source: ${source}] [added: ${day(e.added)}]`);
      }
      lines.push('');
    }
    if (lines.length === 4) lines.push('_Nothing yet._', '');
    return lines.join('\n');
  }

  private drop(id: string): void {
    this.db.prepare('DELETE FROM pack_memory WHERE id = ?').run(id);
  }
}

function wordsOf(s: string): string[] {
  return s
    .toLowerCase()
    .split(/[^\p{L}\p{N}]+/u)
    .filter(Boolean);
}

/** Facts that differ only in case, spacing or a full stop are the same fact. */
function sameFact(a: string, b: string): boolean {
  const norm = (s: string) =>
    s
      .toLowerCase()
      .replace(/[.!\s]+$/, '')
      .replace(/\s+/g, ' ');
  return norm(a) === norm(b);
}

/** Anything the redactor would hide, apart from a home folder path. */
export function looksSecret(fact: string): boolean {
  const homeOnly = fact.replace(/\/(Users|home)\/[^/\s"']+/g, '/$1/<user>');
  return redactString(fact, {}) !== homeOnly;
}

function day(at: number): string {
  return new Date(at).toISOString().slice(0, 10);
}
