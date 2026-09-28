// Record of every action the helper took, and what is needed to reverse it.
// Root-owned JSON file (0600). Also the source of truth for re-applying
// firewall blocks after a reboot, since pf forgets them.

import { randomBytes } from 'node:crypto';
import { mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import type { HelperAction } from './protocol.js';

export type ActionState = 'active' | 'undone' | 'final';

export interface JournalEntry {
  id: string;
  kind: HelperAction['kind'];
  /** What the action was asked to do (the validated command). */
  command: HelperAction;
  /** What undo needs: original path, previous Santa rule, process start time... */
  undo?: Record<string, unknown>;
  /** active = in force and reversible; final = done and nothing to reverse (kill, releases); undone = reversed. */
  state: ActionState;
  createdAt: number;
  undoneAt?: number;
  summary: string;
}

interface JournalFile {
  version: 1;
  entries: JournalEntry[];
}

const MAX_ENTRIES = 5000;

export class Journal {
  private data: JournalFile;

  constructor(
    private readonly filePath: string | undefined,
    private readonly now: () => number = Date.now,
  ) {
    this.data = { version: 1, entries: [] };
    if (filePath) {
      try {
        const parsed = JSON.parse(readFileSync(filePath, 'utf8')) as JournalFile;
        if (parsed.version === 1 && Array.isArray(parsed.entries)) this.data = parsed;
      } catch (err) {
        if ((err as NodeJS.ErrnoException).code !== 'ENOENT') {
          throw new Error(`Cannot read helper journal at ${filePath}: ${(err as Error).message}`, {
            cause: err,
          });
        }
      }
    }
  }

  static newId(): string {
    return randomBytes(12).toString('hex');
  }

  add(entry: Omit<JournalEntry, 'createdAt'> & { createdAt?: number }): JournalEntry {
    const full: JournalEntry = { createdAt: this.now(), ...entry };
    this.data.entries.push(full);
    // Keep every active entry; trim only old finished ones.
    if (this.data.entries.length > MAX_ENTRIES) {
      const excess = this.data.entries.length - MAX_ENTRIES;
      let dropped = 0;
      this.data.entries = this.data.entries.filter((e) => {
        if (dropped < excess && e.state !== 'active') {
          dropped++;
          return false;
        }
        return true;
      });
    }
    this.save();
    return full;
  }

  get(id: string): JournalEntry | undefined {
    return this.data.entries.find((e) => e.id === id);
  }

  markUndone(id: string): void {
    const e = this.get(id);
    if (!e) return;
    e.state = 'undone';
    e.undoneAt = this.now();
    this.save();
  }

  active(): JournalEntry[] {
    return this.data.entries.filter((e) => e.state === 'active');
  }

  recent(limit = 100): JournalEntry[] {
    return this.data.entries.slice(-limit).reverse();
  }

  private save(): void {
    if (!this.filePath) return;
    mkdirSync(dirname(this.filePath), { recursive: true, mode: 0o700 });
    const tmp = `${this.filePath}.tmp-${process.pid}`;
    writeFileSync(tmp, JSON.stringify(this.data, null, 2), { mode: 0o600 });
    renameSync(tmp, this.filePath);
  }
}
