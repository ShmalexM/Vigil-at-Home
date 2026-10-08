// The rules Vigil serves to Santa, with a revision counter so each sync only
// sends what changed since Santa last confirmed a sync.
//
// Stored as one JSON file. In production the root helper owns this file
// (mode 0600, root) so nothing running as the user can add allow rules behind
// Vigil's back.

import { mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import type { RulePolicy, RuleType, SantaRule } from './syncProtocol.js';
import { isValidRuleIdentifier } from './syncProtocol.js';

export interface StoredRule {
  rule: SantaRule;
  /** Revision at which this rule last changed. */
  rev: number;
  /** A removed rule is kept as a tombstone so incremental syncs send REMOVE. */
  removed: boolean;
  reason?: string | undefined;
  updatedAt: number;
}

interface RuleStoreFile {
  version: 1;
  rev: number;
  /** Highest revision Santa has confirmed applying (set at postflight). */
  syncedRev: number;
  /** Set when Santa must drop everything and take the full rule set. */
  cleanSyncPending: boolean;
  rules: Record<string, StoredRule>;
}

export interface RuleChange {
  ruleType: RuleType;
  identifier: string;
  policy: Exclude<RulePolicy, 'REMOVE'>;
  reason?: string | undefined;
  customMessage?: string | undefined;
  /** Required for policy CEL, ignored otherwise. */
  celExpr?: string | undefined;
}

export function ruleKey(ruleType: RuleType, identifier: string): string {
  return `${ruleType}:${identifier}`;
}

export class RuleStore {
  private state: RuleStoreFile;
  /** The last save threw, so the file may be behind memory. */
  private unsaved = false;

  constructor(
    private readonly filePath?: string,
    private readonly now: () => number = Date.now,
  ) {
    this.state = this.load();
  }

  private load(): RuleStoreFile {
    const empty: RuleStoreFile = {
      version: 1,
      rev: 0,
      syncedRev: 0,
      cleanSyncPending: true,
      rules: {},
    };
    if (!this.filePath) return empty;
    try {
      const parsed = JSON.parse(readFileSync(this.filePath, 'utf8')) as RuleStoreFile;
      if (parsed.version !== 1 || typeof parsed.rev !== 'number') return empty;
      return parsed;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === 'ENOENT') return empty;
      // A corrupt file must not silently wipe the block list on the next
      // clean sync, so refuse to start instead.
      throw new Error(
        `Cannot read Santa rule store at ${this.filePath}: ${(err as Error).message}`,
        { cause: err },
      );
    }
  }

  private save(): void {
    if (!this.filePath) return;
    this.unsaved = true;
    mkdirSync(dirname(this.filePath), { recursive: true, mode: 0o700 });
    const tmp = `${this.filePath}.tmp-${process.pid}`;
    writeFileSync(tmp, JSON.stringify(this.state, null, 2), { mode: 0o600 });
    renameSync(tmp, this.filePath);
    this.unsaved = false;
  }

  get rev(): number {
    return this.state.rev;
  }

  get syncedRev(): number {
    return this.state.syncedRev;
  }

  get cleanSyncPending(): boolean {
    return this.state.cleanSyncPending;
  }

  requestCleanSync(): void {
    this.state.cleanSyncPending = true;
    this.save();
  }

  upsert(change: RuleChange): StoredRule {
    if (!isValidRuleIdentifier(change.ruleType, change.identifier)) {
      throw new Error(`Invalid ${change.ruleType} identifier: ${change.identifier}`);
    }
    const key = ruleKey(change.ruleType, change.identifier);
    const rev = ++this.state.rev;
    const rule: SantaRule = {
      identifier: change.identifier,
      policy: change.policy,
      rule_type: change.ruleType,
    };
    if (change.customMessage) rule.custom_msg = change.customMessage;
    if (change.policy === 'CEL') {
      if (!change.celExpr) throw new Error('A CEL rule needs an expression');
      rule.cel_expr = change.celExpr;
    }
    const stored: StoredRule = {
      rule,
      rev,
      removed: false,
      reason: change.reason,
      updatedAt: this.now(),
    };
    this.state.rules[key] = stored;
    this.save();
    return stored;
  }

  /** Returns the rule as it was before removal, or undefined if there was no active rule. */
  remove(ruleType: RuleType, identifier: string): StoredRule | undefined {
    const key = ruleKey(ruleType, identifier);
    const existing = this.state.rules[key];
    if (!existing || existing.removed) return undefined;
    const before = structuredClone(existing);
    this.state.rules[key] = {
      rule: { ...existing.rule, policy: 'REMOVE' },
      rev: ++this.state.rev,
      removed: true,
      reason: existing.reason,
      updatedAt: this.now(),
    };
    this.save();
    return before;
  }

  get(ruleType: RuleType, identifier: string): StoredRule | undefined {
    const r = this.state.rules[ruleKey(ruleType, identifier)];
    return r && !r.removed ? r : undefined;
  }

  active(): StoredRule[] {
    return Object.values(this.state.rules)
      .filter((r) => !r.removed)
      .sort((a, b) => a.rev - b.rev);
  }

  /** Rules (including REMOVE tombstones) changed after `rev`, oldest first. */
  changesSince(rev: number): StoredRule[] {
    return Object.values(this.state.rules)
      .filter((r) => r.rev > rev)
      .sort((a, b) => a.rev - b.rev);
  }

  /** Called at postflight once Santa confirms it applied rules up to `rev`. */
  markSynced(rev: number, clean: boolean): void {
    // Most syncs change nothing; don't rewrite the file for those.
    // A save that failed is retried, though memory already matches.
    if (!this.unsaved && this.state.syncedRev === rev && !(clean && this.state.cleanSyncPending))
      return;
    this.state.syncedRev = rev;
    if (clean) this.state.cleanSyncPending = false;
    this.save();
  }
}
