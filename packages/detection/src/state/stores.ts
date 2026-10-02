import type { AgentIdentity, RuleMode } from '@vigil/core';
import { BlockList, isIP } from 'node:net';
import type { DetectionEvent } from '../types.js';

/**
 * Storage the engine needs. All calls are synchronous so the inline path never
 * awaits: the in-memory stores below are the source of truth at runtime, and
 * the SQLite versions in sqlite.ts write through to disk.
 */

export interface BaselineStore {
  has(scope: string, key: string): boolean;
  add(scope: string, key: string, ts: number): void;
  size(): number;
}

export interface ListEntryMeta {
  source: string;
  updatedAt: number;
}

/**
 * Named lists of indicators: known-bad hashes, domains, IPs and CIDRs,
 * browser team IDs, and so on. A lookup matches exactly (case-insensitive),
 * or by subnet for IPs, or by parent domain (evil.test also matches a.evil.test).
 */
export interface ListStore {
  has(list: string, value: string): boolean;
  replace(list: string, entries: Iterable<string>, meta: ListEntryMeta): void;
  add(list: string, entry: string, meta: ListEntryMeta): void;
  names(): string[];
  size(list: string): number;
  /** Every entry as stored (lower-cased; subnets as written), for copying a list elsewhere. */
  entries(list: string): string[];
}

/**
 * A user decision that a rule should not fire for a specific thing. Every
 * field in `match` must equal (case-insensitively) for the exception to apply,
 * so "this signer" can require both team ID and signing ID.
 */
export interface RuleException {
  id: string;
  /** A rule id, or "*" to exempt the thing from every rule. */
  ruleId: string;
  match: Record<string, string>;
  createdAt: number;
  note?: string;
}

export interface ExceptionStore {
  forRule(ruleId: string): RuleException[];
  add(ex: RuleException): void;
  remove(id: string): void;
  all(): RuleException[];
}

export type Verdict = 'malicious' | 'benign' | 'expected';

export interface VerdictRecord {
  detectionId: string;
  ruleId: string;
  verdict: Verdict;
  ts: number;
}

export interface RuleState {
  ruleId: string;
  /** Overrides the rule's own mode once the user or the engine has moved it. */
  mode?: RuleMode;
  fired: number;
  lastFiredAt?: number;
}

export interface RuleStateStore {
  get(ruleId: string): RuleState | undefined;
  put(state: RuleState): void;
  recordVerdict(v: VerdictRecord): void;
  verdicts(ruleId: string, sinceTs: number): VerdictRecord[];
}

/** Raw event history, kept for a short window so proposed rules can be replayed. */
export interface EventHistory {
  append(e: DetectionEvent): void;
  range(fromTs: number, toTs: number): Iterable<DetectionEvent>;
  prune(beforeTs: number): number;
}

/**
 * Watched-agent records: the user's own agents, Vigil's suggestions, and the
 * user's changes to built-in ones. The built-in catalogue itself is code, not
 * stored, so a release can update it.
 */
export interface AgentStore {
  list(): AgentIdentity[];
  put(a: AgentIdentity): void;
  remove(id: string): void;
}

// ---------------------------------------------------------------------------
// In-memory implementations

export class MemoryBaselineStore implements BaselineStore {
  private readonly keys = new Map<string, Set<string>>();
  has(scope: string, key: string): boolean {
    return this.keys.get(scope)?.has(key) ?? false;
  }
  add(scope: string, key: string, _ts?: number): void {
    let s = this.keys.get(scope);
    if (!s) this.keys.set(scope, (s = new Set()));
    s.add(key);
  }
  size(): number {
    let n = 0;
    for (const s of this.keys.values()) n += s.size;
    return n;
  }
}

class IndicatorList {
  readonly exact = new Set<string>();
  readonly cidrs: string[] = [];
  private blocks: BlockList | undefined;

  add(raw: string): void {
    const entry = raw.trim().toLowerCase();
    if (!entry || entry.startsWith('#')) return;
    const [addr, prefix] = entry.split('/');
    if (prefix !== undefined && addr && isIP(addr)) {
      this.blocks ??= new BlockList();
      this.blocks.addSubnet(addr, Number(prefix), isIP(addr) === 4 ? 'ipv4' : 'ipv6');
      this.cidrs.push(entry);
      return;
    }
    this.exact.add(entry);
  }

  has(raw: string): boolean {
    const v = raw.trim().toLowerCase();
    if (this.exact.has(v)) return true;
    const fam = isIP(v);
    if (fam !== 0) return this.blocks?.check(v, fam === 4 ? 'ipv4' : 'ipv6') ?? false;
    // Domain: walk up parent labels, stopping before the bare TLD.
    let dot = v.indexOf('.');
    while (dot !== -1) {
      const parent = v.slice(dot + 1);
      if (!parent.includes('.')) break;
      if (this.exact.has(parent)) return true;
      dot = v.indexOf('.', dot + 1);
    }
    return false;
  }

  get size(): number {
    return this.exact.size + this.cidrs.length;
  }
}

export class MemoryListStore implements ListStore {
  private readonly lists = new Map<string, IndicatorList>();
  has(list: string, value: string): boolean {
    return this.lists.get(list)?.has(value) ?? false;
  }
  replace(list: string, entries: Iterable<string>, _meta?: ListEntryMeta): void {
    const l = new IndicatorList();
    for (const e of entries) l.add(e);
    this.lists.set(list, l);
  }
  add(list: string, entry: string, _meta?: ListEntryMeta): void {
    let l = this.lists.get(list);
    if (!l) this.lists.set(list, (l = new IndicatorList()));
    l.add(entry);
  }
  names(): string[] {
    return [...this.lists.keys()];
  }
  size(list: string): number {
    return this.lists.get(list)?.size ?? 0;
  }
  entries(list: string): string[] {
    const l = this.lists.get(list);
    return l ? [...l.exact, ...l.cidrs] : [];
  }
}

export class MemoryExceptionStore implements ExceptionStore {
  private readonly byId = new Map<string, RuleException>();
  forRule(ruleId: string): RuleException[] {
    const out: RuleException[] = [];
    for (const ex of this.byId.values())
      if (ex.ruleId === ruleId || ex.ruleId === '*') out.push(ex);
    return out;
  }
  add(ex: RuleException): void {
    this.byId.set(ex.id, ex);
  }
  remove(id: string): void {
    this.byId.delete(id);
  }
  all(): RuleException[] {
    return [...this.byId.values()];
  }
}

export class MemoryRuleStateStore implements RuleStateStore {
  private readonly states = new Map<string, RuleState>();
  private readonly log: VerdictRecord[] = [];
  get(ruleId: string): RuleState | undefined {
    return this.states.get(ruleId);
  }
  put(state: RuleState): void {
    this.states.set(state.ruleId, { ...state });
  }
  recordVerdict(v: VerdictRecord): void {
    this.log.push(v);
  }
  verdicts(ruleId: string, sinceTs: number): VerdictRecord[] {
    return this.log.filter((v) => v.ruleId === ruleId && v.ts >= sinceTs);
  }
}

export class MemoryEventHistory implements EventHistory {
  private events: DetectionEvent[] = [];
  append(e: DetectionEvent): void {
    // Sensors deliver in near order; keep the array sorted for range scans.
    const last = this.events[this.events.length - 1];
    if (!last || last.ts <= e.ts) this.events.push(e);
    else {
      let i = this.events.length - 1;
      while (i > 0 && this.events[i - 1]!.ts > e.ts) i--;
      this.events.splice(i, 0, e);
    }
  }
  *range(fromTs: number, toTs: number): Iterable<DetectionEvent> {
    for (const e of this.events) {
      if (e.ts < fromTs) continue;
      if (e.ts > toTs) break;
      yield e;
    }
  }
  prune(beforeTs: number): number {
    const before = this.events.length;
    this.events = this.events.filter((e) => e.ts >= beforeTs);
    return before - this.events.length;
  }
}

export class MemoryAgentStore implements AgentStore {
  private readonly byId = new Map<string, AgentIdentity>();
  list(): AgentIdentity[] {
    return [...this.byId.values()];
  }
  put(a: AgentIdentity): void {
    this.byId.set(a.id, a);
  }
  remove(id: string): void {
    this.byId.delete(id);
  }
}

export interface Stores {
  baseline: BaselineStore;
  lists: ListStore;
  exceptions: ExceptionStore;
  ruleState: RuleStateStore;
  history: EventHistory;
}

export function memoryStores(): Stores {
  return {
    baseline: new MemoryBaselineStore(),
    lists: new MemoryListStore(),
    exceptions: new MemoryExceptionStore(),
    ruleState: new MemoryRuleStateStore(),
    history: new MemoryEventHistory(),
  };
}
