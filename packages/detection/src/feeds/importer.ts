import type { ListStore } from '../state/stores.js';
import { parseFeed } from './parse.js';
import type { FeedKeyName, FeedList, FeedSource } from './sources.js';
import { cleanEntries, type CleanOptions, type DropReason } from './validate.js';

/** What the importer remembers per source between runs. */
export interface FeedState {
  sourceId: string;
  /** Entry → last time the feed listed it (ms). */
  entries: Record<string, number>;
  etag?: string;
  lastModified?: string;
  /** Last successful fetch (including "not modified"). */
  fetchedAt?: number;
  lastAttemptAt?: number;
  lastError?: string;
}

export interface FeedStateStore {
  get(sourceId: string): FeedState | undefined;
  put(state: FeedState): void;
  all(): FeedState[];
}

export class MemoryFeedStateStore implements FeedStateStore {
  private readonly states = new Map<string, FeedState>();
  get(sourceId: string): FeedState | undefined {
    const s = this.states.get(sourceId);
    return s && { ...s, entries: { ...s.entries } };
  }
  put(state: FeedState): void {
    this.states.set(state.sourceId, { ...state, entries: { ...state.entries } });
  }
  all(): FeedState[] {
    return [...this.states.values()];
  }
}

/** The part of the WHATWG fetch API the importer uses; the app passes globalThis.fetch. */
export type FetchLike = (
  url: string,
  init: { headers: Record<string, string>; signal?: AbortSignal },
) => Promise<{
  status: number;
  headers: { get(name: string): string | null };
  text(): Promise<string>;
}>;

export interface FeedImporterOptions extends CleanOptions {
  fetch?: FetchLike;
  now?: () => number;
  timeoutMs?: number;
  /** Refuse bodies larger than this. */
  maxBytes?: number;
  /** Refuse a feed listing more entries than this. */
  maxEntries?: number;
  /**
   * A replace-mode feed that suddenly lists less than this share of what it
   * listed before is treated as broken and its old entries are kept.
   */
  minShrinkRatio?: number;
  /**
   * The user's key for a feed that needs one (FeedSource.auth), read on every
   * run so a key added or removed takes effect at once. Main process only.
   */
  keys?: (name: FeedKeyName) => string | undefined;
}

export interface FeedRunResult {
  sourceId: string;
  /** `needs_key`: left out until the user adds the key it needs; not an error. */
  status: 'updated' | 'not_modified' | 'skipped' | 'needs_key' | 'failed';
  /** Entries this source now contributes. */
  entries: number;
  added?: number;
  removed?: number;
  dropped?: Partial<Record<DropReason, number>>;
  error?: string;
}

export interface FeedStatus {
  sourceId: string;
  name: string;
  list: FeedList;
  entries: number;
  fetchedAt?: number;
  lastError?: string;
  /** Off until the user adds the key it needs. Its stored entries still count. */
  needsKey?: boolean;
  /** No successful fetch for three intervals. Never set while the feed needs a key. */
  stale: boolean;
  nextDueAt: number;
}

const FEED_LISTS: readonly FeedList[] = ['known_bad_sha256', 'known_bad_domains', 'known_bad_ips'];
const ID_RE = /^[a-z0-9][a-z0-9-]{0,63}$/;

/**
 * Keeps the known-bad lists current. Each source's entries are kept
 * separately, validated, and combined into its list, so one broken feed never
 * empties a list another feed also fills. Feeds can only write the three
 * known_bad_* lists; the user's own blocked-hash list is never touched.
 *
 * Nothing here runs on the inline path: the app calls `run()` on a timer, and
 * the engine sees the new lists on its next lookup.
 */
export class FeedImporter {
  private readonly sources: FeedSource[];
  private readonly fetch: FetchLike;
  private readonly now: () => number;
  /** The run in progress, so a run asked for meanwhile joins it instead of fetching twice. */
  private running: Promise<FeedRunResult[]> | undefined;
  private readonly opts: Required<
    Pick<FeedImporterOptions, 'timeoutMs' | 'maxBytes' | 'maxEntries' | 'minShrinkRatio'>
  >;

  constructor(
    sources: readonly FeedSource[],
    private readonly lists: ListStore,
    private readonly state: FeedStateStore,
    private readonly options: FeedImporterOptions = {},
  ) {
    const seen = new Set<string>();
    for (const s of sources) {
      if (!ID_RE.test(s.id))
        throw new Error(`feed id "${s.id}" must be lowercase letters, digits and dashes`);
      if (seen.has(s.id)) throw new Error(`feed id "${s.id}" is used twice`);
      seen.add(s.id);
      if (!FEED_LISTS.includes(s.list))
        throw new Error(`feed ${s.id}: feeds may only fill ${FEED_LISTS.join(', ')}`);
      if (!/^https:\/\//.test(s.url)) throw new Error(`feed ${s.id}: only https URLs are allowed`);
      if (!(s.intervalHours > 0)) throw new Error(`feed ${s.id}: intervalHours must be positive`);
    }
    this.sources = [...sources];
    const f = options.fetch ?? (globalThis.fetch as unknown as FetchLike | undefined);
    if (!f) throw new Error('no fetch available');
    this.fetch = f;
    this.now = options.now ?? Date.now;
    this.opts = {
      timeoutMs: options.timeoutMs ?? 60_000,
      maxBytes: options.maxBytes ?? 64 * 1024 * 1024,
      maxEntries: options.maxEntries ?? 1_000_000,
      minShrinkRatio: options.minShrinkRatio ?? 0.1,
    };
  }

  private dueAt(s: FeedSource): number {
    const st = this.state.get(s.id);
    const last = Math.max(st?.fetchedAt ?? 0, st?.lastAttemptAt ?? 0);
    if (!last) return 0;
    // After a failure, retry within the hour rather than waiting a full interval.
    const failed = st?.lastError !== undefined && (st.lastAttemptAt ?? 0) >= (st.fetchedAt ?? 0);
    const interval = s.intervalHours * 3_600_000;
    const wait = failed ? Math.min(3_600_000, interval) : interval;
    return last + wait;
  }

  /** The key a source needs, '' when it needs none, undefined when the user hasn't added it. */
  private keyFor(s: FeedSource): string | undefined {
    if (!s.auth) return '';
    return this.options.keys?.(s.auth.key) || undefined;
  }

  /**
   * Fetch every source that is due (or all of them with `force`), then rebuild
   * the affected lists. A source still waiting for its key is left out
   * entirely: its state and its entries in the list stay as they were.
   */
  run(opts: { force?: boolean } = {}): Promise<FeedRunResult[]> {
    this.running ??= this.runAll(opts).finally(() => (this.running = undefined));
    return this.running;
  }

  private async runAll(opts: { force?: boolean }): Promise<FeedRunResult[]> {
    const now = this.now();
    const results: FeedRunResult[] = [];
    const touched = new Set<FeedList>();
    for (const s of this.sources) {
      const key = this.keyFor(s);
      if (key === undefined) {
        results.push({
          sourceId: s.id,
          status: 'needs_key',
          entries: Object.keys(this.state.get(s.id)?.entries ?? {}).length,
        });
        continue;
      }
      if (!opts.force && this.dueAt(s) > now) {
        results.push({
          sourceId: s.id,
          status: 'skipped',
          entries: Object.keys(this.state.get(s.id)?.entries ?? {}).length,
        });
        continue;
      }
      const r = await this.fetchSource(s, key, now);
      results.push(r);
      if (r.status === 'updated') touched.add(s.list);
    }
    for (const list of touched) this.rebuild(list, now);
    return results;
  }

  /** Rebuild every feed list from stored state, e.g. after a source is removed from the config. */
  rebuildAll(): void {
    for (const list of FEED_LISTS) this.rebuild(list, this.now());
  }

  status(): FeedStatus[] {
    const now = this.now();
    return this.sources.map((s) => {
      const st = this.state.get(s.id);
      const needsKey = this.keyFor(s) === undefined;
      const out: FeedStatus = {
        sourceId: s.id,
        name: s.name,
        list: s.list,
        entries: Object.keys(st?.entries ?? {}).length,
        stale:
          !needsKey && (!st?.fetchedAt || now - st.fetchedAt > 3 * s.intervalHours * 3_600_000),
        nextDueAt: this.dueAt(s),
      };
      if (needsKey) out.needsKey = true;
      if (st?.fetchedAt !== undefined) out.fetchedAt = st.fetchedAt;
      // An error from before the key was removed (or before keys were needed) is no longer news.
      if (st?.lastError !== undefined && !needsKey) out.lastError = st.lastError;
      return out;
    });
  }

  private rebuild(list: FeedList, now: number): void {
    const union = new Set<string>();
    for (const s of this.sources) {
      if (s.list !== list) continue;
      for (const e of Object.keys(this.state.get(s.id)?.entries ?? {})) union.add(e);
    }
    this.lists.replace(list, union, { source: 'feeds', updatedAt: now });
  }

  private async fetchSource(s: FeedSource, key: string, now: number): Promise<FeedRunResult> {
    const prev: FeedState = this.state.get(s.id) ?? { sourceId: s.id, entries: {} };
    const fail = (error: string): FeedRunResult => {
      this.state.put({ ...prev, lastAttemptAt: now, lastError: error });
      return { sourceId: s.id, status: 'failed', entries: Object.keys(prev.entries).length, error };
    };

    const headers: Record<string, string> = { ...(s.headers ?? {}) };
    if (s.auth && key) headers[s.auth.header] = key;
    if (prev.etag) headers['If-None-Match'] = prev.etag;
    if (prev.lastModified) headers['If-Modified-Since'] = prev.lastModified;

    let text: string;
    let res: Awaited<ReturnType<FetchLike>>;
    try {
      res = await this.fetch(s.url, { headers, signal: AbortSignal.timeout(this.opts.timeoutMs) });
      if (res.status === 304) {
        const st: FeedState = { ...prev, fetchedAt: now, lastAttemptAt: now };
        delete st.lastError;
        this.state.put(st);
        return {
          sourceId: s.id,
          status: 'not_modified',
          entries: Object.keys(prev.entries).length,
        };
      }
      if (res.status !== 200) return fail(`HTTP ${res.status}`);
      const len = Number(res.headers.get('content-length') ?? '0');
      if (len > this.opts.maxBytes) return fail(`feed is larger than ${this.opts.maxBytes} bytes`);
      text = await res.text();
    } catch (err) {
      return fail(err instanceof Error ? err.message : String(err));
    }
    if (text.length > this.opts.maxBytes)
      return fail(`feed is larger than ${this.opts.maxBytes} bytes`);

    const { entries, dropped } = cleanEntries(s.list, parseFeed(text, s.format), this.options);
    if (entries.length > this.opts.maxEntries)
      return fail(`feed lists more than ${this.opts.maxEntries} entries`);

    const prevCount = Object.keys(prev.entries).length;
    if (
      s.retainDays === 0 &&
      prevCount >= 50 &&
      entries.length < prevCount * this.opts.minShrinkRatio
    ) {
      return fail(
        `feed shrank from ${prevCount} to ${entries.length} entries; keeping the old list`,
      );
    }

    const next: Record<string, number> = {};
    if (s.retainDays > 0) {
      const cutoff = now - s.retainDays * 86_400_000;
      for (const [e, seen] of Object.entries(prev.entries)) if (seen >= cutoff) next[e] = seen;
    }
    for (const e of entries) next[e] = now;

    const added = Object.keys(next).filter((e) => !(e in prev.entries)).length;
    const removed = Object.keys(prev.entries).filter((e) => !(e in next)).length;
    const st: FeedState = { sourceId: s.id, entries: next, fetchedAt: now, lastAttemptAt: now };
    const etag = res.headers.get('etag');
    const lastModified = res.headers.get('last-modified');
    if (etag) st.etag = etag;
    if (lastModified) st.lastModified = lastModified;
    this.state.put(st);
    return {
      sourceId: s.id,
      status: 'updated',
      entries: Object.keys(next).length,
      added,
      removed,
      dropped,
    };
  }
}
