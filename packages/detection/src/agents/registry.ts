import { AgentIdentity, AgentIdentityInput } from '@vigil/core';
import { assertUserOrigin, type UserOrigin } from '../origin.js';
import type { AgentStore } from '../state/stores.js';
import { AGENT_CATALOG, VIGIL_SELF, type CatalogEntry } from './catalog.js';
import { compileAgentMatchers, type CompiledAgentMatcher } from './match.js';

/** An agent as the Agents screen lists it. */
export type AgentRecord = AgentIdentity & {
  /** From Vigil's catalogue (it can be reset, not removed). */
  builtin: boolean;
  /** A built-in whose matchers the user changed. */
  edited: boolean;
  installPaths: string[];
  preflightHost?: string;
};

function basename(p: string): string {
  const i = p.lastIndexOf('/');
  return i === -1 ? p : p.slice(i + 1);
}

function identityOf(e: CatalogEntry): AgentIdentity {
  const { installPaths: _paths, preflightHost: _host, ...identity } = e;
  return identity;
}

/**
 * The agents Vigil watches: the built-in catalogue merged with what the user
 * added or changed and with Vigil's own suggestions.
 *
 * For a built-in, a stored record either holds only the user's watch and
 * status (stored origin `builtin`, so catalogue updates still apply) or the
 * user's own matchers too (stored origin `user`, which wins until reset).
 *
 * Every change needs a UserOrigin. The one exception is `suggest`, Vigil's
 * deterministic heuristic, and a suggestion tags nothing until accepted. No
 * AI path reaches this class.
 */
export class AgentRegistry {
  private readonly catalog: Map<string, CatalogEntry>;
  private compiled: CompiledAgentMatcher | undefined;
  private readonly listeners = new Set<() => void>();

  constructor(
    private readonly store: AgentStore,
    catalog: readonly CatalogEntry[] = AGENT_CATALOG,
    private readonly now: () => number = Date.now,
  ) {
    this.catalog = new Map(catalog.map((c) => [c.id, c]));
  }

  /** Built-ins in catalogue order, then the user's agents and suggestions, oldest first. */
  list(): AgentRecord[] {
    const stored = new Map(this.store.list().map((a) => [a.id, a]));
    const out: AgentRecord[] = [];
    for (const entry of this.catalog.values()) out.push(this.builtin(entry, stored.get(entry.id)));
    const own = [...stored.values()]
      .filter((a) => !this.catalog.has(a.id))
      .sort((a, b) => a.createdAt - b.createdAt || a.id.localeCompare(b.id));
    for (const a of own) out.push({ ...a, builtin: false, edited: false, installPaths: [] });
    return out;
  }

  get(id: string): AgentIdentity | undefined {
    const r = this.record(id);
    if (!r) return undefined;
    const { builtin: _b, edited: _e, installPaths: _i, preflightHost: _p, ...identity } = r;
    return identity;
  }

  /** For the tracker. Cached; rebuilt after any change. */
  matcher(): CompiledAgentMatcher {
    this.compiled ??= compileAgentMatchers(this.list());
    return this.compiled;
  }

  /**
   * Add an agent, or change one. A new id is the user's own and starts
   * active. For a built-in, this saves the user's copy of its matchers.
   */
  save(input: AgentIdentityInput, origin: UserOrigin): AgentIdentity {
    assertUserOrigin(origin);
    const v = AgentIdentityInput.parse(input);
    if (v.id === VIGIL_SELF) throw new Error(`"${VIGIL_SELF}" is reserved for Vigil itself.`);
    const at = this.now();
    const entry = this.catalog.get(v.id);
    const current = this.get(v.id);
    const next: AgentIdentity = {
      id: v.id,
      name: v.name,
      kind: v.kind,
      match: v.match,
      watch: v.watch,
      origin: entry ? 'user' : (current?.origin ?? 'user'),
      status: current?.status ?? 'active',
      createdAt: entry?.createdAt ?? current?.createdAt ?? at,
      updatedAt: at,
    };
    if (v.note !== undefined) next.note = v.note;
    this.store.put(AgentIdentity.parse(next));
    this.changed();
    return this.get(v.id)!;
  }

  setWatch(id: string, watch: boolean, origin: UserOrigin): void {
    assertUserOrigin(origin);
    this.write(id, { watch });
  }

  /**
   * Ignore an agent, or make it active again. Accepting a suggestion (even
   * one ignored before) makes it active with watch on: that is the point.
   */
  setStatus(id: string, status: 'active' | 'ignored', origin: UserOrigin): void {
    assertUserOrigin(origin);
    if (status !== 'active' && status !== 'ignored') throw new Error(`Unknown status "${status}".`);
    const current = this.get(id);
    if (!current) throw new Error(`No agent "${id}".`);
    const accepting =
      status === 'active' && current.origin === 'suggested' && current.status !== 'active';
    this.write(id, accepting ? { status, watch: true } : { status });
  }

  remove(id: string, origin: UserOrigin): void {
    assertUserOrigin(origin);
    if (this.catalog.has(id)) {
      throw new Error('A built-in agent cannot be removed: reset or ignore instead.');
    }
    if (!this.stored(id)) return;
    this.store.remove(id);
    this.changed();
  }

  /** Drop the user's copy of a built-in, watch and status included. */
  reset(id: string, origin: UserOrigin): void {
    assertUserOrigin(origin);
    if (!this.catalog.has(id)) throw new Error('Only a built-in agent can be reset.');
    if (!this.stored(id)) return;
    this.store.remove(id);
    this.changed();
  }

  /**
   * Record a program Vigil's heuristic thinks is an agent, as a suggestion
   * the user can accept or ignore. Refused when an agent already names that
   * path, or the program already matches one (ignored ones included, so
   * "not an agent" sticks).
   */
  suggest(c: { path: string; at: number }): AgentIdentity | undefined {
    if (c.path.length < 3 || c.path.length > 256) return undefined;
    const all = this.list();
    if (all.some((a) => a.match.some((m) => m.paths?.includes(c.path)))) return undefined;
    if (this.matcher().match({ path: c.path })) return undefined;

    const name = basename(c.path).slice(0, 60) || 'Unknown program';
    const slug =
      name
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, '-')
        .slice(0, 24)
        .replace(/^-+|-+$/g, '') || 'program';
    const taken = new Set(all.map((a) => a.id));
    let id = `suggested-${slug}`;
    for (let i = 2; taken.has(id); i++) id = `suggested-${slug}-${i}`;
    const parsed = AgentIdentity.safeParse({
      id,
      name,
      kind: c.path.includes('.app/') ? 'app' : 'cli',
      origin: 'suggested',
      status: 'suggested',
      watch: false,
      match: [{ paths: [c.path] }],
      note: 'It runs many shell commands, the way AI agents do.',
      createdAt: c.at,
      updatedAt: c.at,
    });
    if (!parsed.success) return undefined;
    this.store.put(parsed.data);
    this.changed();
    return parsed.data;
  }

  /** Called after every change. Returns a function that stops the calls. */
  onChange(cb: () => void): () => void {
    this.listeners.add(cb);
    return () => this.listeners.delete(cb);
  }

  // ---------------------------------------------------------------- internals

  private builtin(entry: CatalogEntry, stored: AgentIdentity | undefined): AgentRecord {
    const base = identityOf(entry);
    let identity = base;
    let edited = false;
    if (stored?.origin === 'user') {
      identity = { ...stored, origin: 'builtin' };
      edited = true;
    } else if (stored && stored.status !== 'suggested') {
      identity = {
        ...base,
        watch: stored.watch,
        status: stored.status,
        updatedAt: stored.updatedAt,
      };
    }
    const out: AgentRecord = {
      ...identity,
      builtin: true,
      edited,
      installPaths: [...entry.installPaths],
    };
    if (entry.preflightHost) out.preflightHost = entry.preflightHost;
    return out;
  }

  private record(id: string): AgentRecord | undefined {
    const entry = this.catalog.get(id);
    if (entry) return this.builtin(entry, this.stored(id));
    const s = this.stored(id);
    return s && { ...s, builtin: false, edited: false, installPaths: [] };
  }

  private stored(id: string): AgentIdentity | undefined {
    return this.store.list().find((a) => a.id === id);
  }

  /** Change watch or status, keeping everything else. A built-in gets a settings-only record. */
  private write(id: string, patch: Partial<Pick<AgentIdentity, 'watch' | 'status'>>): void {
    const entry = this.catalog.get(id);
    const base = this.stored(id) ?? (entry ? identityOf(entry) : undefined);
    if (!base) throw new Error(`No agent "${id}".`);
    this.store.put({ ...base, ...patch, updatedAt: this.now() });
    this.changed();
  }

  private changed(): void {
    this.compiled = undefined;
    for (const cb of [...this.listeners]) cb();
  }
}
