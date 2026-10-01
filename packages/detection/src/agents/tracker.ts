import type { AgentIdentity, AgentTag, ProcessRef, SensorEvent } from '@vigil/core';
import { VIGIL_CONNECTOR, VIGIL_SELF } from './catalog.js';
import type { AgentProc, CompiledAgentMatcher } from './match.js';
import type { PsRow } from './ps-table.js';
import { sessionId } from './session-id.js';

/**
 * Which processes run under a watched AI agent.
 *
 * The tracker keeps a bounded map of the processes it has seen launch (and
 * the ones `ps` listed at startup) and tags each event before rules run: an
 * agent's own program starts a session at depth 0, and everything it starts
 * inherits the tag one level deeper. Rules then read `process.agent` like
 * any other field, so replay and preview see exactly what the engine saw.
 *
 * Sensors miss some links (a subshell that forks without exec, a process
 * that started before Vigil). Those show up as holes: the event stays
 * untagged and `onMiss` asks the app to look again with `ps`.
 */

export interface SessionStart {
  /** The session id: 16 hex chars, see session-id.ts. */
  id: string;
  agentId: string;
  rootPid: number;
  rootPath: string;
  startedAt: number;
  /** The enclosing agent's session, when one agent started another. */
  parentSession?: string;
  /** True when the root was found by `ps` rather than seen launching. */
  seeded: boolean;
}

export interface TrackerOptions {
  /** The current identities. Called on every launch, so it should be cached. */
  matcher: () => CompiledAgentMatcher;
  /** Vigil's own process: its tree is tagged `vigil-self`, whatever it runs. */
  self?: { pid: number; path: string; startedAt?: number };
  /** Processes remembered at once (least recently seen go first). Default 8192. */
  maxNodes?: number;
  /** A new agent session (once per session id). */
  onSession?(s: SessionStart): void;
  /** A process or parent Vigil has not seen: a hint to read `ps` again. */
  onMiss?(ppid: number): void;
  /** An unknown program that runs shell commands the way agents do. */
  onCandidate?(c: { pid: number; path: string; shellChildren: number }): void;
}

const MAX_NODES = 8192;
/** Matches the AgentTag schema. */
const MAX_DEPTH = 64;
const MAX_ANCESTORS = 4;
const MAX_NAME = 255;
/** Command lines kept on a node, only for programs whose arguments can decide a match. */
const MAX_KEPT_ARGS = 1024;
/** ps reports start times in whole seconds; a launch event is within that of it. */
const SAME_START_MS = 2000;
/** Session ids already reported, so a retag does not report them again. */
const MAX_ANNOUNCED = 4096;
/** Connector processes Vigil has started and not yet stopped. */
const MAX_CONNECTORS = 64;

const CANDIDATE_SHELLS = 20;
const CANDIDATE_WINDOW_MS = 10 * 60_000;
const MAX_WINDOWS = 512;
const COMMAND_SHELLS = new Set(['sh', 'bash', 'zsh']);
/** Programs that run shell commands all day for a person: terminals, multiplexers, build tools, runtimes. */
const NEVER_CANDIDATES = new Set([
  'Terminal',
  'iTerm2',
  'ghostty',
  'wezterm-gui',
  'alacritty',
  'kitty',
  'stable', // Warp
  'tmux',
  'screen',
  'sshd',
  'sshd-session',
  'login',
  'sudo',
  'launchd',
  'make',
  'gmake',
  'ninja',
  'cmake',
  'xcodebuild',
  'npm',
  'pnpm',
  'yarn',
  'bun',
  'node',
  'python3',
  'ruby',
  'cargo',
  'go',
  'swift',
  'sh',
  'bash',
  'zsh',
  'dash',
  'ksh',
  'fish',
  'tcsh',
  'csh',
]);
/** Script runners: which script they run is in the arguments, so keep those for a later retag. */
const INTERPRETERS = new Set([
  'node',
  'bun',
  'deno',
  'python',
  'python3',
  'ruby',
  'perl',
  'java',
  'npx',
  'uv',
  'uvx',
]);

interface Node {
  pid: number;
  ppid: number | undefined;
  path: string;
  name: string;
  /** Only when they can decide a match; see `keepArgs`. */
  args?: string[];
  teamId?: string;
  signingId?: string;
  /** Launch time; with the pid it names a session. */
  startedAt: number;
  seeded: boolean;
  /** Program names of the parent, grandparent and so on, nearest first. */
  ancestors?: string[];
  /** The parent's tag when last known, used once the parent itself is forgotten. */
  parentTag?: AgentTag | undefined;
  /** This process was that agent before it exec'd into something else. */
  wasAgent?: string;
  /** Its program matches an identity (any status), so it is never a candidate. */
  known?: boolean;
  tag?: AgentTag | undefined;
}

interface ShellWindow {
  path: string;
  times: number[];
  fired: boolean;
}

function basename(p: string): string {
  const i = p.lastIndexOf('/');
  return (i === -1 ? p : p.slice(i + 1)).slice(0, MAX_NAME);
}

function childOf(t: AgentTag | undefined): AgentTag | undefined {
  return t && { id: t.id, session: t.session, depth: Math.min(t.depth + 1, MAX_DEPTH) };
}

function sameTag(a: AgentTag | undefined, b: AgentTag | undefined): boolean {
  return a === b || (!!a && !!b && a.id === b.id && a.session === b.session && a.depth === b.depth);
}

/** `sh -c`, `zsh -lc` and the like: how agents run a command. */
function isShellCommand(name: string, args: readonly string[] | undefined): boolean {
  if (!COMMAND_SHELLS.has(name) || !args) return false;
  for (let i = 1; i < args.length && i < 4; i++) {
    if (/^-[A-Za-z]*c[A-Za-z]*$/.test(args[i]!)) return true;
  }
  return false;
}

export class AgentTracker {
  private readonly nodes = new Map<number, Node>();
  private readonly self: Node | undefined;
  private selfAnnounced = false;
  private readonly maxNodes: number;
  private readonly windows = new Map<number, ShellWindow>();
  private readonly announced = new Set<string>();
  /** Pids of the connectors Vigil started: their trees are not Vigil's own. */
  private readonly connectors = new Set<number>();

  constructor(private readonly opts: TrackerOptions) {
    this.maxNodes = opts.maxNodes ?? MAX_NODES;
    if (opts.self) {
      const startedAt = opts.self.startedAt ?? Date.now();
      this.self = {
        pid: opts.self.pid,
        ppid: undefined,
        path: opts.self.path,
        name: basename(opts.self.path),
        startedAt,
        seeded: false,
        tag: { id: VIGIL_SELF, session: sessionId(VIGIL_SELF, opts.self.pid, startedAt), depth: 0 },
      };
    }
  }

  /**
   * Learn from the event and return it with `process.ancestors` and
   * `process.agent` filled in. The same object comes back when there is
   * nothing to add.
   */
  observe<E extends SensorEvent>(e: E): E {
    this.announceSelf();
    const ev = e as SensorEvent;
    if (ev.kind === 'agent.tool_request') return e; // a request, not a process
    if (ev.kind === 'process.exec') return this.exec(ev) as E;
    const p = 'process' in ev ? ev.process : undefined;
    if (!p || p.pid <= 0) return e;
    const n = this.get(p.pid);
    if (n && n.path === p.path) return this.withTree(e, n.tag, n.ancestors);
    if (ev.kind === 'santa.decision' && ev.target === 'execution') {
      // A blocked launch never ran, so it has no node; its parent says who tried.
      const parent = p.ppid !== undefined && p.ppid > 0 ? this.get(p.ppid) : undefined;
      if (parent) {
        const anc = [parent.name, ...(parent.ancestors ?? [])].slice(0, MAX_ANCESTORS);
        return this.withTree(e, childOf(parent.tag), anc);
      }
    }
    if (p.pid > 1) this.opts.onMiss?.(p.pid);
    return e;
  }

  /** Add processes listed by `ps` (those running before Vigil, or missed), then retag. */
  seed(rows: PsRow[]): void {
    this.announceSelf();
    const m = this.opts.matcher();
    const added: Node[] = [];
    for (const r of rows) {
      if (r.pid <= 0 || r.pid === this.self?.pid) continue;
      const prev = this.nodes.get(r.pid);
      // Known from its launch, which says more than ps does. A new parent with the
      // same program and start time is the same process, handed to launchd when its
      // parent exited (`nohup … &`): it keeps its lineage.
      const reparented =
        prev !== undefined &&
        prev.path === r.path &&
        Math.abs(prev.startedAt - r.startedAt) < SAME_START_MS;
      if (prev && (prev.ppid === r.ppid || reparented)) {
        // A new path means an exec Vigil missed.
        if (prev.path !== r.path) this.setProgram(prev, { path: r.path, args: r.args }, m);
        continue;
      }
      const n: Node = {
        pid: r.pid,
        ppid: r.ppid,
        path: r.path,
        name: basename(r.path),
        startedAt: r.startedAt,
        seeded: true,
      };
      this.setProgram(n, { path: r.path, args: r.args }, m);
      this.insert(n);
      added.push(n);
    }
    for (const n of added) this.setAncestors(n);
    this.retag();
  }

  /**
   * Recompute every tag from the current identities, parents first, e.g.
   * after the user adds an agent or turns watch off. Memoised; a chain is
   * followed at most 64 levels up.
   */
  retag(): void {
    this.announceSelf();
    const m = this.opts.matcher();
    const done = new Set<Node>();
    const visiting = new Set<Node>();
    const visit = (n: Node, hops: number): AgentTag | undefined => {
      if (n === this.self || done.has(n)) return n.tag;
      const parent = n.ppid !== undefined && n.ppid > 0 ? this.peek(n.ppid) : undefined;
      let inherited: AgentTag | undefined;
      if (parent && parent !== n && !visiting.has(parent) && hops < MAX_DEPTH) {
        visiting.add(n);
        inherited = visit(parent, hops + 1);
        visiting.delete(n);
        n.parentTag = inherited;
      } else {
        // The parent is gone (or the chain loops): trust what it was, while that agent is still watched.
        inherited = this.stillWatched(n.parentTag, m);
      }
      const identity = this.identityOf(n, m);
      n.known = identity !== undefined;
      const tag = this.resolve(n, identity, childOf(inherited));
      if (!sameTag(tag, n.tag)) n.tag = tag;
      done.add(n);
      return n.tag;
    };
    for (const n of this.nodes.values()) visit(n, 0);
  }

  /** What Vigil knows about a running process, for attributing a hook's request. */
  lookup(pid: number, path?: string): { path: string; tag?: AgentTag } | undefined {
    const n = this.get(pid);
    if (!n || (path !== undefined && n.path !== path)) return undefined;
    return n.tag ? { path: n.path, tag: n.tag } : { path: n.path };
  }

  /**
   * Vigil started a connector (a user's MCP server) as `pid`. Its tree is
   * tagged `vigil-connector` from here on, in a session of its own, so agent
   * rules watch it and nothing treats it as Vigil. Call before the launch
   * event can arrive when possible; a process already seen is retagged.
   */
  connectorStarted(pid: number): void {
    if (pid <= 1 || pid === this.self?.pid) return;
    this.connectors.delete(pid);
    this.connectors.add(pid);
    if (this.connectors.size > MAX_CONNECTORS) {
      this.connectors.delete(this.connectors.values().next().value!);
    }
    if (this.nodes.has(pid)) this.retag();
  }

  /**
   * The connector was closed. A process Vigil already tagged keeps its tag;
   * a new process that reuses the pid later is not a connector.
   */
  connectorStopped(pid: number): void {
    this.connectors.delete(pid);
  }

  size(): number {
    return this.nodes.size + (this.self ? 1 : 0);
  }

  // ---------------------------------------------------------------- internals

  private exec(e: Extract<SensorEvent, { kind: 'process.exec' }>): SensorEvent {
    const p = e.process;
    if (p.pid <= 0) return e;
    if (this.self && p.pid === this.self.pid) return this.withTree(e, this.self.tag, undefined);
    const m = this.opts.matcher();
    const ppid = p.ppid;
    const parent = ppid !== undefined && ppid > 0 && ppid !== p.pid ? this.get(ppid) : undefined;
    if (!parent && ppid !== undefined && ppid > 1) this.opts.onMiss?.(ppid);
    const identity = m.match(p);
    const prev = this.nodes.get(p.pid);

    let n: Node;
    if (prev && ppid !== undefined && prev.ppid === ppid) {
      // The same process running a new program (a shell's exec, a wrapper script).
      // It keeps its tag unless the new program is itself an agent.
      n = prev;
      if (n.tag && n.tag.depth === 0 && n.tag.id !== VIGIL_SELF && n.tag.id !== VIGIL_CONNECTOR)
        n.wasAgent = n.tag.id;
      this.setProgram(n, p, m);
      n.seeded = false;
      n.known = identity !== undefined;
      this.insert(n);
      const tag = this.resolve(n, identity, n.tag);
      if (!sameTag(tag, n.tag)) n.tag = tag;
    } else {
      // A new process, or a reused pid (its parent differs): start over.
      n = {
        pid: p.pid,
        ppid,
        path: p.path,
        name: basename(p.path),
        startedAt: p.startTime ?? e.ts,
        seeded: false,
        known: identity !== undefined,
      };
      this.setProgram(n, p, m);
      this.insert(n);
      this.setAncestors(n);
      n.parentTag = parent?.tag;
      n.tag = this.resolve(n, identity, childOf(parent?.tag));
    }

    if (parent && this.opts.onCandidate && isShellCommand(n.name, p.args)) {
      this.countShell(parent, e.ts);
    }
    return this.withTree(e, n.tag, n.ancestors);
  }

  /**
   * The tag a process gets from its program and `base`, the tag it carries
   * otherwise (its parent's, one level down). A watched agent's program
   * starts a session unless it is already that agent's (an app's helpers).
   */
  private resolve(
    n: Node,
    identity: AgentIdentity | undefined,
    base: AgentTag | undefined,
  ): AgentTag | undefined {
    // A connector Vigil started runs the user's program: a session of its own.
    // Once tagged it stays a connector, even after Vigil stops tracking the pid.
    if (base?.id === VIGIL_SELF && n.tag?.id === VIGIL_CONNECTOR && n.tag.depth === 0) return n.tag;
    if (base?.id === VIGIL_SELF && base.depth === 1 && this.connectors.has(n.pid)) {
      const session = sessionId(VIGIL_CONNECTOR, n.pid, n.startedAt);
      if (n.tag?.depth === 0 && n.tag.session === session) return n.tag;
      this.announce({
        id: session,
        agentId: VIGIL_CONNECTOR,
        rootPid: n.pid,
        rootPath: n.path,
        startedAt: n.startedAt,
        seeded: n.seeded,
        parentSession: base.session,
      });
      return { id: VIGIL_CONNECTOR, session, depth: 0 };
    }
    // Vigil's own tree stays Vigil's: the claude and codex it runs are its helpers.
    if (base?.id === VIGIL_SELF) return base;
    // A connector's tree stays the connector's, whatever it runs.
    if (base?.id === VIGIL_CONNECTOR) return base;
    if (!identity?.watch || identity.status !== 'active' || identity.id === base?.id) return base;
    const session = sessionId(identity.id, n.pid, n.startedAt);
    if (n.tag?.depth === 0 && n.tag.session === session) return n.tag;
    const s: SessionStart = {
      id: session,
      agentId: identity.id,
      rootPid: n.pid,
      rootPath: n.path,
      startedAt: n.startedAt,
      seeded: n.seeded,
    };
    if (base) s.parentSession = base.session;
    this.announce(s);
    return { id: identity.id, session, depth: 0 };
  }

  private identityOf(n: Node, m: CompiledAgentMatcher): AgentIdentity | undefined {
    const proc: AgentProc = {
      path: n.path,
      args: n.args,
      teamId: n.teamId,
      signingId: n.signingId,
    };
    return m.match(proc) ?? (n.wasAgent !== undefined ? m.byId(n.wasAgent) : undefined);
  }

  private stillWatched(t: AgentTag | undefined, m: CompiledAgentMatcher): AgentTag | undefined {
    if (!t || t.id === VIGIL_SELF || t.id === VIGIL_CONNECTOR) return t;
    return m.byId(t.id)?.watch ? t : undefined;
  }

  private setProgram(n: Node, p: AgentProc, m: CompiledAgentMatcher): void {
    n.path = p.path;
    n.name = basename(p.path);
    if (p.teamId !== undefined) n.teamId = p.teamId;
    else delete n.teamId;
    if (p.signingId !== undefined) n.signingId = p.signingId;
    else delete n.signingId;
    const keep = p.args?.length && (INTERPRETERS.has(n.name) || m.wantsArgs(p));
    if (keep) {
      const joined = p.args!.join(' ');
      n.args = joined.length > MAX_KEPT_ARGS ? [joined.slice(0, MAX_KEPT_ARGS)] : [joined];
    } else {
      delete n.args;
    }
  }

  private setAncestors(n: Node): void {
    const out: string[] = [];
    const seen: number[] = [n.pid];
    let pid = n.ppid;
    while (out.length < MAX_ANCESTORS && pid !== undefined && pid > 0 && !seen.includes(pid)) {
      const a = this.peek(pid);
      if (!a) break;
      out.push(a.name);
      seen.push(pid);
      pid = a.ppid;
    }
    if (out.length) n.ancestors = out;
    else delete n.ancestors;
  }

  /** Count `sh -c` children of a program no identity knows; 20 in 10 minutes makes it a candidate. */
  private countShell(parent: Node, ts: number): void {
    if (parent.tag || parent.known || parent === this.self) return;
    if (NEVER_CANDIDATES.has(parent.name)) return;
    let w = this.windows.get(parent.pid);
    if (w) this.windows.delete(parent.pid);
    if (!w || w.path !== parent.path) w = { path: parent.path, times: [], fired: false };
    this.windows.set(parent.pid, w);
    if (this.windows.size > MAX_WINDOWS) this.windows.delete(this.windows.keys().next().value!);
    if (w.fired) return;
    w.times.push(ts);
    while (w.times.length > 0 && ts - w.times[0]! > CANDIDATE_WINDOW_MS) w.times.shift();
    if (w.times.length >= CANDIDATE_SHELLS) {
      w.fired = true;
      this.opts.onCandidate?.({
        pid: parent.pid,
        path: parent.path,
        shellChildren: w.times.length,
      });
      w.times = [];
    }
  }

  private withTree<E extends SensorEvent>(
    e: E,
    tag: AgentTag | undefined,
    ancestors: string[] | undefined,
  ): E {
    const p = (e as { process?: ProcessRef }).process;
    if (!p || (p.agent === tag && p.ancestors === ancestors)) return e;
    const process: ProcessRef = { ...p };
    if (ancestors) process.ancestors = ancestors;
    else delete process.ancestors;
    if (tag) process.agent = tag;
    else delete process.agent;
    return { ...e, process } as E;
  }

  private announce(s: SessionStart): void {
    if (this.announced.has(s.id)) return;
    this.announced.add(s.id);
    if (this.announced.size > MAX_ANNOUNCED) {
      this.announced.delete(this.announced.values().next().value!);
    }
    this.opts.onSession?.(s);
  }

  /** Report Vigil's own session the first time the tracker is used (not from the constructor). */
  private announceSelf(): void {
    if (this.selfAnnounced || !this.self?.tag) return;
    this.selfAnnounced = true;
    this.announce({
      id: this.self.tag.session,
      agentId: VIGIL_SELF,
      rootPid: this.self.pid,
      rootPath: this.self.path,
      startedAt: this.self.startedAt,
      seeded: false,
    });
  }

  /** Look up and mark recently used. */
  private get(pid: number): Node | undefined {
    if (this.self && pid === this.self.pid) return this.self;
    const n = this.nodes.get(pid);
    if (n) {
      this.nodes.delete(pid);
      this.nodes.set(pid, n);
    }
    return n;
  }

  /** Look up without changing the eviction order. */
  private peek(pid: number): Node | undefined {
    if (this.self && pid === this.self.pid) return this.self;
    return this.nodes.get(pid);
  }

  private insert(n: Node): void {
    this.nodes.delete(n.pid);
    this.nodes.set(n.pid, n);
    if (this.nodes.size > this.maxNodes) this.nodes.delete(this.nodes.keys().next().value!);
  }
}
