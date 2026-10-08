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
 * untagged and `onMiss` asks the app to look again with `ps`. A subshell
 * that forks without exec is gone by the time `ps` runs, so programs it
 * starts stay untagged until Santa's fork events are used.
 *
 * `ps` names a program by argv[0] (`-zsh`, `node`, `claude`), not by the
 * executable a sensor reports, so a path from `ps` is only a hint: it never
 * replaces what a sensor said, and the first sensor event for that process
 * replaces it.
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
  /**
   * When an agent root found by `ps` already had a session (before a restart,
   * say): its start time then, if within 2 s of `psStartedAt`. The session id
   * comes from the start time, so reusing it keeps the id.
   */
  priorStart?(agentId: string, rootPid: number, psStartedAt: number): number | undefined;
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
/** Agent roots kept apart from the LRU, so a quiet agent is not forgotten while others run. */
const MAX_KEPT_ROOTS = 256;
/** Tagged processes recently evicted, so a `ps` seed can give them back their tag. */
const MAX_GHOSTS = 1024;
/** After a suggestion, the same program may be suggested again this much later. */
const CANDIDATE_REARM_MS = 60 * 60_000;

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
  'XCBBuildService', // Xcode script phases
  'SWBBuildService',
  'npm',
  'pnpm',
  'yarn',
  'bun',
  'node',
  'python',
  'Python', // framework builds (Homebrew, python.org, the Command Line Tools)
  'perl',
  'java',
  'ruby',
  'cargo',
  'go',
  'swift',
  'xargs',
  'find',
  'vim',
  'nvim',
  'emacs',
  'Emacs',
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
  'Python',
  'ruby',
  'perl',
  'java',
  'npx',
  'uv',
  'uvx',
]);

/** A program name without its version: python3.12 and python3 are python, perl5.34 is perl. */
function unversioned(name: string): string {
  return name.replace(/[-\d.]+$/, '');
}

/**
 * A copy of `s` that does not share memory with a longer string. V8 keeps a
 * slice's whole parent alive, so a kept 1 KB of a 1 MB command line would
 * hold the megabyte. JSON keeps lone surrogates as they are.
 */
function ownString(s: string): string {
  return JSON.parse(JSON.stringify(s)) as string;
}

/** The arguments joined with spaces, at most `max` characters, without joining more than needed. */
function joinCapped(args: readonly string[], max: number): string {
  let out = '';
  for (let i = 0; i < args.length && out.length < max; i++) out += (i ? ' ' : '') + args[i];
  return out.length > max ? out.slice(0, max) : out;
}

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
  /** `path` came from `ps` (argv[0] or an unresolved link), not from a sensor. */
  psPath?: true;
  /** The launch event that last set its program, counted by `exec` (see `mark`). */
  seq?: number;
  /** Program names of the parent, grandparent and so on, nearest first (see mergeAncestors). */
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
  /** When it was last suggested; it may be suggested again after CANDIDATE_REARM_MS. */
  firedAt?: number;
}

function basename(p: string): string {
  const i = p.lastIndexOf('/');
  return (i === -1 ? p : p.slice(i + 1)).slice(0, MAX_NAME);
}

/**
 * The ancestry to report: the sensor hub's when it has one, since it saw the
 * launches itself; the tracker's when the hub had none (a parent that started
 * before Vigil, found with `ps`), or when the tracker's carries on further up
 * the same chain. Both are basenames, nearest first, at most four.
 */
function mergeAncestors(
  sensor: string[] | undefined,
  tracked: string[] | undefined,
): string[] | undefined {
  if (!sensor?.length) return tracked ?? sensor;
  if (!tracked || tracked.length <= sensor.length) return sensor;
  return sensor.every((a, i) => tracked[i] === a) ? tracked : sensor;
}

function childOf(t: AgentTag | undefined): AgentTag | undefined {
  return t && { ...t, depth: Math.min(t.depth + 1, MAX_DEPTH) };
}

function sameTag(a: AgentTag | undefined, b: AgentTag | undefined): boolean {
  return (
    a === b ||
    (!!a &&
      !!b &&
      a.id === b.id &&
      a.session === b.session &&
      a.depth === b.depth &&
      a.teamId === b.teamId &&
      a.signingId === b.signingId)
  );
}

/** The root's signature on a session's first tag, when its launch reported one. */
function rootTag(id: string, session: string, n: Node): AgentTag {
  const t: AgentTag = { id, session, depth: 0 };
  if (n.teamId !== undefined) t.teamId = n.teamId;
  if (n.signingId !== undefined) t.signingId = n.signingId;
  return t;
}

/**
 * The tag `n` hands its children (one level down once childOf adds it). The
 * root's signature goes on only while `n` itself has it: the root, or a copy
 * of the same signed program it started. A shell or any other program in
 * between, or a re-exec into something else, drops it, so a child's
 * `teamId` always means its parent is the signed agent program.
 */
function passOn(n: Node | undefined): AgentTag | undefined {
  const t = n?.tag;
  if (!t || (t.teamId === undefined && t.signingId === undefined)) return t;
  if (n.teamId === t.teamId && n.signingId === t.signingId) return t;
  const { teamId: _t, signingId: _s, ...rest } = t;
  return rest;
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
  /** Launch events seen; `mark` hands it out so a `ps` read can tell what it predates. */
  private execSeq = 0;
  /** Agent roots pushed out of `nodes` by other processes; looked up when `nodes` misses. */
  private readonly keptRoots = new Map<number, Node>();
  /** Tagged processes pushed out of `nodes`, for a `ps` seed to bring back. */
  private readonly ghosts = new Map<number, Node>();
  /** The start time each agent session was announced with, by root pid. */
  private readonly sessionStarts = new Map<number, { agentId: string; startedAt: number }>();
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
   * Learn from the event and return it with `process.agent` set and
   * `process.ancestors` filled in where the sensor hub left it out or knew
   * less (see mergeAncestors). The same object comes back when there is
   * nothing to add.
   */
  observe<E extends SensorEvent>(e: E): E {
    this.announceSelf();
    const ev = e as SensorEvent;
    // A request is not a process; an exit says nothing about the tree and has no path.
    if (ev.kind === 'agent.tool_request' || ev.kind === 'process.exit') return e;
    if (ev.kind === 'process.exec') return this.exec(ev) as E;
    const p = 'process' in ev ? ev.process : undefined;
    if (!p || p.pid <= 0) return e;
    const n = this.get(p.pid);
    if (
      n?.psPath &&
      // A blocked launch names the program it tried to run, not the one running.
      ev.kind !== 'santa.decision' &&
      n.path !== p.path &&
      p.path.startsWith('/') &&
      (p.ppid === undefined || p.ppid === n.ppid)
    ) {
      this.adopt(n, p);
    }
    if (n && n.path === p.path) return this.withTree(e, n.tag, n.ancestors);
    if (ev.kind === 'santa.decision' && ev.target === 'execution') {
      // A blocked launch never ran, so it has no node; its parent says who tried.
      const parent = p.ppid !== undefined && p.ppid > 0 ? this.get(p.ppid) : undefined;
      if (parent) {
        const anc = [parent.name, ...(parent.ancestors ?? [])].slice(0, MAX_ANCESTORS);
        return this.withTree(e, childOf(passOn(parent)), anc);
      }
    }
    // Reading ps again helps a process Vigil doesn't know, or a reused pid (a new
    // parent); it never changes what a sensor said, so a path alone isn't a miss.
    if (p.pid > 1 && (!n || (p.ppid !== undefined && p.ppid !== n.ppid))) this.opts.onMiss?.(p.pid);
    return e;
  }

  /**
   * Take this before reading `ps` and pass it to `seed`: a launch Vigil sees
   * while ps runs is newer than ps's row for that process.
   */
  mark(): number {
    return this.execSeq;
  }

  /**
   * Add processes listed by `ps` (those running before Vigil, or missed),
   * then retag. With `since` from `mark()`, a row for a process launched or
   * re-exec'd after that is older than what Vigil saw, and is skipped.
   */
  seed(rows: PsRow[], since?: number): void {
    this.announceSelf();
    const m = this.opts.matcher();
    const added: Node[] = [];
    for (const r of rows) {
      if (r.pid <= 0 || r.pid === this.self?.pid) continue;
      const prev = this.find(r.pid);
      if (prev && since !== undefined && (prev.seq ?? 0) > since) {
        this.touch(prev); // still running
        continue;
      }
      // Known from its launch, which says more than ps does. A new parent with the
      // same start time is the same process, handed to launchd when its parent
      // exited (`nohup … &`): it keeps its lineage. ps names argv[0], not the
      // executable, so the path cannot tell whether it is the same process.
      const reparented =
        prev !== undefined && Math.abs(prev.startedAt - r.startedAt) < SAME_START_MS;
      if (prev && (prev.ppid === r.ppid || reparented)) {
        // ps never overrides what a sensor said; it may update its own hint.
        if (prev.psPath && prev.path !== r.path)
          this.setProgram(prev, { path: ownString(r.path), args: r.args }, m);
        this.touch(prev); // still running, so not the first to forget
        continue;
      }
      const ghost = this.ghosts.get(r.pid);
      if (ghost && Math.abs(ghost.startedAt - r.startedAt) < SAME_START_MS) {
        // Forgotten while it ran (a long-lived server under an agent): it keeps what it was.
        this.ghosts.delete(r.pid);
        this.insert(ghost);
        continue;
      }
      const path = ownString(r.path);
      const n: Node = {
        pid: r.pid,
        ppid: r.ppid,
        path,
        name: basename(path),
        startedAt: r.startedAt,
        seeded: true,
        psPath: true,
      };
      this.setProgram(n, { path, args: r.args }, m);
      this.insert(n);
      added.push(n);
    }
    for (const n of added) this.setAncestors(n);
    // A filled hole lengthens the ancestry of everything below it, not only of the rows ps added.
    for (const n of this.nodes.values()) this.extendAncestors(n);
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
        visit(parent, hops + 1);
        visiting.delete(n);
        inherited = passOn(parent);
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
    for (const n of this.keptRoots.values()) visit(n, 0);
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
    if (this.find(pid)) this.retag();
  }

  /**
   * The connector was closed. A process Vigil already tagged keeps its tag;
   * a new process that reuses the pid later is not a connector.
   */
  connectorStopped(pid: number): void {
    this.connectors.delete(pid);
  }

  size(): number {
    return this.nodes.size + this.keptRoots.size + (this.self ? 1 : 0);
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
    const prev = this.find(p.pid);

    let n: Node;
    if (prev && ppid !== undefined && prev.ppid === ppid) {
      // The same process running a new program (a shell's exec, a wrapper script).
      // It keeps its tag unless the new program is itself an agent.
      n = prev;
      if (n.tag && n.tag.depth === 0 && n.tag.id !== VIGIL_SELF && n.tag.id !== VIGIL_CONNECTOR)
        n.wasAgent = n.tag.id;
      this.setProgram(n, p, m);
      delete n.psPath;
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
      n.parentTag = passOn(parent);
      n.tag = this.resolve(n, identity, childOf(n.parentTag));
    }

    // What the sensor hub knows of the chain is what its children will carry too.
    const ancestors = mergeAncestors(p.ancestors, n.ancestors);
    if (ancestors?.length) n.ancestors = ancestors;
    n.seq = ++this.execSeq;

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
      if (n.seeded) this.reuseStart(n, VIGIL_CONNECTOR);
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
    if (n.seeded) this.reuseStart(n, identity.id);
    const session = sessionId(identity.id, n.pid, n.startedAt);
    const tag = rootTag(identity.id, session, n);
    if (n.tag?.depth === 0 && n.tag.session === session) return sameTag(tag, n.tag) ? n.tag : tag;
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
    return tag;
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
    const keep = p.args?.length && (INTERPRETERS.has(unversioned(n.name)) || m.wantsArgs(p));
    if (keep) {
      n.args = [ownString(joinCapped(p.args!, MAX_KEPT_ARGS))];
    } else {
      delete n.args;
    }
  }

  /**
   * The first sensor event for a process `ps` listed names its real program
   * (ps gave argv[0]). Rare, so retagging when that changes its identity is cheap.
   */
  private adopt(n: Node, p: ProcessRef): void {
    const m = this.opts.matcher();
    const before = this.identityOf(n, m);
    // ps matched it by argv[0] (an npm Claude Code's process title, say): it stays that agent.
    if (before && n.tag?.depth === 0 && n.tag.id === before.id) n.wasAgent = before.id;
    const signed = [n.teamId, n.signingId];
    this.setProgram(n, { path: p.path, args: n.args, teamId: p.teamId, signingId: p.signingId }, m);
    delete n.psPath;
    // A changed signature changes what the tag hands down (see passOn) too.
    if (
      this.identityOf(n, m)?.id !== before?.id ||
      (n.tag && (signed[0] !== n.teamId || signed[1] !== n.signingId))
    )
      this.retag();
  }

  /**
   * A root `ps` found that already had a session (announced before it was
   * forgotten, or before Vigil restarted) takes that session's start time, so
   * its id stays the same. ps reports whole seconds, a launch event the
   * moment Santa logged it; they can fall in different seconds.
   */
  private reuseStart(n: Node, agentId: string): void {
    const known = this.sessionStarts.get(n.pid);
    const prior =
      known && known.agentId === agentId && Math.abs(known.startedAt - n.startedAt) < SAME_START_MS
        ? known.startedAt
        : this.opts.priorStart?.(agentId, n.pid, n.startedAt);
    if (prior !== undefined && Math.abs(prior - n.startedAt) < SAME_START_MS) n.startedAt = prior;
  }

  private setAncestors(n: Node): void {
    const out: string[] = [];
    const seen: number[] = [n.pid];
    let pid = n.ppid;
    let top: Node | undefined;
    while (out.length < MAX_ANCESTORS && pid !== undefined && pid > 0 && !seen.includes(pid)) {
      const a = this.peek(pid);
      if (!a) break;
      out.push(a.name);
      seen.push(pid);
      top = a;
      pid = a.ppid;
    }
    // The walk stopped below a parent Vigil no longer has (or never had): the
    // ancestry the last process found had when it launched (often from the
    // sensor hub) goes on top.
    const looped = pid !== undefined && seen.includes(pid);
    if (top?.ancestors && !looped)
      for (const a of top.ancestors) {
        if (out.length >= MAX_ANCESTORS) break;
        out.push(a);
      }
    if (out.length) n.ancestors = out;
    else delete n.ancestors;
  }

  /** Lengthen a node's ancestry after a seed filled a gap above it; never rewrite or shorten it. */
  private extendAncestors(n: Node): void {
    const old = n.ancestors;
    if (old && old.length >= MAX_ANCESTORS) return;
    this.setAncestors(n);
    const now = n.ancestors;
    if (now && now.length > (old?.length ?? 0) && (old ?? []).every((a, i) => now[i] === a)) return;
    if (old) n.ancestors = old;
    else delete n.ancestors;
  }

  /** Count `sh -c` children of a program no identity knows; 20 in 10 minutes makes it a candidate. */
  private countShell(parent: Node, ts: number): void {
    // A path from ps is argv[0] (`goose`), which no suggestion could match later.
    if (parent.tag || parent.known || parent === this.self || parent.psPath) return;
    if (NEVER_CANDIDATES.has(parent.name) || NEVER_CANDIDATES.has(unversioned(parent.name))) return;
    let w = this.windows.get(parent.pid);
    if (w) this.windows.delete(parent.pid);
    if (!w || w.path !== parent.path) w = { path: parent.path, times: [] };
    this.windows.set(parent.pid, w);
    if (this.windows.size > MAX_WINDOWS) this.windows.delete(this.windows.keys().next().value!);
    // The app may drop a suggestion (one a day at most), so it can come again later.
    if (w.firedAt !== undefined && ts - w.firedAt < CANDIDATE_REARM_MS) return;
    w.times.push(ts);
    while (w.times.length > 0 && ts - w.times[0]! > CANDIDATE_WINDOW_MS) w.times.shift();
    if (w.times.length >= CANDIDATE_SHELLS) {
      w.firedAt = ts;
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
    tracked: string[] | undefined,
  ): E {
    const p = (e as { process?: ProcessRef }).process;
    if (!p) return e;
    const ancestors = mergeAncestors(p.ancestors, tracked);
    if (p.agent === tag && p.ancestors === ancestors) return e;
    const process: ProcessRef = { ...p };
    if (ancestors) process.ancestors = ancestors;
    else delete process.ancestors;
    if (tag) process.agent = tag;
    else delete process.agent;
    return { ...e, process } as E;
  }

  private announce(s: SessionStart): void {
    if (s.agentId !== VIGIL_SELF) {
      this.sessionStarts.delete(s.rootPid);
      this.sessionStarts.set(s.rootPid, { agentId: s.agentId, startedAt: s.startedAt });
      if (this.sessionStarts.size > MAX_ANNOUNCED)
        this.sessionStarts.delete(this.sessionStarts.keys().next().value!);
    }
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
      return n;
    }
    const r = this.keptRoots.get(pid);
    if (r) {
      this.keptRoots.delete(pid);
      this.keptRoots.set(pid, r);
    }
    return r;
  }

  /** Look up without changing the eviction order. */
  private peek(pid: number): Node | undefined {
    if (this.self && pid === this.self.pid) return this.self;
    return this.find(pid);
  }

  private find(pid: number): Node | undefined {
    return this.nodes.get(pid) ?? this.keptRoots.get(pid);
  }

  /** Mark a known node recently used. */
  private touch(n: Node): void {
    if (this.nodes.get(n.pid) === n) {
      this.nodes.delete(n.pid);
      this.nodes.set(n.pid, n);
    } else if (this.keptRoots.get(n.pid) === n) {
      this.keptRoots.delete(n.pid);
      this.keptRoots.set(n.pid, n);
    }
  }

  private insert(n: Node): void {
    this.keptRoots.delete(n.pid);
    this.ghosts.delete(n.pid);
    this.nodes.delete(n.pid);
    this.nodes.set(n.pid, n);
    if (this.nodes.size > this.maxNodes) this.evict(this.nodes.keys().next().value!);
  }

  /**
   * Forget the least recently seen process. An agent root waiting for its
   * user sends nothing, so it moves to `keptRoots` instead: otherwise other
   * programs' launches would push it out and its next command would run
   * untagged. Other tagged processes leave a ghost a `ps` seed can restore.
   */
  private evict(pid: number): void {
    const n = this.nodes.get(pid)!;
    this.nodes.delete(pid);
    if (!n.tag || n.tag.id === VIGIL_SELF) return;
    if (n.tag.depth === 0) {
      this.keptRoots.set(pid, n);
      if (this.keptRoots.size > MAX_KEPT_ROOTS) this.dropKeptRoot();
      return;
    }
    this.ghosts.delete(pid);
    this.ghosts.set(pid, n);
    if (this.ghosts.size > MAX_GHOSTS) this.ghosts.delete(this.ghosts.keys().next().value!);
  }

  /** Over the cap: forget a nested root (one agent started by another) first, else the oldest. */
  private dropKeptRoot(): void {
    for (const [pid, n] of this.keptRoots) {
      if (n.parentTag) {
        this.keptRoots.delete(pid);
        return;
      }
    }
    this.keptRoots.delete(this.keptRoots.keys().next().value!);
  }
}
