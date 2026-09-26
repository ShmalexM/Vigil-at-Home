import type { DetectionEngine } from '../engine.js';
import type { EventHistory } from '../state/stores.js';
import type { DetectionEvent, DetectionEventKind } from '../types.js';
import type { RulePipeline } from './pipeline.js';

/**
 * A compact, redacted digest of recent activity for rule-proposal runs.
 * The AI never sees raw events or command lines: only aggregates, program
 * paths with the home folder replaced by ~, and domains without URLs.
 */
export interface TelemetrySummary {
  window: { from: string; to: string; events: number };
  countsByKind: Partial<Record<DetectionEventKind, number>>;
  topTalkers: Array<{
    program: string;
    signing: string;
    connections: number;
    distinctDestinations: number;
    sampleDomains: string[];
  }>;
  untrustedPrograms: Array<{
    program: string;
    signing: string;
    launches: number;
    fromInternet: boolean;
  }>;
  newLoginItems: Array<{ item: string; program: string }>;
  listeners: Array<{ program: string; port?: number; address?: string }>;
  newExtensions: Array<{ browser: string; id: string; name?: string; permissions: string[] }>;
  rules: Array<{
    id: string;
    name: string;
    mode: string;
    fired: number;
    markedSafe: number;
    confirmed: number;
  }>;
  recentProposals: Array<{ id: string; ruleId: string; status: string; userNote?: string }>;
  lists: Array<{ name: string; size: number }>;
}

const HOME = /^\/Users\/[^/]+/;
const EMAIL = /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g;

export function redactPath(p: string | undefined): string {
  if (!p) return 'unknown';
  return p.replace(HOME, '~').replace(EMAIL, '<email>');
}

function top<T>(m: Map<string, T>, n: number, score: (t: T) => number): Array<[string, T]> {
  return [...m.entries()].sort((a, b) => score(b[1]) - score(a[1])).slice(0, n);
}

export function summarizeTelemetry(opts: {
  history: EventHistory;
  engine: DetectionEngine;
  pipeline?: RulePipeline;
  from: number;
  to: number;
}): TelemetrySummary {
  const counts: Partial<Record<DetectionEventKind, number>> = {};
  const talkers = new Map<
    string,
    { signing: string; connections: number; dests: Set<string>; domains: Set<string> }
  >();
  const untrusted = new Map<string, { signing: string; launches: number; fromInternet: boolean }>();
  const loginItems = new Map<string, { program: string }>();
  const listeners = new Map<string, { program: string; port?: number; address?: string }>();
  const exts = new Map<
    string,
    { browser: string; id: string; name?: string; permissions: string[] }
  >();
  let events = 0;

  const add = (e: DetectionEvent) => {
    events++;
    counts[e.kind] = (counts[e.kind] ?? 0) + 1;
    const proc = 'process' in e ? e.process : undefined;
    const prog = redactPath(proc?.path);
    const signing = proc?.signing ?? 'unknown';
    switch (e.kind) {
      case 'network.connection': {
        if (e.direction !== 'outbound') break;
        let t = talkers.get(prog);
        if (!t) {
          t = { signing, connections: 0, dests: new Set(), domains: new Set() };
          talkers.set(prog, t);
        }
        t.connections++;
        const dest = e.remoteHost ?? e.remoteAddress;
        if (t.dests.size < 1000) t.dests.add(dest);
        if (e.remoteHost && t.domains.size < 5) t.domains.add(e.remoteHost);
        break;
      }
      case 'process.exec': {
        if (signing === 'unsigned' || signing === 'adhoc' || signing === 'invalid') {
          const u = untrusted.get(prog) ?? { signing, launches: 0, fromInternet: false };
          u.launches++;
          u.fromInternet ||= !!(e.process as { quarantine?: unknown }).quarantine;
          untrusted.set(prog, u);
        }
        break;
      }
      case 'persistence': {
        if (e.change !== 'removed') {
          loginItems.set(redactPath(e.path), { program: redactPath(e.program) });
        }
        break;
      }
      case 'network.listen': {
        listeners.set(`${prog}:${e.localPort}`, {
          program: prog,
          port: e.localPort,
          address: e.localAddress,
        });
        break;
      }
      case 'browser.extension': {
        if (e.change !== 'removed') {
          const x: { browser: string; id: string; name?: string; permissions: string[] } = {
            browser: e.browser,
            id: e.extensionId,
            permissions: e.permissions ?? [],
          };
          if (e.name) x.name = e.name;
          exts.set(`${e.browser}:${e.extensionId}`, x);
        }
        break;
      }
      default:
        break;
    }
  };
  for (const e of opts.history.range(opts.from, opts.to)) add(e);

  const since = opts.from;
  const rules = opts.engine.listRules().map((r) => {
    const vs = opts.engine.stores.ruleState.verdicts(r.id, since);
    return {
      id: r.id,
      name: r.name,
      mode: r.effectiveMode,
      fired: opts.engine.stores.ruleState.get(r.id)?.fired ?? 0,
      markedSafe: vs.filter((v) => v.verdict === 'benign').length,
      confirmed: vs.filter((v) => v.verdict === 'malicious').length,
    };
  });

  const recentProposals = (opts.pipeline?.list() ?? []).slice(0, 10).map((p) => {
    const r: TelemetrySummary['recentProposals'][number] = {
      id: p.id,
      ruleId: p.rule.id,
      status: p.status,
    };
    if (p.decisionNote !== undefined) r.userNote = p.decisionNote;
    return r;
  });

  return {
    window: {
      from: new Date(opts.from).toISOString(),
      to: new Date(opts.to).toISOString(),
      events,
    },
    countsByKind: counts,
    topTalkers: top(talkers, 15, (t) => t.connections).map(([program, t]) => ({
      program,
      signing: t.signing,
      connections: t.connections,
      distinctDestinations: t.dests.size,
      sampleDomains: [...t.domains],
    })),
    untrustedPrograms: top(untrusted, 20, (u) => u.launches).map(([program, u]) => ({
      program,
      ...u,
    })),
    newLoginItems: [...loginItems.entries()].slice(0, 20).map(([item, v]) => ({ item, ...v })),
    listeners: [...listeners.values()].slice(0, 20),
    newExtensions: [...exts.values()].slice(0, 20),
    rules,
    recentProposals,
    lists: opts.engine.stores.lists
      .names()
      .map((name) => ({ name, size: opts.engine.stores.lists.size(name) })),
  };
}
