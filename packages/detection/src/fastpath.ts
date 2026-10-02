// Which blocking rules the root helper can run on its own, straight off the
// sensor stream, without waiting for the app:
//
//   app engine ── rules in block mode ──► fastPathRules() ──► helper engine
//                                          drops rules that need
//                                          what only the app has
//
// The app keeps running every rule either way and stays the one that raises
// alerts. A rule is left out when it depends on something the helper does
// not have: the "first seen" baseline (kept in the app's database), or a
// field only the app fills in (agent sessions, for example).

import { createHash } from 'node:crypto';
import type { RuleMode } from '@vigil/core';
import type { DetectionRule } from './types.js';

/**
 * Fields the app adds to events after they leave the helper. Rules reading
 * them stay app-only. Matched as prefixes, so "agent." covers "agent.name".
 */
export const APP_ONLY_FIELD_PREFIXES: readonly string[] = [];

export interface FastPathSet {
  /** The rules, each with mode set to block. */
  rules: DetectionRule[];
  /** Indicator lists the rules look things up in. */
  lists: string[];
}

export function fastPathRules(
  rules: Array<DetectionRule & { effectiveMode: RuleMode }>,
  appOnlyFields: readonly string[] = APP_ONLY_FIELD_PREFIXES,
): FastPathSet {
  const out: DetectionRule[] = [];
  const lists = new Set<string>();
  for (const { effectiveMode, ...rule } of rules) {
    if (effectiveMode !== 'block') continue;
    const seen = scan(rule);
    if (seen.firstSeen) continue;
    if (seen.fields.some((f) => appOnlyFields.some((p) => f === p || f.startsWith(p)))) continue;
    for (const l of seen.lists) lists.add(l);
    out.push({ ...(rule as DetectionRule), mode: 'block' });
  }
  return { rules: out, lists: [...lists].sort() };
}

interface Scan {
  firstSeen: boolean;
  lists: string[];
  fields: string[];
}

/** Every field, list and "first seen" a rule mentions, wherever in the rule it is. */
function scan(rule: object): Scan {
  const s: Scan = { firstSeen: false, lists: [], fields: [] };
  const walk = (v: unknown, key?: string): void => {
    if (typeof v === 'string') {
      if (key === 'field') s.fields.push(v);
      // Response templates: "{{process.pid}}", "{{remoteHost|remoteAddress}}".
      for (const m of v.matchAll(/\{\{([^}]+)\}\}/g)) s.fields.push(...m[1]!.split('|'));
      return;
    }
    if (Array.isArray(v)) {
      // Keys (threshold, dedupe, sequence) are lists of field paths.
      if (key === 'key') s.fields.push(...v.filter((x): x is string => typeof x === 'string'));
      for (const x of v) walk(x);
      return;
    }
    if (v && typeof v === 'object') {
      for (const [k, x] of Object.entries(v)) {
        if (k === 'firstSeen') s.firstSeen = true;
        if (k === 'inList' && x && typeof x === 'object') {
          const list = (x as { list?: unknown }).list;
          if (typeof list === 'string') s.lists.push(list);
        }
        walk(x, k);
      }
    }
  };
  walk(rule);
  return s;
}

/** A stable fingerprint of a list's contents, so the app only sends lists that changed. */
export function listDigest(entries: Iterable<string>): string {
  const sorted = [...new Set(entries)].sort();
  return createHash('sha256').update(sorted.join('\n')).digest('hex');
}
