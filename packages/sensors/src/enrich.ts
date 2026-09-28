// Fills in what a sensor could not say about a process from what another one
// already did. Santa's launch events carry the signature, the hash and the
// quarantine origin, but its file-access lines and osquery's connection rows
// name only a pid and a path. Rules that ask "is this program unsigned?" need
// the signature on every event, so the hub remembers each launch by pid (and
// each program's signature by path) and copies it onto later events.
//
// Nothing here is guessed: a pid is only trusted while the path matches, and
// a program seen only before Vigil started stays without a signature.

import type { SensorEvent } from '@vigil/core';
import type { ProcessRef } from './types.js';

const MAX_ENTRIES = 4096;

type Known = Pick<
  ProcessRef,
  'path' | 'signing' | 'teamId' | 'signingId' | 'sha256' | 'cdhash' | 'quarantine'
>;

function remember<V>(map: Map<string | number, V>, key: string | number, value: V): void {
  map.delete(key);
  map.set(key, value);
  if (map.size > MAX_ENTRIES) {
    // Maps iterate in insertion order, so this drops the least recently seen.
    const oldest = map.keys().next().value;
    if (oldest !== undefined) map.delete(oldest);
  }
}

function signatureOf(p: ProcessRef): Known {
  const out: Known = { path: p.path };
  if (p.signing !== undefined) out.signing = p.signing;
  if (p.teamId !== undefined) out.teamId = p.teamId;
  if (p.signingId !== undefined) out.signingId = p.signingId;
  if (p.sha256 !== undefined) out.sha256 = p.sha256;
  if (p.cdhash !== undefined) out.cdhash = p.cdhash;
  return out;
}

export class ProcessEnricher {
  private readonly byPid = new Map<string | number, Known>();
  private readonly byPath = new Map<string | number, Known>();

  /** Learn from the event, then return it with any missing signature filled in. */
  enrich(event: SensorEvent): SensorEvent {
    const p = 'process' in event ? event.process : undefined;
    if (!p) return event;
    if (event.kind === 'process.exit') {
      this.byPid.delete(p.pid);
      return event;
    }
    if (p.signing !== undefined) {
      this.learn(event, p);
      return event;
    }
    const known = this.lookup(p);
    if (!known) return event;
    const filled: ProcessRef = { ...p };
    for (const [k, v] of Object.entries(known) as [keyof Known, Known[keyof Known]][]) {
      if (k !== 'path' && v !== undefined && filled[k] === undefined)
        (filled as Record<string, unknown>)[k] = v;
    }
    if (!filled.path) filled.path = known.path;
    return { ...event, process: filled } as SensorEvent;
  }

  private learn(event: SensorEvent, p: ProcessRef): void {
    if (!p.path) return;
    const sig = signatureOf(p);
    // Only a launch says for certain which program a pid is running now.
    if (event.kind === 'process.exec' && p.pid > 0) {
      remember(this.byPid, p.pid, p.quarantine ? { ...sig, quarantine: p.quarantine } : sig);
    }
    // A path can be updated to a new build, so its hashes belong to the pid only.
    const { sha256: _sha, cdhash: _cd, ...program } = sig;
    remember(this.byPath, p.path, program);
  }

  private lookup(p: ProcessRef): Known | undefined {
    const byPid = p.pid > 0 ? this.byPid.get(p.pid) : undefined;
    // A reused pid runs a different program; the path gives that away.
    if (byPid && (!p.path || p.path === byPid.path)) return byPid;
    return p.path ? this.byPath.get(p.path) : undefined;
  }
}
