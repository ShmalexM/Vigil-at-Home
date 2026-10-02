// Fills in what a sensor could not say about a process from what another one
// already did. Santa's launch events carry the signature, the hash and the
// quarantine origin, but its file-access lines and osquery's connection rows
// name only a pid and a path. Rules that ask "is this program unsigned?" need
// the signature on every event, so the hub remembers each launch by pid (and
// each program's signature by path) and copies it onto later events.
//
// Launches also build the process tree, so every event says who started the
// program and whether anything above it came from a download:
//
//   Safari ─► Installer.app (quarantined) ─► sh ─► curl
//   curl: parentPath /bin/sh, ancestors [sh, Installer, Safari],
//         downloadedAncestor { path: …/Installer.app/…, originUrl }
//
// Nothing here is guessed: a pid is only trusted while the path matches, and
// a program seen only before Vigil started stays without a signature until
// a signature lookup (signatureLookup, in the helper) answers for its path.

import type { SensorEvent, SigningStatus } from '@vigil/core';
import type { ProcessRef } from './types.js';

const MAX_ENTRIES = 4096;
const MAX_ANCESTORS = 4;

type Signature = Pick<
  ProcessRef,
  'path' | 'signing' | 'teamId' | 'signingId' | 'sha256' | 'cdhash' | 'quarantine'
>;

/** What a launch taught about one running pid. */
interface Known extends Signature {
  ppid?: number;
  parentPath?: string;
  ancestors?: string[];
  downloadedAncestor?: { path: string; originUrl?: string; signing?: SigningStatus };
}

/** A program's signature, as a lookup outside the sensors reports it. */
export interface SignatureInfo {
  signing: SigningStatus;
  teamId?: string;
  signingId?: string;
}

export interface ProcessEnricherOptions {
  /**
   * Called (at most once per path) for a program whose signature no sensor
   * reported, typically one that started before Vigil. Answer later with
   * `learnSignature`; the event in hand goes on without waiting.
   */
  onUnknownSignature?: (path: string) => void;
}

function remember<V>(map: Map<string | number, V>, key: string | number, value: V): void {
  map.delete(key);
  map.set(key, value);
  if (map.size > MAX_ENTRIES) {
    // Maps iterate in insertion order, so this drops the least recently seen.
    const oldest = map.keys().next().value;
    if (oldest !== undefined) map.delete(oldest);
  }
}

function basename(p: string): string {
  const i = p.lastIndexOf('/');
  return i === -1 ? p : p.slice(i + 1);
}

function signatureOf(p: ProcessRef): Signature {
  const out: Signature = { path: p.path };
  if (p.signing !== undefined) out.signing = p.signing;
  if (p.teamId !== undefined) out.teamId = p.teamId;
  if (p.signingId !== undefined) out.signingId = p.signingId;
  if (p.sha256 !== undefined) out.sha256 = p.sha256;
  if (p.cdhash !== undefined) out.cdhash = p.cdhash;
  return out;
}

const FILLED: (keyof Known)[] = [
  'signing',
  'teamId',
  'signingId',
  'sha256',
  'cdhash',
  'quarantine',
  'ppid',
  'parentPath',
  'ancestors',
  'downloadedAncestor',
];

export class ProcessEnricher {
  private readonly byPid = new Map<string | number, Known>();
  private readonly byPath = new Map<string | number, Signature>();
  private readonly asked = new Set<string>();

  constructor(private readonly opts: ProcessEnricherOptions = {}) {}

  /** Learn from the event, then return it with what is missing filled in. */
  enrich(event: SensorEvent): SensorEvent {
    const p = 'process' in event ? event.process : undefined;
    if (!p) return event;
    if (event.kind === 'process.exit') {
      this.byPid.delete(p.pid);
      return event;
    }
    if (event.kind === 'process.exec' || (event.kind === 'santa.decision' && p.signing)) {
      const known = this.learnLaunch(event.kind === 'process.exec', p);
      return this.fill(event, p, known);
    }
    if (p.signing !== undefined && p.path) remember(this.byPath, p.path, programOf(p));
    const known = this.lookup(p);
    if (!known && p.signing === undefined) this.ask(p.path);
    return known ? this.fill(event, p, known) : event;
  }

  /** A signature lookup's answer for a program no sensor described. */
  learnSignature(path: string, info: SignatureInfo): void {
    const sig: Signature = { path, signing: info.signing };
    if (info.teamId) sig.teamId = info.teamId;
    if (info.signingId) sig.signingId = info.signingId;
    if (!this.byPath.has(path)) remember(this.byPath, path, sig);
  }

  private ask(path: string): void {
    if (!path || !this.opts.onUnknownSignature || this.asked.has(path)) return;
    if (this.asked.size >= MAX_ENTRIES) this.asked.clear();
    this.asked.add(path);
    this.opts.onUnknownSignature(path);
  }

  /** Record a launch in the tree. Only a real launch says which program a pid runs now. */
  private learnLaunch(isExec: boolean, p: ProcessRef): Known {
    const known: Known = signatureOf(p);
    if (p.quarantine) known.quarantine = p.quarantine;
    const parent = p.ppid !== undefined && p.ppid > 0 ? this.byPid.get(p.ppid) : undefined;
    if (p.ppid !== undefined) known.ppid = p.ppid;
    const parentPath = p.parentPath ?? parent?.path;
    if (parentPath) {
      known.parentPath = parentPath;
      known.ancestors = [basename(parentPath), ...(parent?.ancestors ?? [])].slice(
        0,
        MAX_ANCESTORS,
      );
    }
    if (parent) {
      const downloaded = parent.quarantine
        ? {
            path: parent.path,
            ...(parent.quarantine.originUrl ? { originUrl: parent.quarantine.originUrl } : {}),
            ...(parent.signing ? { signing: parent.signing } : {}),
          }
        : parent.downloadedAncestor;
      if (downloaded) known.downloadedAncestor = downloaded;
    }
    if (isExec && p.pid > 0) remember(this.byPid, p.pid, known);
    if (p.path && p.signing !== undefined) remember(this.byPath, p.path, programOf(p));
    return known;
  }

  private fill(event: SensorEvent, p: ProcessRef, known: Known): SensorEvent {
    const filled: ProcessRef = { ...p };
    let changed = false;
    for (const k of FILLED) {
      const v = known[k];
      if (v !== undefined && filled[k] === undefined) {
        (filled as Record<string, unknown>)[k] = v;
        changed = true;
      }
    }
    if (!filled.path && known.path) {
      filled.path = known.path;
      changed = true;
    }
    return changed ? ({ ...event, process: filled } as SensorEvent) : event;
  }

  private lookup(p: ProcessRef): Known | undefined {
    const byPid = p.pid > 0 ? this.byPid.get(p.pid) : undefined;
    // A reused pid runs a different program; the path gives that away.
    if (byPid && (!p.path || p.path === byPid.path)) {
      // Long-running programs keep their place ahead of short-lived churn.
      remember(this.byPid, p.pid, byPid);
      const sig = byPid.signing === undefined && p.path ? this.byPath.get(p.path) : undefined;
      return sig ? { ...sig, ...withoutUndefined(byPid) } : byPid;
    }
    return p.path ? this.byPath.get(p.path) : undefined;
  }
}

/** A path can be updated to a new build, so its hashes belong to the pid only. */
function programOf(p: ProcessRef): Signature {
  const { sha256: _sha, cdhash: _cd, ...program } = signatureOf(p);
  return program;
}

function withoutUndefined<T extends object>(o: T): Partial<T> {
  const out: Partial<T> = {};
  for (const [k, v] of Object.entries(o))
    if (v !== undefined) (out as Record<string, unknown>)[k] = v;
  return out;
}
