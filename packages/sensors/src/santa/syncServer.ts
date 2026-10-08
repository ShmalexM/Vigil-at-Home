// Vigil as Santa's sync server, running on the same Mac.
//
// Flow of one sync (Santa drives it, every full_sync_interval seconds or when
// `santactl sync` is run):
//
//   preflight ──► eventupload (0..n) ──► ruledownload (1..n) ──► postflight
//   Vigil picks    Santa reports        Vigil sends rules        Santa confirms,
//   NORMAL/CLEAN   blocks it made       changed since the        Vigil records the
//   and the mode                        last confirmed sync      synced revision
//
// Santa only accepts plain http for localhost, but anything running as the
// user could bind the port first and serve allow rules. So in production this
// server runs inside the root helper over HTTPS, with the CA pinned in
// Santa's ServerAuthRootsData and the private key readable only by root.

import type { IncomingMessage, ServerResponse } from 'node:http';
import { gunzipSync, inflateSync } from 'node:zlib';
import { createHash } from 'node:crypto';
import { defined, nonEmpty, pidOf, type SensorEvent, type SensorEventSink } from '../types.js';
import type { RuleStore, StoredRule } from './ruleStore.js';
import { santaSigning } from '../signing.js';
import { WRITE_WATCH_SUFFIX } from './logParser.js';
import {
  type ClientMode,
  type PreflightResponse,
  type RuleDownloadResponse,
  normalizeUploadedEvent,
  normalizeUploadedFileAccessEvent,
  pick,
} from './syncProtocol.js';

/** Sent alone on a clean sync when Vigil has no rules; see preflight(). */
export const CLEAN_SYNC_SENTINEL: StoredRule = {
  rule: { identifier: '0'.repeat(64), policy: 'REMOVE', rule_type: 'BINARY' },
  rev: 0,
  removed: true,
  updatedAt: 0,
};

export interface SyncServerOptions {
  store: RuleStore;
  /**
   * Gets the events uploaded to /eventupload. Nothing proves Santa sent them:
   * any local account can post here, so they must never drive a response.
   * The helper leaves this unset and reads the same events from santa.log.
   */
  onEvent?: SensorEventSink;
  /** Default MONITOR: only explicit block rules are enforced; unknown programs still run. */
  clientMode?: ClientMode;
  fullSyncIntervalSeconds?: number;
  /** Shown as the button in Santa's block dialog; placeholders like %file_sha% are filled by Santa. */
  eventDetailUrl?: string;
  eventDetailText?: string;
  /** Rules per RuleDownload page. */
  pageSize?: number;
  maxBodyBytes?: number;
  log?: (msg: string) => void;
  /** For tests. */
  now?: () => number;
}

interface SyncSession {
  clean: boolean;
  /** Rules to send in this sync, frozen at preflight so pages stay consistent. */
  rules: StoredRule[];
  snapshotRev: number;
  startedAt: number;
}

// Any local account can reach the port, and each machine id holds a copy of
// the rules until postflight, so only a few unfinished syncs are kept, briefly.
export const MAX_SYNC_SESSIONS = 4;
export const SYNC_SESSION_TTL_MS = 10 * 60 * 1000;

const ROUTE_RE = /^\/(preflight|eventupload|ruledownload|postflight)\/([^/?#]{1,128})\/?$/;

export class HttpError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

export class SantaSyncServer {
  private readonly sessions = new Map<string, SyncSession>();
  private readonly opts: Required<
    Omit<SyncServerOptions, 'onEvent' | 'eventDetailUrl' | 'eventDetailText' | 'log'>
  > &
    SyncServerOptions;

  constructor(options: SyncServerOptions) {
    this.opts = {
      clientMode: 'MONITOR',
      fullSyncIntervalSeconds: 600,
      pageSize: 500,
      maxBodyBytes: 16 * 1024 * 1024,
      now: Date.now,
      ...options,
    };
  }

  /** Node http(s) request handler. */
  readonly handler = (req: IncomingMessage, res: ServerResponse): void => {
    this.handle(req)
      .then((body) => {
        const json = JSON.stringify(body);
        res.writeHead(200, {
          'content-type': 'application/json',
          'content-length': Buffer.byteLength(json),
        });
        res.end(json);
      })
      .catch((err: unknown) => {
        const status = err instanceof HttpError ? err.status : 500;
        this.opts.log?.(`santa sync ${req.method} ${req.url} failed: ${(err as Error).message}`);
        res.writeHead(status, { 'content-type': 'text/plain' });
        res.end(status === 500 ? 'internal error' : (err as Error).message);
      });
  };

  async handle(req: IncomingMessage): Promise<unknown> {
    if (req.method !== 'POST') throw new HttpError(405, 'method not allowed');
    const m = ROUTE_RE.exec(req.url ?? '');
    if (!m) throw new HttpError(404, 'not found');
    const stage = m[1]!;
    const machineId = decodeURIComponent(m[2]!);
    const contentType = String(req.headers['content-type'] ?? '');
    if (contentType.includes('protobuf')) {
      // SyncEnableProtoTransfer must stay off in the profile Vigil generates.
      throw new HttpError(415, 'binary proto transfer is not supported');
    }
    const body = await this.readJson(req);
    return this.dispatch(stage, machineId, body);
  }

  dispatch(stage: string, machineId: string, body: unknown): unknown {
    switch (stage) {
      case 'preflight':
        return this.preflight(machineId, body);
      case 'eventupload':
        return this.eventUpload(machineId, body);
      case 'ruledownload':
        return this.ruleDownload(machineId, body);
      case 'postflight':
        return this.postflight(machineId, body);
      default:
        throw new HttpError(404, 'not found');
    }
  }

  private preflight(machineId: string, body: unknown): PreflightResponse {
    const { store } = this.opts;
    const requestedClean = pick<boolean>(body, 'request_clean_sync') === true;
    const clientCount = ['binary', 'certificate', 'teamid', 'signingid', 'cdhash'].reduce(
      (sum, t) => sum + (Number(pick(body, `${t}_rule_count`)) || 0),
      0,
    );
    const active = store.active();
    // If Santa's database drifted from ours (someone edited it, Santa was
    // reinstalled), replace it wholesale rather than guessing.
    const drifted =
      !store.cleanSyncPending && store.syncedRev === store.rev && clientCount !== active.length;
    const clean = requestedClean || store.cleanSyncPending || drifted;

    const snapshotRev = store.rev;
    let rules = clean ? active : store.changesSince(store.syncedRev);
    // Santa wipes its rules on a clean sync only when the download holds at
    // least one rule (SNTSyncRuleDownload returns early on an empty one), so
    // an empty clean sync would leave whatever Santa already had. A REMOVE for
    // a hash no program has makes the wipe happen and changes nothing else.
    if (clean && rules.length === 0) rules = [CLEAN_SYNC_SENTINEL];
    this.startSession(machineId, { clean, rules, snapshotRev, startedAt: this.opts.now() });

    const resp: PreflightResponse = {
      client_mode: this.opts.clientMode,
      sync_type: clean ? 'CLEAN' : 'NORMAL',
      batch_size: 50,
      enable_bundles: false,
      enable_transitive_rules: false,
      // Monitor mode would otherwise upload every unknown program; Vigil
      // already sees executions in Santa's event log.
      disable_unknown_event_upload: true,
      full_sync_interval: this.opts.fullSyncIntervalSeconds,
    };
    if (this.opts.eventDetailUrl) resp.event_detail_url = this.opts.eventDetailUrl;
    if (this.opts.eventDetailText) resp.event_detail_text = this.opts.eventDetailText;
    return resp;
  }

  private startSession(machineId: string, session: SyncSession): void {
    this.dropExpired();
    this.sessions.delete(machineId);
    // Any local account can start syncs under made-up machine ids. Once Santa
    // has finished a sync, its id always gets a session and the others share
    // what is left, so they can only push each other out.
    const known = this.opts.store.syncedMachineId;
    const isKnown = known !== undefined && machineId === known;
    const others = () => [...this.sessions.keys()].filter((id) => id !== known);
    const limit = known === undefined || isKnown ? MAX_SYNC_SESSIONS : MAX_SYNC_SESSIONS - 1;
    const used = () => (isKnown ? this.sessions.size : others().length);
    while (used() >= limit) {
      // The map is in start order, so this is the oldest evictable session.
      const oldest = others()[0];
      if (oldest === undefined) break;
      this.sessions.delete(oldest);
    }
    this.sessions.set(machineId, session);
  }

  private session(machineId: string): SyncSession | undefined {
    this.dropExpired();
    return this.sessions.get(machineId);
  }

  private dropExpired(): void {
    const cutoff = this.opts.now() - SYNC_SESSION_TTL_MS;
    for (const [id, s] of this.sessions) if (s.startedAt < cutoff) this.sessions.delete(id);
  }

  private eventUpload(machineId: string, body: unknown): Record<string, never> {
    const events = pick<unknown[]>(body, 'events') ?? [];
    const faa = pick<unknown[]>(body, 'file_access_events') ?? [];
    const sink = this.opts.onEvent;
    if (sink) {
      for (const raw of Array.isArray(events) ? events : [])
        sink(uploadedExecToEvent(raw, machineId));
      for (const raw of Array.isArray(faa) ? faa : [])
        sink(uploadedFileAccessToEvent(raw, machineId));
    }
    return {};
  }

  private ruleDownload(machineId: string, body: unknown): RuleDownloadResponse {
    const session = this.session(machineId);
    if (!session) throw new HttpError(409, 'ruledownload without preflight');
    const cursor = pick<string>(body, 'cursor') ?? '';
    const offset = cursor === '' ? 0 : Number.parseInt(cursor, 10);
    if (!Number.isInteger(offset) || offset < 0 || offset > session.rules.length) {
      throw new HttpError(400, 'bad cursor');
    }
    const page = session.rules.slice(offset, offset + this.opts.pageSize);
    const next = offset + page.length;
    const resp: RuleDownloadResponse = { rules: page.map((r) => r.rule) };
    if (next < session.rules.length) resp.cursor = String(next);
    return resp;
  }

  /** When Santa last finished a sync with this server (ms since epoch), or null. */
  lastSyncAt: number | null = null;

  private postflight(machineId: string, body: unknown): Record<string, never> {
    const session = this.session(machineId);
    // A postflight with no sync behind it says nothing about Santa.
    if (!session) return {};
    this.sessions.delete(machineId);
    this.lastSyncAt = this.opts.now();
    const received = Number(pick(body, 'rules_received') ?? NaN);
    const processed = Number(pick(body, 'rules_processed') ?? NaN);
    // Only advance when Santa says it applied everything we sent; otherwise
    // the same changes go out again next time.
    if (received === session.rules.length && processed === session.rules.length) {
      this.opts.store.markSynced(session.snapshotRev, session.clean, machineId);
    } else {
      this.opts.log?.(
        `santa postflight mismatch: sent ${session.rules.length}, received ${received}, processed ${processed}`,
      );
    }
    return {};
  }

  private async readJson(req: IncomingMessage): Promise<unknown> {
    const chunks: Buffer[] = [];
    let size = 0;
    for await (const chunk of req) {
      size += (chunk as Buffer).length;
      if (size > this.opts.maxBodyBytes) throw new HttpError(413, 'body too large');
      chunks.push(chunk as Buffer);
    }
    let buf = Buffer.concat(chunks);
    const encoding = String(req.headers['content-encoding'] ?? '').toLowerCase();
    try {
      if (encoding === 'deflate')
        buf = inflateSync(buf, { maxOutputLength: this.opts.maxBodyBytes });
      else if (encoding === 'gzip')
        buf = gunzipSync(buf, { maxOutputLength: this.opts.maxBodyBytes });
      else if (encoding !== '' && encoding !== 'identity')
        throw new HttpError(415, 'unsupported encoding');
    } catch (err) {
      if (err instanceof HttpError) throw err;
      throw new HttpError(400, 'bad compressed body');
    }
    if (buf.length === 0) return {};
    try {
      return JSON.parse(buf.toString('utf8'));
    } catch {
      throw new HttpError(400, 'bad json');
    }
  }
}

function syncEventId(kind: string, raw: unknown): string {
  return (
    `santa-sync:${kind}:` +
    createHash('sha256').update(JSON.stringify(raw)).digest('hex').slice(0, 32)
  );
}

export function uploadedExecToEvent(raw: unknown, _machineId: string): SensorEvent {
  const e = normalizeUploadedEvent(raw);
  const process = defined({
    pid: pidOf(e.pid) ?? 0,
    ppid: pidOf(e.ppid),
    path: e.file_path && e.file_name ? `${e.file_path}/${e.file_name}` : (e.file_path ?? ''),
    sha256: nonEmpty(e.file_sha256),
    cdhash: nonEmpty(e.cdhash),
    teamId: nonEmpty(e.team_id),
    signingId: nonEmpty(e.signing_id),
    signing: santaSigning({
      cert_cn: e.signing_chain?.[0]?.cn,
      teamid: e.team_id,
      signingid: e.signing_id,
    }),
    user: nonEmpty(e.executing_user),
    parentPath: nonEmpty(e.parent_name),
  });
  const base = {
    id: syncEventId('exec', raw),
    ts: e.execution_time !== undefined ? Math.round(e.execution_time * 1000) : Date.now(),
    source: 'santa' as const,
    raw,
  };
  const decision = e.decision ?? 'DECISION_UNKNOWN';
  if (decision.startsWith('BLOCK_')) {
    return {
      ...base,
      kind: 'santa.decision',
      target: 'execution',
      decision: 'block',
      reason: decision,
      process,
    };
  }
  return { ...base, kind: 'process.exec', process };
}

export function uploadedFileAccessToEvent(raw: unknown, _machineId: string): SensorEvent {
  const e = normalizeUploadedFileAccessEvent(raw);
  const p = e.process_chain?.[0];
  const decision = e.decision ?? 'FILE_ACCESS_DECISION_UNKNOWN';
  const base = {
    id: syncEventId('faa', raw),
    ts: e.access_time !== undefined ? Math.round(e.access_time * 1000) : Date.now(),
    source: 'santa' as const,
    raw,
  };
  const path = e.target ?? '';
  const process = p
    ? defined({
        pid: pidOf(p.pid) ?? 0,
        path: p.file_path ?? '',
        sha256: nonEmpty(p.file_sha256),
        cdhash: nonEmpty(p.cdhash),
        teamId: nonEmpty(p.team_id),
        signingId: nonEmpty(p.signing_id),
        signing: santaSigning({ teamid: p.team_id, signingid: p.signing_id }),
      })
    : undefined;
  if (decision.includes('DENIED')) {
    return {
      ...base,
      kind: 'santa.decision',
      target: 'file_access',
      decision: 'block',
      reason: e.rule_name ? `${decision}:${e.rule_name}` : decision,
      path,
      process: process ?? { pid: 0, path: '' },
    };
  }
  // Santa uploads only what a watch item matched, so an access it let through
  // was audit-only: file activity for the rules, like the event log's.
  return {
    ...base,
    kind: 'file',
    op: e.rule_name?.endsWith(WRITE_WATCH_SUFFIX) ? 'write' : 'open',
    path,
    ...defined({ process }),
  };
}
