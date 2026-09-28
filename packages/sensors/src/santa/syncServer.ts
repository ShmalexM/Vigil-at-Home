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
import {
  type ClientMode,
  type PreflightResponse,
  type RuleDownloadResponse,
  normalizeUploadedEvent,
  normalizeUploadedFileAccessEvent,
  pick,
} from './syncProtocol.js';

export interface SyncServerOptions {
  store: RuleStore;
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
}

interface SyncSession {
  clean: boolean;
  /** Rules to send in this sync, frozen at preflight so pages stay consistent. */
  rules: StoredRule[];
  snapshotRev: number;
  startedAt: number;
}

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
    const rules = clean ? active : store.changesSince(store.syncedRev);
    this.sessions.set(machineId, { clean, rules, snapshotRev, startedAt: Date.now() });

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
    const session = this.sessions.get(machineId);
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
    this.lastSyncAt = Date.now();
    const session = this.sessions.get(machineId);
    this.sessions.delete(machineId);
    if (!session) return {};
    const received = Number(pick(body, 'rules_received') ?? NaN);
    const processed = Number(pick(body, 'rules_processed') ?? NaN);
    // Only advance when Santa says it applied everything we sent; otherwise
    // the same changes go out again next time.
    if (received === session.rules.length && processed === session.rules.length) {
      this.opts.store.markSynced(session.snapshotRev, session.clean);
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
  return {
    id: syncEventId('faa', raw),
    ts: e.access_time !== undefined ? Math.round(e.access_time * 1000) : Date.now(),
    source: 'santa',
    raw,
    kind: 'santa.decision',
    target: 'file_access',
    decision: decision.includes('DENIED') ? 'block' : 'audit_only',
    reason: e.rule_name ? `${decision}:${e.rule_name}` : decision,
    path: e.target ?? '',
    process: p
      ? defined({
          pid: pidOf(p.pid) ?? 0,
          path: p.file_path ?? '',
          sha256: nonEmpty(p.file_sha256),
          cdhash: nonEmpty(p.cdhash),
          teamId: nonEmpty(p.team_id),
          signingId: nonEmpty(p.signing_id),
        })
      : { pid: 0, path: '' },
  };
}
