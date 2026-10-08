// The root daemon launchd starts at boot. It wires together:
//   - the command socket the app talks to (HelperServer + Executor)
//   - Santa's sync server over pinned HTTPS on 127.0.0.1
//   - the log sensors (Santa's event log, osquery results), streamed to the app
//   - the app's blocking rules, run on that stream before it leaves (FastPath)
//
//   Santa ──santa.log──┐                                    ┌── socket ──► Vigil app (popup, rules, AI)
//   osquery ──results──┴─► SensorHub ─► FastPath ─► publish ┤   (event + what the helper ran)
//                                            │ kill/block     └── commands ◄── Vigil app
//                                            ▼ Executor
//   Santa ◄─sync HTTPS── rules ─── RuleStore ◄── santa.block / santa.allow
//   osqueryd -S ◄── SensorHub: a 2 s look at suspicious programs' connections
//
// The sync port takes only the client certificate the helper made for Santa
// (mutual TLS, pinned by SHA-256; see createSyncHttpsServer). Events Santa
// uploads over sync are still not used: santa.log already has them, and
// Santa's profile may predate the client certificate (see SyncClientAuth).

import type { IncomingMessage, ServerResponse } from 'node:http';
import { createServer as createHttpsServer, type Server as HttpsServer } from 'node:https';
import type { TLSSocket } from 'node:tls';
import { createHash } from 'node:crypto';
import { chmodSync, existsSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import {
  FileHasher,
  OSQUERYD_PATH,
  RuleStore,
  type SensorEvent,
  SantaSyncServer,
  type SignatureInfo,
  SensorHub,
  certFingerprint,
  ensureSyncTls,
  fileAccessPolicy,
  syncTlsPaths,
} from '@vigil/sensors';
import { Approvals } from './approval.js';
import { defaultPaths, SANTA_SYNC_PORT, type HelperPaths } from './config.js';
import { Executor, type ActionOutcome } from './executor.js';
import { FastPath } from './fastpath.js';
import { Journal } from './journal.js';
import {
  ensureOsquery,
  defaultOsqueryPaths,
  osqueryShellRunner,
  santaReportsLaunchItems,
  type OsqueryPaths,
} from './osquery.js';
import { HelperServer } from './server.js';
import { PreexecSync } from './preexec.js';
import { signatureLookup } from './signature.js';
import { linuxPackageIndex } from './packageTrust.js';
import { ensureLinuxOsquery, type LinuxOsqueryPaths } from './linuxOsquery.js';
import { FapolicydBlocks } from './commands/fapolicyd.js';
import type { HelperRan } from './fastpath.js';
import { BINARIES, LINUX_BINARIES, realSystem, type System } from './system.js';

export interface DaemonOptions {
  paths?: HelperPaths;
  syncPort?: number;
  sys?: System;
  log?: (msg: string) => void;
  /** Owner required on approval files; only tests change this from root. */
  approvalOwnerUid?: number;
  opensslBin?: string;
  /** Files whose presence means Santa and osquery are installed; tests point these elsewhere. */
  sensorBinaries?: { santa: string | false; osquery: string };
  /** Where osquery lives; false leaves osquery alone (tests). Only acted on as root. */
  osquery?: OsqueryPaths | false;
  /** Linux: where osquery lives; false leaves it alone. Only acted on as root. */
  linuxOsquery?: LinuxOsqueryPaths;
  /** Linux: fapolicyd's rules folder; tests point it elsewhere. */
  fapolicydRulesDir?: string;
  /** Linux: the trust answer for a program path. Defaults to the dpkg/rpm index. */
  trust?: (path: string) => SignatureInfo | undefined;
  /** How long to wait before trying the sync port again when it is taken. */
  syncRetryMs?: number;
}

/** What helper.status reports about each sensor. The app decides what counts as stale. */
export interface SensorHealth {
  santa: {
    installed: boolean;
    lastEventAt: number | null;
    lastSyncAt: number | null;
    /** Why the sync server isn't listening (it keeps retrying), or null. */
    syncError: string | null;
    /**
     * Whether the sync port takes only Santa's client certificate. False until
     * Santa first presents it, i.e. while its profile predates the certificate
     * and needs installing again (SyncClientAuth).
     */
    clientCertRequired: boolean;
  };
  osquery: { installed: boolean; lastEventAt: number | null };
}

export async function runDaemon(opts: DaemonOptions = {}): Promise<() => Promise<void>> {
  const sys = opts.sys ?? realSystem();
  // Linux has no Santa: no sync server, certificate or file-access policy,
  // and network blocks go through nftables (see executor.ts).
  const linux = sys.platform === 'linux';
  const paths = opts.paths ?? defaultPaths(undefined, linux ? 'linux' : 'darwin');
  const log = opts.log ?? ((m: string) => console.error(`[vigil-helper] ${m}`));
  const syncPort = opts.syncPort ?? SANTA_SYNC_PORT;

  if (process.getuid?.() !== 0) log('warning: not running as root; most actions will fail');
  // Everything the helper creates is private unless it says otherwise.
  process.umask(0o077);
  mkdirSync(paths.supportDir, { recursive: true, mode: 0o755 });
  // The umask above would make it 0700, and so did earlier versions. Santa's
  // sync service runs as nobody and must pass through it to read the pinned CA
  // in santa-sync/. Everything inside is 0600/0644 or its own 0700 folder.
  chmodSync(paths.supportDir, 0o755);

  const tls = syncTlsPaths(paths.tlsDir);
  let clientAuth: SyncClientAuth | undefined;
  if (!linux) {
    // No CA yet means no Santa profile was ever made for this helper, so the
    // profile the user installs will carry the client certificate.
    const fresh = !existsSync(tls.caCert);
    await ensureSyncTls(tls, opts.opensslBin);
    clientAuth = new SyncClientAuth({
      marker: join(paths.tlsDir, CLIENT_AUTH_MARKER),
      clientCert: tls.clientCert,
      fresh,
      log,
    });

    // Vigil owns this policy file; Santa re-reads it every minute. Rewriting it
    // brings watch items added in newer versions to existing installs, keeping
    // blocking on if the user turned it on.
    writeFileAccessPolicy(paths.fileAccessPolicy);
  }

  const rules = new RuleStore(paths.santaRules);
  const journal = new Journal(paths.journal);
  const approvals = new Approvals({
    dir: paths.approvalsDir,
    requiredOwnerUid: opts.approvalOwnerUid ?? 0,
  });
  const bins =
    opts.sensorBinaries ??
    (linux
      ? { santa: false as const, osquery: LINUX_BINARIES.osqueryd }
      : { santa: BINARIES.santactl, osquery: OSQUERYD_PATH });
  // Created below, after the socket is up; status calls before then report no activity.
  const live: { hub?: SensorHub; sync?: SantaSyncServer; syncError?: string } = {};
  const sensors = (): SensorHealth => {
    const seen = live.hub?.lastEventAt();
    return {
      santa: {
        installed: bins.santa !== false && existsSync(bins.santa),
        lastEventAt: seen?.santa ?? null,
        lastSyncAt: live.sync?.lastSyncAt ?? null,
        syncError: live.syncError ?? null,
        clientCertRequired: clientAuth?.required ?? false,
      },
      osquery: { installed: existsSync(bins.osquery), lastEventAt: seen?.osquery ?? null },
    };
  };

  // Blocking rules from the app, run on the sensor stream before events reach it.
  const fastPath: FastPath = new FastPath({
    file: paths.helperRules,
    run: async (action): Promise<ActionOutcome> => {
      const out = await executor.execute(action);
      if (out.kind !== 'done') throw new Error('needs the admin password');
      return out.result as ActionOutcome;
    },
    log,
  });
  fastPath.load();

  // Linux: programs blocked by hash (fapolicyd, plus the check on each launch below).
  const fapolicyd = linux
    ? new FapolicydBlocks(sys, {
        store: join(paths.supportDir, 'blocked-programs.json'),
        ...(opts.fapolicydRulesDir ? { rulesDir: opts.fapolicydRulesDir } : {}),
      })
    : undefined;

  const executor: Executor = new Executor({
    sys,
    journal,
    approvals,
    rules,
    quarantine: { quarantineDir: paths.quarantineDir },
    syncPort,
    ...(linux
      ? {}
      : {
          santaClientCert: () => ({
            path: tls.clientP12,
            password: readFileSync(tls.clientP12Password, 'utf8').trim(),
          }),
          triggerSantaSync: async () => {
            await sys.run('santactl', ['sync'], { timeoutMs: 60_000 });
          },
          preexec: new PreexecSync(sys, rules, existsSync),
        }),
    statusExtra: () => ({
      sensors: sensors(),
      helperRules: fastPath.status(),
      ...(fapolicyd ? { fapolicyd: fapolicyd.status() } : {}),
    }),
    fastPath,
    ...(fapolicyd ? { fapolicyd } : {}),
  });

  const server = new HelperServer({
    socketPath: paths.socket,
    executor,
    ownerUid: sys.consoleUid(),
    log,
  });
  await server.listen();

  // Linux: a blocked program that got past fapolicyd (not installed, or not
  // reloaded yet) is stopped as soon as its launch is seen.
  const stopBlockedLaunch = async (e: SensorEvent): Promise<HelperRan[]> => {
    if (!fapolicyd || e.kind !== 'process.exec' || !e.process.sha256) return [];
    if (!fapolicyd.has(e.process.sha256)) return [];
    const action = { kind: 'process.kill' as const, pid: e.process.pid, path: e.process.path };
    try {
      const out = await executor.execute(action);
      return [
        {
          ruleId: 'blocked-program',
          action,
          at: Date.now(),
          ...(out.kind === 'done' ? { outcome: out.result as ActionOutcome } : {}),
        },
      ];
    } catch (err) {
      return [{ ruleId: 'blocked-program', action, at: Date.now(), error: (err as Error).message }];
    }
  };

  let delivered = Promise.resolve();
  const hub = new SensorHub({
    santaLogPath: paths.santaLog,
    osqueryResultsPath: paths.osqueryResults,
    // One event at a time, in order: a block finishes before the next event
    // is looked at, and the app hears about each event with what was done.
    sink: (e) => {
      delivered = delivered.then(async () => {
        const ran = [...(await stopBlockedLaunch(e)), ...(await fastPath.check(e))];
        server.publish(e, ran);
      });
    },
    // Signatures of programs that started before Vigil (codesign is macOS-only).
    ...(process.platform === 'darwin' && !linux ? { signatureLookup: signatureLookup(sys) } : {}),
    // Linux: whether the package manager installed each program, answered at
    // once, and the hash of each untrusted one (blocks are by hash).
    ...(linux ? { trust: opts.trust ?? trustFromPackages(), hash: hasher() } : {}),
    // The closer look at suspicious programs' connections needs osquery and root.
    ...(existsSync(bins.osquery) && process.getuid?.() === 0 && opts.osquery !== false
      ? { osqueryRunner: osqueryShellRunner(sys) }
      : {}),
    onError: (source, err) => log(`${source} sensor: ${err.message}`),
  });
  await hub.start();
  live.hub = hub;

  let https: HttpsServer | undefined;
  let syncRetry: NodeJS.Timeout | undefined;
  let stopped = false;
  if (clientAuth) {
    const sync = new SantaSyncServer({
      store: rules,
      log,
      eventDetailUrl: 'vigil://santa/event?sha256=%file_sha%',
      eventDetailText: 'Open Vigil',
    });
    live.sync = sync;
    const server = createSyncHttpsServer(syncTlsFiles(tls), sync.handler, clientAuth);
    https = server;
    // Another account can hold the port first. Blocking, sensors and the
    // socket don't depend on it, so keep them running and try again later.
    const listenSync = async (): Promise<void> => {
      if (stopped) return;
      try {
        await listenUnlessStopped(server, syncPort, () => stopped);
        if (stopped) return;
        if (live.syncError) log(`Santa sync listening on port ${syncPort}`);
        delete live.syncError;
      } catch (err) {
        const msg = (err as Error).message;
        if (live.syncError !== msg) log(`Santa sync server: ${msg}; retrying`);
        live.syncError = msg;
        if (stopped) return;
        syncRetry = setTimeout(() => void listenSync(), opts.syncRetryMs ?? 30_000);
        syncRetry.unref();
      }
    };
    await listenSync();
  }

  if (fapolicyd) {
    try {
      await fapolicyd.apply();
    } catch (err) {
      log(`could not apply fapolicyd rules: ${(err as Error).message}`);
    }
  }

  try {
    const n = await executor.reapplyFirewallBlocks();
    if (n) log(`re-applied ${n} network blocks`);
  } catch (err) {
    log(`could not re-apply network blocks: ${(err as Error).message}`);
  }

  // Start osquery with Vigil's queries once it is installed, and keep it loaded.
  const osqueryPaths = opts.osquery ?? defaultOsqueryPaths();
  const keepOsquery = () => {
    if (opts.osquery === false || process.getuid?.() !== 0) return;
    if (linux) {
      ensureLinuxOsquery(sys, opts.linuxOsquery)
        .then((state) => {
          if (state === 'started' || state === 'restarted') log(`osquery ${state}`);
        })
        .catch((err: Error) => log(`could not start osquery: ${err.message}`));
      return;
    }
    if (!osqueryPaths) return;
    // osquery's startup-item query slows to a 5 minute safety net only while
    // Santa is actually reporting (it can be installed but not yet approved).
    const santaAt = hub.lastEventAt().santa;
    const santaLive = santaAt !== null && Date.now() - santaAt < 10 * 60 * 1000;
    ensureOsquery(sys, osqueryPaths, {
      santaReportsLaunchItems: santaLive && santaReportsLaunchItems(),
    })
      .then((state) => {
        if (state === 'started' || state === 'restarted') log(`osquery ${state}`);
      })
      .catch((err: Error) => log(`could not start osquery: ${err.message}`));
  };
  keepOsquery();
  const osqueryTimer = setInterval(keepOsquery, 5 * 60 * 1000);
  osqueryTimer.unref();

  // Renew the sync certificate daily if it is close to expiring.
  const renew = setInterval(
    () => {
      if (!https) return;
      const server = https;
      ensureSyncTls(tls, opts.opensslBin)
        .then((changed) => {
          if (!changed) return;
          server.setSecureContext(syncTlsFiles(tls));
          // Santa reads the new PKCS#12 on its next sync.
          clientAuth?.reload();
        })
        .catch((err: Error) => log(`certificate renewal failed: ${err.message}`));
    },
    24 * 3600 * 1000,
  );
  renew.unref();

  log(
    https?.listening
      ? `ready: socket ${paths.socket}, Santa sync on https://127.0.0.1:${syncPort}/`
      : `ready: socket ${paths.socket}`,
  );

  return async () => {
    stopped = true;
    clearTimeout(syncRetry);
    clearInterval(renew);
    clearInterval(osqueryTimer);
    await hub.stop();
    await server.close();
    if (https?.listening) {
      const server = https;
      await new Promise<void>((r) => server.close(() => r()));
    }
  };
}

function syncTlsFiles(tls: ReturnType<typeof syncTlsPaths>): SyncTlsFiles {
  return {
    key: readFileSync(tls.serverKey),
    cert: readFileSync(tls.serverCert),
    ca: readFileSync(tls.caCert),
  };
}

/** Written once Santa has presented its client certificate; from then on it is required. */
export const CLIENT_AUTH_MARKER = 'client-auth-required';

/** Which clients the sync port takes. */
export interface SyncClientPin {
  /** SHA-256 (hex) of the DER certificate Santa presents. */
  readonly fingerprint: string;
  /** Whether a client must present a certificate at all. */
  readonly required: boolean;
  /** Called when a client presented the pinned certificate. */
  pinnedSeen(): void;
}

/**
 * Santa's client certificate pin, and the move from profiles made before it
 * existed.
 *
 * Santa reads its settings only from the profile the user installed, which
 * the helper can't rewrite. A profile from an earlier version has no
 * ClientAuthCertificateFile, so that Santa connects without a certificate.
 * Refusing it would stop rule updates (blocks included) until the user
 * reinstalls the profile, so until Santa first presents the pinned
 * certificate a client without one is still served as before. Santa
 * presenting it shows the new profile is in place: the helper records that
 * in a root-only marker and from then on refuses every other client, across
 * restarts. A client presenting any other certificate is always refused.
 * A new install (no CA yet) starts in the required state.
 */
export class SyncClientAuth implements SyncClientPin {
  private pin: string;
  private requireCert: boolean;

  constructor(
    private readonly o: {
      marker: string;
      clientCert: string;
      fresh: boolean;
      log: (msg: string) => void;
    },
  ) {
    this.pin = certFingerprint(readFileSync(o.clientCert));
    if (o.fresh) this.markRequired();
    this.requireCert = existsSync(o.marker);
    if (!this.requireCert)
      o.log(
        "Santa sync: Santa's profile predates its client certificate; clients without one " +
          'are served until Santa presents it (reinstall the Santa profile)',
      );
  }

  get fingerprint(): string {
    return this.pin;
  }

  get required(): boolean {
    return this.requireCert;
  }

  /** Re-reads the certificate after renewal. */
  reload(): void {
    this.pin = certFingerprint(readFileSync(this.o.clientCert));
  }

  pinnedSeen(): void {
    if (this.requireCert) return;
    this.requireCert = true;
    try {
      this.markRequired();
    } catch (err) {
      // Required for the rest of this run either way.
      this.o.log(`Santa sync: could not record the client certificate: ${(err as Error).message}`);
    }
    this.o.log('Santa sync: Santa presented its client certificate; it is now required');
  }

  private markRequired(): void {
    writeFileSync(this.o.marker, `${new Date().toISOString()}\n`, { mode: 0o600 });
    chmodSync(this.o.marker, 0o600);
  }
}

/**
 * Limits on the Santa sync port. Any local process can open a connection, so
 * slow or idle clients are cut off and only a few connections are kept at once.
 */
export const SYNC_SERVER_LIMITS: Readonly<{
  maxConnections: number;
  handshakeTimeoutMs: number;
  headersTimeoutMs: number;
  requestTimeoutMs: number;
  keepAliveTimeoutMs: number;
}> = {
  maxConnections: 16,
  handshakeTimeoutMs: 10_000,
  headersTimeoutMs: 15_000,
  requestTimeoutMs: 30_000,
  keepAliveTimeoutMs: 5_000,
};

export interface SyncTlsFiles {
  key: Buffer;
  cert: Buffer;
  /** Vigil's CA: the server's issuer and the only one client certificates may chain to. */
  ca: Buffer;
}

/** Whether a TLS connection may reach the sync handler. */
export function syncClientAllowed(socket: TLSSocket, pin: SyncClientPin): boolean {
  const peer = socket.getPeerCertificate();
  // An empty object when the client sent no certificate.
  if (!peer?.raw) return !pin.required;
  if (!socket.authorized) return false;
  if (createHash('sha256').update(peer.raw).digest('hex') !== pin.fingerprint) return false;
  pin.pinnedSeen();
  return true;
}

/**
 * The Santa sync server: HTTPS with Santa's client certificate pinned.
 * Clients are checked as soon as the handshake ends, before any request is
 * read, and again on each request.
 */
export function createSyncHttpsServer(
  tls: SyncTlsFiles,
  handler: (req: IncomingMessage, res: ServerResponse) => void,
  pin: SyncClientPin,
  l: typeof SYNC_SERVER_LIMITS = SYNC_SERVER_LIMITS,
): HttpsServer {
  const admitted = new WeakSet<TLSSocket>();
  const server = createHttpsServer(
    {
      ...tls,
      // The certificate must chain to Vigil's CA and then match the pin.
      // While a Santa profile from before the client certificate is still
      // installed, a client that sends none gets through the handshake to
      // the check below, which decides (SyncClientAuth).
      requestCert: true,
      rejectUnauthorized: pin.required,
      minVersion: 'TLSv1.2',
      handshakeTimeout: l.handshakeTimeoutMs,
      headersTimeout: l.headersTimeoutMs,
      requestTimeout: l.requestTimeoutMs,
      keepAliveTimeout: l.keepAliveTimeoutMs,
    },
    (req, res) => {
      const socket = req.socket as TLSSocket;
      // Again per request: a keep-alive connection admitted without a
      // certificate must not outlive Santa first presenting one.
      if (admitted.has(socket) && syncClientAllowed(socket, pin)) handler(req, res);
      else req.socket.destroy();
    },
  );
  // Ahead of the HTTP parser's own listener, so a refused client is gone
  // before it can send a request.
  server.prependListener('secureConnection', (socket: TLSSocket) => {
    if (syncClientAllowed(socket, pin)) admitted.add(socket);
    else socket.destroy();
  });
  server.maxConnections = l.maxConnections;
  return server;
}

/**
 * Listens on 127.0.0.1. If the helper stopped while the listen was under
 * way, closes the server again so the port is not left bound.
 */
export function listenUnlessStopped(
  server: HttpsServer,
  port: number,
  stopped: () => boolean,
): Promise<void> {
  return new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, '127.0.0.1', () => {
      server.off('error', reject);
      if (stopped()) server.close(() => resolve());
      else resolve();
    });
  });
}

function writeFileAccessPolicy(path: string): void {
  let current: string | undefined;
  try {
    current = readFileSync(path, 'utf8');
  } catch {
    mkdirSync(dirname(path), { recursive: true });
  }
  const enforce = current !== undefined && /<key>AuditOnly<\/key>\s*<false\/>/.test(current);
  const next = fileAccessPolicy({ enforce });
  if (next === current) return;
  writeFileSync(path, next, { mode: 0o644 });
  chmodSync(path, 0o644);
}

/** The package index, built once at start and reloaded when packages change. */
function trustFromPackages(): (path: string) => SignatureInfo | undefined {
  const index = linuxPackageIndex();
  return (path) => index.trust(path);
}

function hasher(): (path: string) => string | undefined {
  const h = new FileHasher();
  return (path) => h.sha256(path);
}
