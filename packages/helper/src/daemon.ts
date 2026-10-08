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
// Events Santa uploads over sync are not used: any local account can post to
// the port, and santa.log already has the same executions and file accesses.

import { createServer as createHttpsServer, type Server as HttpsServer } from 'node:https';
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
  if (!linux) {
    await ensureSyncTls(tls, opts.opensslBin);

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
  if (!linux) {
    const sync = new SantaSyncServer({
      store: rules,
      log,
      eventDetailUrl: 'vigil://santa/event?sha256=%file_sha%',
      eventDetailText: 'Open Vigil',
    });
    live.sync = sync;
    const server = createHttpsServer(
      {
        key: readFileSync(tls.serverKey),
        cert: readFileSync(tls.serverCert),
        minVersion: 'TLSv1.2',
      },
      sync.handler,
    );
    https = server;
    // Another account can hold the port first. Blocking, sensors and the
    // socket don't depend on it, so keep them running and try again later.
    const listenSync = async (): Promise<void> => {
      if (stopped) return;
      try {
        await new Promise<void>((resolve, reject) => {
          server.once('error', reject);
          server.listen(syncPort, '127.0.0.1', () => {
            server.off('error', reject);
            resolve();
          });
        });
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
          if (changed)
            server.setSecureContext({
              key: readFileSync(tls.serverKey),
              cert: readFileSync(tls.serverCert),
            });
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
