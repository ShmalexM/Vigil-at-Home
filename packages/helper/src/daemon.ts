// The root daemon launchd starts at boot. It wires together:
//   - the command socket the app talks to (HelperServer + Executor)
//   - Santa's sync server over pinned HTTPS on 127.0.0.1
//   - the log sensors (Santa's event log, osquery results), streamed to the app
//
//   Santa ──santa.log──┐                        ┌── socket ──► Vigil app (popup, rules, AI)
//   osquery ──results──┼─► SensorHub ─► publish ┤
//   Santa ──sync HTTPS─┘   (blocks it made)     └── commands ◄── Vigil app
//         ◄── rules ─── RuleStore ◄── santa.block / santa.allow
//   osqueryd -S ◄── SensorHub: a 2 s look at suspicious programs' connections

import { createServer as createHttpsServer, type Server as HttpsServer } from 'node:https';
import { chmodSync, existsSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import {
  OSQUERYD_PATH,
  RuleStore,
  SantaSyncServer,
  SensorHub,
  ensureSyncTls,
  fileAccessPolicy,
  syncTlsPaths,
} from '@vigil/sensors';
import { Approvals } from './approval.js';
import { defaultPaths, SANTA_SYNC_PORT, type HelperPaths } from './config.js';
import { Executor } from './executor.js';
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
import { BINARIES, realSystem, type System } from './system.js';

export interface DaemonOptions {
  paths?: HelperPaths;
  syncPort?: number;
  sys?: System;
  log?: (msg: string) => void;
  /** Owner required on approval files; only tests change this from root. */
  approvalOwnerUid?: number;
  opensslBin?: string;
  /** Files whose presence means Santa and osquery are installed; tests point these elsewhere. */
  sensorBinaries?: { santa: string; osquery: string };
  /** Where osquery lives; false leaves osquery alone (tests). Only acted on as root. */
  osquery?: OsqueryPaths | false;
}

/** What helper.status reports about each sensor. The app decides what counts as stale. */
export interface SensorHealth {
  santa: { installed: boolean; lastEventAt: number | null; lastSyncAt: number | null };
  osquery: { installed: boolean; lastEventAt: number | null };
}

export async function runDaemon(opts: DaemonOptions = {}): Promise<() => Promise<void>> {
  const paths = opts.paths ?? defaultPaths();
  const sys = opts.sys ?? realSystem();
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
  await ensureSyncTls(tls, opts.opensslBin);

  // Vigil owns this policy file; Santa re-reads it every minute. Rewriting it
  // brings watch items added in newer versions to existing installs, keeping
  // blocking on if the user turned it on.
  writeFileAccessPolicy(paths.fileAccessPolicy);

  const rules = new RuleStore(paths.santaRules);
  const journal = new Journal(paths.journal);
  const approvals = new Approvals({
    dir: paths.approvalsDir,
    requiredOwnerUid: opts.approvalOwnerUid ?? 0,
  });
  const bins = opts.sensorBinaries ?? { santa: BINARIES.santactl, osquery: OSQUERYD_PATH };
  // Created below, after the socket is up; status calls before then report no activity.
  const live: { hub?: SensorHub; sync?: SantaSyncServer } = {};
  const sensors = (): SensorHealth => {
    const seen = live.hub?.lastEventAt();
    return {
      santa: {
        installed: existsSync(bins.santa),
        lastEventAt: seen?.santa ?? null,
        lastSyncAt: live.sync?.lastSyncAt ?? null,
      },
      osquery: { installed: existsSync(bins.osquery), lastEventAt: seen?.osquery ?? null },
    };
  };

  const executor = new Executor({
    sys,
    journal,
    approvals,
    rules,
    quarantine: { quarantineDir: paths.quarantineDir },
    syncPort,
    triggerSantaSync: async () => {
      await sys.run('santactl', ['sync'], { timeoutMs: 60_000 });
    },
    statusExtra: () => ({ sensors: sensors() }),
    preexec: new PreexecSync(sys, rules, existsSync),
  });

  const server = new HelperServer({
    socketPath: paths.socket,
    executor,
    ownerUid: sys.consoleUid(),
    log,
  });
  await server.listen();

  const hub = new SensorHub({
    santaLogPath: paths.santaLog,
    osqueryResultsPath: paths.osqueryResults,
    sink: (e) => server.publish(e),
    // Signatures of programs that started before Vigil (codesign is macOS-only).
    ...(process.platform === 'darwin' ? { signatureLookup: signatureLookup(sys) } : {}),
    // The closer look at suspicious programs' connections needs osquery and root.
    ...(existsSync(bins.osquery) && process.getuid?.() === 0 && opts.osquery !== false
      ? { osqueryRunner: osqueryShellRunner(sys) }
      : {}),
    onError: (source, err) => log(`${source} sensor: ${err.message}`),
  });
  await hub.start();
  live.hub = hub;

  const sync = new SantaSyncServer({
    store: rules,
    onEvent: (e) => hub.emit(e),
    log,
    eventDetailUrl: 'vigil://santa/event?sha256=%file_sha%',
    eventDetailText: 'Open Vigil',
  });
  live.sync = sync;
  const https: HttpsServer = createHttpsServer(
    { key: readFileSync(tls.serverKey), cert: readFileSync(tls.serverCert), minVersion: 'TLSv1.2' },
    sync.handler,
  );
  await new Promise<void>((resolve, reject) => {
    https.once('error', reject);
    https.listen(syncPort, '127.0.0.1', () => resolve());
  });

  try {
    const n = await executor.reapplyFirewallBlocks();
    if (n) log(`re-applied ${n} network blocks`);
  } catch (err) {
    log(`could not re-apply network blocks: ${(err as Error).message}`);
  }

  // Start osquery with Vigil's queries once it is installed, and keep it loaded.
  const osqueryPaths = opts.osquery ?? defaultOsqueryPaths();
  const keepOsquery = () => {
    if (!osqueryPaths || process.getuid?.() !== 0) return;
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
      ensureSyncTls(tls, opts.opensslBin)
        .then((changed) => {
          if (changed)
            https.setSecureContext({
              key: readFileSync(tls.serverKey),
              cert: readFileSync(tls.serverCert),
            });
        })
        .catch((err: Error) => log(`certificate renewal failed: ${err.message}`));
    },
    24 * 3600 * 1000,
  );
  renew.unref();

  log(`ready: socket ${paths.socket}, Santa sync on https://127.0.0.1:${syncPort}/`);

  return async () => {
    clearInterval(renew);
    clearInterval(osqueryTimer);
    await hub.stop();
    await server.close();
    await new Promise<void>((r) => https.close(() => r()));
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
