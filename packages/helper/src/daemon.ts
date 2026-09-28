// The root daemon launchd starts at boot. It wires together:
//   - the command socket the app talks to (HelperServer + Executor)
//   - Santa's sync server over pinned HTTPS on 127.0.0.1
//   - the log sensors (Santa's event log, osquery results), streamed to the app
//
//   Santa ──santa.log──┐                        ┌── socket ──► Vigil app (popup, rules, AI)
//   osquery ──results──┼─► SensorHub ─► publish ┤
//   Santa ──sync HTTPS─┘   (blocks it made)     └── commands ◄── Vigil app
//         ◄── rules ─── RuleStore ◄── santa.block / santa.allow

import { createServer as createHttpsServer, type Server as HttpsServer } from 'node:https';
import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import {
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
import { HelperServer } from './server.js';
import { realSystem, type System } from './system.js';

export interface DaemonOptions {
  paths?: HelperPaths;
  syncPort?: number;
  sys?: System;
  log?: (msg: string) => void;
  /** Owner required on approval files; only tests change this from root. */
  approvalOwnerUid?: number;
  opensslBin?: string;
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

  const tls = syncTlsPaths(paths.tlsDir);
  await ensureSyncTls(tls, opts.opensslBin);

  // Vigil owns this policy file; Santa re-reads it every minute.
  if (!existsSync(paths.fileAccessPolicy)) {
    mkdirSync(dirname(paths.fileAccessPolicy), { recursive: true });
    writeFileSync(paths.fileAccessPolicy, fileAccessPolicy(), { mode: 0o644 });
  }

  const rules = new RuleStore(paths.santaRules);
  const journal = new Journal(paths.journal);
  const approvals = new Approvals({
    dir: paths.approvalsDir,
    requiredOwnerUid: opts.approvalOwnerUid ?? 0,
  });
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
    onError: (source, err) => log(`${source} sensor: ${err.message}`),
  });
  await hub.start();

  const sync = new SantaSyncServer({
    store: rules,
    onEvent: (e) => hub.emit(e),
    log,
    eventDetailUrl: 'vigil://santa/event?sha256=%file_sha%',
    eventDetailText: 'Open Vigil',
  });
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
    await hub.stop();
    await server.close();
    await new Promise<void>((r) => https.close(() => r()));
  };
}
