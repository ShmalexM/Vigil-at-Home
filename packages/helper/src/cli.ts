#!/usr/bin/env node
// vigil-helper daemon            run the root daemon (launchd does this)
// vigil-helper approve <nonce>…  record the user's approval; only works as root,
//                                i.e. after the admin password dialog (osascript
//                                on macOS, pkexec on Linux)
// vigil-helper santa-profile     print the Santa configuration profile
// vigil-helper osquery-config    print the osquery configuration
// vigil-helper osquery-flags     print osquery's startup flags (osquery.flags)
// vigil-helper osquery-setup     (root) write Vigil's osquery config and start osquery
// vigil-helper osquery-remove    (root) stop Vigil's osquery job, restore osquery's old config
// vigil-helper pin-app <path>    (root) pin the app the helper is installed for (appPin.ts):
//                                its main executable on macOS, its AppImage on Linux
// vigil-helper fs-child          one file operation as a user, for the daemon (commands/fsChild.ts)

import {
  osqueryConfig,
  osqueryFlags,
  osqueryLinuxConfig,
  osqueryLinuxFlags,
  santaProfile,
} from '@vigil/sensors';
import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { Approvals } from './approval.js';
import { pinFor } from './appPin.js';
import { AppPinStore } from './pinStore.js';
import { runFsChild } from './commands/fsChild.js';
import { daemonAnswers } from './socketProbe.js';
import { defaultPaths, installedSelf, SANTA_SYNC_PORT } from './config.js';
import { runDaemon } from './daemon.js';
import { ensureOsquery, removeOsquery } from './osquery.js';
import { ensureLinuxOsquery, removeLinuxOsquery } from './linuxOsquery.js';
import { hostPlatform } from './platform.js';
import { realSystem } from './system.js';

async function main(argv: string[]): Promise<number> {
  const [cmd, arg, ...more] = argv;
  switch (cmd) {
    case 'fs-child':
      // One file operation as a user, started by the daemon (commands/fsChild.ts).
      return runFsChild();
    case 'daemon': {
      const stop = await runDaemon();
      const shutdown = () => {
        stop().finally(() => process.exit(0));
      };
      process.on('SIGTERM', shutdown);
      process.on('SIGINT', shutdown);
      return new Promise<number>(() => {});
    }
    case 'approve': {
      if (process.getuid?.() !== 0) {
        console.error('approve must run as root (through the admin password dialog)');
        return 1;
      }
      // One password can approve several commands, each by its own nonce.
      const nonces = arg ? [arg, ...more] : [];
      if (
        nonces.length === 0 ||
        nonces.length > 8 ||
        !nonces.every((n) => /^[a-f0-9]{32}$/.test(n))
      ) {
        console.error('usage: vigil-helper approve <nonce>…');
        return 2;
      }
      for (const n of nonces) Approvals.writeApproval(defaultPaths().approvalsDir, n);
      return 0;
    }
    case 'santa-profile':
      process.stdout.write(santaProfile({ syncPort: SANTA_SYNC_PORT }));
      return 0;
    case 'osquery-config':
      process.stdout.write(hostPlatform() === 'linux' ? osqueryLinuxConfig() : osqueryConfig());
      return 0;
    case 'osquery-flags':
      process.stdout.write(hostPlatform() === 'linux' ? osqueryLinuxFlags() : osqueryFlags());
      return 0;
    case 'osquery-setup':
    case 'osquery-remove': {
      if (process.getuid?.() !== 0) {
        console.error(`${cmd} must run as root`);
        return 1;
      }
      const linux = hostPlatform() === 'linux';
      if (cmd === 'osquery-remove')
        await (linux ? removeLinuxOsquery(realSystem()) : removeOsquery(realSystem()));
      else
        console.log(
          `osquery: ${await (linux ? ensureLinuxOsquery(realSystem()) : ensureOsquery(realSystem()))}`,
        );
      return 0;
    }
    case 'pin-app': {
      if (process.getuid?.() !== 0) {
        console.error('pin-app must run as root (install.sh runs it)');
        return 1;
      }
      if (!arg || more.length) {
        console.error('usage: vigil-helper pin-app <path>');
        return 2;
      }
      const sys = realSystem();
      const paths = defaultPaths();
      // The daemon keeps its own pin in memory; pinning under it would be undone or lost.
      if (await daemonAnswers(paths.socket)) {
        console.error('the helper is running; stop it before pin-app (install.sh does)');
        return 1;
      }
      mkdirSync(dirname(paths.appPinDir), { recursive: true, mode: 0o755 });
      const store = new AppPinStore(sys, { dir: paths.appPinDir, publicFile: paths.appPin });
      await store.load();
      // Whatever happens, an older app's pin doesn't outlive this install.
      await store.write(undefined);
      const pin = await pinFor(sys, arg, { installed: installedSelf(sys.platform) });
      if (pin) await store.write(pin);
      return 0;
    }
    default:
      console.error(
        'usage: vigil-helper daemon | approve <nonce>… | santa-profile | osquery-config | ' +
          'osquery-flags | osquery-setup | osquery-remove | pin-app <path>',
      );
      return 2;
  }
}

main(process.argv.slice(2)).then(
  (code) => process.exit(code),
  (err: Error) => {
    console.error(err.stack ?? err.message);
    process.exit(1);
  },
);
