#!/usr/bin/env node
// vigil-helper daemon            run the root daemon (launchd does this)
// vigil-helper approve <nonce>…  record the user's approval; only works as root,
//                                i.e. after macOS's admin password dialog
// vigil-helper santa-profile     print the Santa configuration profile
// vigil-helper osquery-config    print the osquery configuration
// vigil-helper osquery-flags     print osquery's startup flags (osquery.flags)
// vigil-helper osquery-setup     (root) write Vigil's osquery config and start osquery
// vigil-helper osquery-remove    (root) stop Vigil's osquery job, restore osquery's old config

import { osqueryConfig, osqueryFlags, santaProfile } from '@vigil/sensors';
import { Approvals } from './approval.js';
import { defaultPaths, SANTA_SYNC_PORT } from './config.js';
import { runDaemon } from './daemon.js';
import { ensureOsquery, removeOsquery } from './osquery.js';
import { realSystem } from './system.js';

async function main(argv: string[]): Promise<number> {
  const [cmd, arg, ...more] = argv;
  switch (cmd) {
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
        console.error('approve must run as root (through the macOS password dialog)');
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
      process.stdout.write(osqueryConfig());
      return 0;
    case 'osquery-flags':
      process.stdout.write(osqueryFlags());
      return 0;
    case 'osquery-setup':
    case 'osquery-remove': {
      if (process.getuid?.() !== 0) {
        console.error(`${cmd} must run as root`);
        return 1;
      }
      if (cmd === 'osquery-remove') await removeOsquery(realSystem());
      else console.log(`osquery: ${await ensureOsquery(realSystem())}`);
      return 0;
    }
    default:
      console.error(
        'usage: vigil-helper daemon | approve <nonce>… | santa-profile | osquery-config | ' +
          'osquery-flags | osquery-setup | osquery-remove',
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
