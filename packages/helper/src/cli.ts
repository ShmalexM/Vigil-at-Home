#!/usr/bin/env node
// vigil-helper daemon            run the root daemon (launchd does this)
// vigil-helper approve <nonce>   record the user's approval; only works as root,
//                                i.e. after macOS's admin password dialog
// vigil-helper santa-profile     print the Santa configuration profile
// vigil-helper osquery-config    print the osquery configuration

import { osqueryConfig, santaProfile } from '@vigil/sensors';
import { Approvals } from './approval.js';
import { defaultPaths, SANTA_SYNC_PORT } from './config.js';
import { runDaemon } from './daemon.js';

async function main(argv: string[]): Promise<number> {
  const [cmd, arg] = argv;
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
      if (!arg || !/^[a-f0-9]{32}$/.test(arg)) {
        console.error('usage: vigil-helper approve <nonce>');
        return 2;
      }
      Approvals.writeApproval(defaultPaths().approvalsDir, arg);
      return 0;
    }
    case 'santa-profile':
      process.stdout.write(santaProfile({ syncPort: SANTA_SYNC_PORT }));
      return 0;
    case 'osquery-config':
      process.stdout.write(osqueryConfig());
      return 0;
    default:
      console.error(
        'usage: vigil-helper daemon | approve <nonce> | santa-profile | osquery-config',
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
