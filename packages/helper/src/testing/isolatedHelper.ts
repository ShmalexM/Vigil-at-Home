// A whole helper daemon for tests that touches nothing on the machine: its
// own socket, state folder and approvals folder under a fresh temporary
// folder, and FakeSystem (fakeSystem.ts) in place of pf, Santa, launchd and
// signals. The e2e harness (apps/desktop/e2e/harness.mjs) points the app at
// its socket, so the app runs its real helper path with nothing enforced.

import { mkdtempSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Approvals } from '../approval.js';
import type { Approver } from '../client.js';
import { defaultPaths, type HelperPaths } from '../config.js';
import { runDaemon } from '../daemon.js';
import { FakeSystem } from './fakeSystem.js';

export interface IsolatedHelper {
  /** The temporary folder everything lives in; removed by stop(). */
  root: string;
  paths: HelperPaths;
  socket: string;
  /** What the helper "did": pf table, signals, launchctl and the rest. */
  sys: FakeSystem;
  /** Answers the password dialog for this helper, as `approve` decides. */
  approver: (approve?: () => boolean) => Approver;
  stop(): Promise<void>;
}

export interface IsolatedHelperOptions {
  /** Parent of the temporary folder; the OS temp folder by default. */
  parent?: string;
  log?: (msg: string) => void;
}

/** A port nothing listens on now, for the helper's Santa sync server. */
async function freePort(): Promise<number> {
  const server = createServer();
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address() as { port: number };
  await new Promise<void>((resolve) => server.close(() => resolve()));
  return port;
}

export async function startIsolatedHelper(
  opts: IsolatedHelperOptions = {},
): Promise<IsolatedHelper> {
  // The real path: the helper compares paths as written, and tmpdir is a link on macOS.
  const root = realpathSync(mkdtempSync(join(opts.parent ?? tmpdir(), 'vigil-e2e-')));
  const paths: HelperPaths = {
    ...defaultPaths(join(root, 'support')),
    approvalsDir: join(root, 'approvals'),
    socket: join(root, 'helper.sock'),
    santaLog: join(root, 'santa.log'),
    osqueryResults: join(root, 'osquery.log'),
    helperExecutable: join(root, 'vigil-helper'),
  };
  writeFileSync(paths.santaLog as string, '');
  writeFileSync(paths.osqueryResults as string, '');
  const sys = new FakeSystem();
  // Handing the socket to the console user needs root; otherwise it stays ours.
  sys.console = process.getuid?.() === 0 ? 501 : undefined;
  const stopDaemon = await runDaemon({
    paths,
    syncPort: await freePort(),
    sys,
    log: opts.log ?? (() => {}),
    approvalOwnerUid: process.getuid?.() ?? 0,
    opensslBin: 'openssl',
    sensorBinaries: { santa: false, osquery: join(root, 'no-osqueryd') },
    osquery: false,
    ownProgramRoots: [],
    osProgramRoots: [],
  });
  return {
    root,
    paths,
    socket: paths.socket,
    sys,
    approver:
      (approve = () => true) =>
      async (nonce, _prompt, also = []) => {
        if (!approve()) return false;
        for (const n of [nonce, ...also]) Approvals.writeApproval(paths.approvalsDir, n);
        return true;
      },
    async stop() {
      await stopDaemon();
      rmSync(root, { recursive: true, force: true });
    },
  };
}
