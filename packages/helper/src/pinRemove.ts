// `vigil-helper pin-remove`, run by the uninstallers once the helper has
// stopped. Like pin-app it is a root command line only: it is not one of
// the socket's commands (protocol.ts), it refuses unless the effective user
// is root, and it refuses while the daemon answers on its socket, which
// keeps the pin in memory and would only put it back.

import { daemonAnswers } from './socketProbe.js';
import { removePinStore } from './pinStore.js';
import type { System } from './system.js';

export interface PinRemoveOptions {
  /** process.geteuid() of the command. */
  euid: number | undefined;
  socket: string;
  /** config appPinDir and appPin. */
  dir: string;
  publicFile: string;
  sys: System;
  error?: (msg: string) => void;
}

/** The exit code: 0 once the pin folder and its copy are gone. */
export async function pinRemove(opts: PinRemoveOptions): Promise<number> {
  const error = opts.error ?? ((m: string) => console.error(m));
  if (opts.euid !== 0) {
    error('pin-remove must run as root (uninstall.sh runs it)');
    return 1;
  }
  if (await daemonAnswers(opts.socket)) {
    error('the helper is running; stop it before pin-remove (uninstall.sh does)');
    return 1;
  }
  await removePinStore(opts.sys, opts.dir, opts.publicFile);
  return 0;
}
