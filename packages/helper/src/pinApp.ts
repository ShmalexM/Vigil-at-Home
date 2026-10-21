// `vigil-helper pin-app <path>`, run by install.sh once the helper has
// stopped (appPin.ts). Like pin-remove it is a root command line only, and it
// refuses while the daemon answers on its socket: the daemon keeps its own
// pin in memory, so pinning under it would be undone or lost.
//
// It always signs new files with the key it loads (or makes): first "no
// pin", then the app's pin if it has one. So a helper update replaces pin
// and generation files the helper ignores, whatever made them (another key,
// two installs at once, a backup put back), and that is how they are ever
// replaced: the daemon reports them and the app asks for this update.

import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { pinFor } from './appPin.js';
import { AppPinStore } from './pinStore.js';
import { daemonAnswers } from './socketProbe.js';
import type { System } from './system.js';

export interface PinAppOptions {
  /** process.geteuid() of the command. */
  euid: number | undefined;
  socket: string;
  /** config appPinDir and appPin. */
  dir: string;
  publicFile: string;
  sys: System;
  /** The app to pin, as install.sh names it. */
  target: string;
  /** The installer's folders (config installedSelf): an app there is never pinned. */
  installed: readonly string[];
  /** uid that must own the pin folder and key; root's, but for tests. */
  ownerUid?: number;
  error?: (msg: string) => void;
}

/** The exit code: 0 once the pin (or "no pin") is signed and in place. */
export async function pinApp(opts: PinAppOptions): Promise<number> {
  const error = opts.error ?? ((m: string) => console.error(m));
  if (opts.euid !== 0) {
    error('pin-app must run as root (install.sh runs it)');
    return 1;
  }
  if (await daemonAnswers(opts.socket)) {
    error('the helper is running; stop it before pin-app (install.sh does)');
    return 1;
  }
  mkdirSync(dirname(opts.dir), { recursive: true, mode: 0o755 });
  const store = new AppPinStore(opts.sys, {
    dir: opts.dir,
    publicFile: opts.publicFile,
    ...(opts.ownerUid !== undefined ? { ownerUid: opts.ownerUid } : {}),
  });
  await store.load();
  // Whatever happens, an older app's pin doesn't outlive this install.
  await store.write(undefined);
  const pin = await pinFor(opts.sys, opts.target, { installed: opts.installed });
  if (pin) await store.write(pin);
  return 0;
}
