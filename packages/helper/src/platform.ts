// Which operating system the helper is acting on. Everything OS-specific
// (binaries, protected paths, the firewall, startup items) is chosen from
// this, never from process.platform deep inside a command, so tests can run
// the macOS code on a Linux CI runner and the Linux code on a Mac.

export type Platform = 'darwin' | 'linux';

/** The platform this process runs on. Anything that isn't Linux is treated as macOS. */
export function hostPlatform(): Platform {
  return process.platform === 'linux' ? 'linux' : 'darwin';
}
