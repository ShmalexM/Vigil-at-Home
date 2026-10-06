import { spawn } from 'node:child_process';
import { accessSync, constants } from 'node:fs';

/**
 * Terminal programs Linux desktops ship, most general first: Debian's
 * alternatives link, then GNOME (Console, Ptyxis, the older Terminal), KDE,
 * Xfce and xterm.
 */
export const LINUX_TERMINALS = [
  '/usr/bin/x-terminal-emulator',
  '/usr/bin/kgx',
  '/usr/bin/ptyxis',
  '/usr/bin/gnome-terminal',
  '/usr/bin/konsole',
  '/usr/bin/xfce4-terminal',
  '/usr/bin/xterm',
];

const runnable = (path: string) => {
  try {
    accessSync(path, constants.X_OK);
    return true;
  } catch {
    return false;
  }
};

/** The first terminal this Linux computer has, or undefined. */
export function linuxTerminal(
  isRunnable: (path: string) => boolean = runnable,
): string | undefined {
  return LINUX_TERMINALS.find(isRunnable);
}

/** Open a terminal window on Linux; false when none was found. */
export function openLinuxTerminal(): boolean {
  const term = linuxTerminal();
  if (!term) return false;
  spawn(term, [], { detached: true, stdio: 'ignore' }).unref();
  return true;
}
