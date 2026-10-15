// Whether the daemon is up, for commands that must not run beside it
// (cli.ts pin-app). The daemon holds its socket for as long as it runs, so
// a connection that is accepted, or one that hangs, counts as up.

import { createConnection } from 'node:net';

export function daemonAnswers(socket: string, timeoutMs = 2000): Promise<boolean> {
  return new Promise((resolve) => {
    const c = createConnection(socket);
    const done = (up: boolean) => {
      clearTimeout(t);
      c.destroy();
      resolve(up);
    };
    const t = setTimeout(() => done(true), timeoutMs);
    c.once('connect', () => done(true));
    c.once('error', () => done(false));
  });
}
