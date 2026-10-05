// Real-Linux checks: run as root with VIGIL_LINUX_INTEGRATION=1, e.g.
//   sudo VIGIL_LINUX_INTEGRATION=1 pnpm vitest run packages/helper/src/linux.integration.test.ts
// They load real nftables rules and signal real processes, so they are
// skipped everywhere else.

import { afterAll, describe, expect, it } from 'vitest';
import { spawn } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { createServer, connect, type Server } from 'node:net';
import { networkInterfaces } from 'node:os';
import { identifyProcess, killProcess, suspendProcess } from './commands/process.js';
import { NftFirewall } from './commands/nftables.js';
import { LINUX_BINARIES, realSystem } from './system.js';

const run = process.env.VIGIL_LINUX_INTEGRATION === '1' && process.platform === 'linux';
const sys = realSystem(LINUX_BINARIES, 'linux');

/** This machine's first non-loopback IPv4 address: traffic to it still passes the output and input hooks. */
function localAddress(): string | undefined {
  for (const list of Object.values(networkInterfaces())) {
    for (const a of list ?? []) if (a.family === 'IPv4' && !a.internal) return a.address;
  }
  return undefined;
}

function reachable(host: string, port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const s = connect({ host, port, timeout: 1500 });
    s.once('connect', () => {
      s.destroy();
      resolve(true);
    });
    s.once('timeout', () => {
      s.destroy();
      resolve(false);
    });
    s.once('error', () => resolve(false));
  });
}

describe.skipIf(!run)('helper on real Linux', () => {
  const fw = new NftFirewall(sys);
  let server: Server | undefined;

  afterAll(async () => {
    await fw.release();
    server?.close();
  });

  it('pauses and stops a process found through /proc', async () => {
    const child = spawn('/usr/bin/sleep', ['30']);
    await new Promise((r) => setTimeout(r, 200));
    const pid = child.pid!;
    const id = await identifyProcess(sys, pid);
    expect(id?.path).toBe('/usr/bin/sleep');
    await suspendProcess(sys, pid, { path: '/usr/bin/sleep' });
    await new Promise((r) => setTimeout(r, 100));
    // Field 3 of /proc/<pid>/stat is the state; T means stopped.
    expect(readFileSync(`/proc/${pid}/stat`, 'utf8').split(') ')[1]![0]).toBe('T');
    await expect(suspendProcess(sys, pid, { path: '/usr/bin/other' })).rejects.toMatchObject({
      code: 'refused',
    });
    const exited = new Promise((r) => child.once('exit', (_code, sig) => r(sig)));
    await killProcess(sys, pid, { path: '/usr/bin/sleep' });
    expect(await exited).toBe('SIGKILL');
  });

  it('drops traffic to a blocked address and lets it through again on unblock', async () => {
    const host = localAddress();
    expect(host, 'needs a non-loopback IPv4 address').toBeDefined();
    server = createServer((s) => s.end());
    await new Promise<void>((r) => server!.listen(0, host, () => r()));
    const port = (server.address() as { port: number }).port;

    expect(await reachable(host!, port)).toBe(true);
    expect(await fw.block(host!)).toBe(host);
    expect(await fw.list()).toEqual([host]);
    expect(await reachable(host!, port)).toBe(false);
    await fw.unblock(host!);
    expect(await fw.list()).toEqual([]);
    expect(await reachable(host!, port)).toBe(true);
  });
});
