import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { execFileWithin } from './execWithin';
import { JsonRpcStdio } from './providers/jsonRpcStdio';

/** A child that ignores SIGTERM, answers nothing and prints its pid. */
const STUBBORN = `process.on('SIGTERM', () => {}); console.log(process.pid); setInterval(() => {}, 1000);`;

function alive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

const handlers = { onRequest: async () => null, onNotification: () => {} };

describe('bounded outside calls', () => {
  it('execFileWithin answers at its limit and kills a program that ignores SIGTERM', async () => {
    const started = Date.now();
    const pidFile = join(mkdtempSync(join(tmpdir(), 'vigil-exec-')), 'pid');
    const r = await execFileWithin(
      process.execPath,
      [
        '-e',
        `require('fs').writeFileSync(${JSON.stringify(pidFile)}, String(process.pid)); ${STUBBORN}`,
      ],
      300,
    );
    expect(r.timedOut).toBe(true);
    expect(Date.now() - started).toBeLessThan(1_500);
    const pid = Number(readFileSync(pidFile, 'utf8'));
    expect(pid).toBeGreaterThan(0);
    await new Promise((r) => setTimeout(r, 2_500));
    expect(alive(pid)).toBe(false);
  }, 10_000);

  it('execFileWithin returns a normal exit as before', async () => {
    const r = await execFileWithin(process.execPath, ['-e', 'console.log("hi")'], 5_000);
    expect(r).toEqual({ code: 0, stdout: 'hi\n', stderr: '', timedOut: false });
  });

  it('a JSON-RPC request with no answer fails at its limit', async () => {
    const rpc = new JsonRpcStdio(process.execPath, ['-e', STUBBORN], {}, process.cwd(), handlers);
    const started = Date.now();
    await expect(rpc.request('thread/start', {}, 300)).rejects.toThrow(
      'thread/start did not answer',
    );
    expect(Date.now() - started).toBeLessThan(1_500);
    rpc.close();
  });

  it('closing fails waiting requests at once and kills a server that ignores SIGTERM', async () => {
    const rpc = new JsonRpcStdio(
      process.execPath,
      [
        '-e',
        STUBBORN.replace('console.log(process.pid)', 'process.stderr.write(String(process.pid))'),
      ],
      {},
      process.cwd(),
      handlers,
    );
    await new Promise((r) => setTimeout(r, 300));
    const pid = Number(rpc.stderr.join(''));
    expect(alive(pid)).toBe(true);
    const waiting = rpc.request('turn/start', {}, 60_000);
    rpc.close();
    await expect(waiting).rejects.toThrow('closed');
    await expect(rpc.request('turn/start', {}, 60_000)).rejects.toThrow('closed');
    await new Promise((r) => setTimeout(r, 2_500));
    expect(alive(pid)).toBe(false);
  }, 10_000);

  it('a server that died is a failed request, not a crash', async () => {
    const rpc = new JsonRpcStdio(
      '/bin/sh',
      ['-c', 'exec 0<&-; sleep 1'], // closes its input and stays up a moment
      {},
      process.cwd(),
      handlers,
    );
    await new Promise((r) => setTimeout(r, 200));
    for (let i = 0; i < 20; i++) rpc.notify('initialized', { pad: 'x'.repeat(65_536) });
    await expect(rpc.request('thread/start', {}, 1_000)).rejects.toThrow();
    await new Promise((r) => setTimeout(r, 100)); // an EPIPE would surface as an unhandled error here
  });
});
