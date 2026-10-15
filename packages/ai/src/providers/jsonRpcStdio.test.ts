import { describe, expect, it } from 'vitest';
import { JsonRpcStdio } from './jsonRpcStdio.js';

const handlers = { onRequest: async () => null, onNotification: () => {} };

function alive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

describe('JsonRpcStdio', () => {
  it('stops a server that never answers once a request times out', async () => {
    // A server that prints its pid, then reads requests and never answers.
    const rpc = new JsonRpcStdio(
      process.execPath,
      ['-e', 'console.error(process.pid); process.stdin.resume(); setInterval(() => {}, 1000)'],
      { PATH: process.env['PATH'] ?? '' },
      process.cwd(),
      handlers,
    );
    await expect(rpc.request('initialize', {}, 300)).rejects.toThrow(/did not answer/);
    const pid = Number(rpc.stderr.join('').trim());
    expect(pid).toBeGreaterThan(0);
    for (let i = 0; i < 50 && alive(pid); i++) await new Promise((r) => setTimeout(r, 20));
    expect(alive(pid)).toBe(false);
    // Later requests fail at once rather than waiting.
    await expect(rpc.request('account/read', {}, 300)).rejects.toThrow(/did not answer/);
  });

  it('answers in time without stopping the server', async () => {
    const rpc = new JsonRpcStdio(
      process.execPath,
      [
        '-e',
        `require('readline').createInterface({ input: process.stdin }).on('line', (l) => {
          const m = JSON.parse(l); console.log(JSON.stringify({ id: m.id, result: { ok: true } }));
        });`,
      ],
      { PATH: process.env['PATH'] ?? '' },
      process.cwd(),
      handlers,
    );
    expect(await rpc.request('a', {}, 2_000)).toEqual({ ok: true });
    expect(await rpc.request('b', {}, 2_000)).toEqual({ ok: true });
    rpc.close();
  });
});
