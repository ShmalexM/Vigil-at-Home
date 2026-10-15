import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { createServer, type Server } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { approvalOpen, HelperClient, pkexecApprover, type Approver } from './client.js';

const NONCE = 'a'.repeat(32);

let dir: string;

beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), 'vigil-client-'));
});

afterAll(() => {
  rmSync(dir, { recursive: true, force: true });
});

describe('password dialogs', () => {
  it('counts an open dialog and closes it, as a no, when the caller stops waiting', async () => {
    // Stands in for pkexec: a dialog the user never answers.
    const dialog = join(dir, 'dialog.sh');
    writeFileSync(dialog, '#!/bin/sh\nexec sleep 30\n');
    chmodSync(dialog, 0o755);
    const ask = pkexecApprover('/usr/local/bin/vigil-helper', dialog);
    const c = new AbortController();
    const answer = ask(NONCE, 'Release it?', [], c.signal);
    expect(approvalOpen()).toBe(true);
    c.abort();
    await expect(answer).resolves.toBe(false);
    expect(approvalOpen()).toBe(false);
  });

  it('counts nothing open when the dialog program refuses to start', async () => {
    // A NUL in an argument makes execFile throw before anything runs.
    const ask = pkexecApprover('/usr/local/bin/vigil-helper', '/bin/true\u0000');
    await expect(ask(NONCE, 'x')).resolves.toBe(false);
    expect(approvalOpen()).toBe(false);
  });

  it('a yes counts while nobody gave up', async () => {
    const dialog = join(dir, 'yes.sh');
    writeFileSync(dialog, '#!/bin/sh\nexit 0\n');
    chmodSync(dialog, 0o755);
    await expect(pkexecApprover('/usr/local/bin/vigil-helper', dialog)(NONCE, 'ok')).resolves.toBe(
      true,
    );
    expect(approvalOpen()).toBe(false);
  });
});

describe('HelperClient.call with a signal', () => {
  let server: Server;
  const socket = () => join(dir, 'helper.sock');
  /** Commands the fake helper got with an approval attached. */
  const approvedSends: unknown[] = [];

  beforeAll(async () => {
    server = createServer((s) => {
      s.setEncoding('utf8');
      let buf = '';
      s.on('data', (chunk: string) => {
        buf += chunk;
        let nl: number;
        while ((nl = buf.indexOf('\n')) >= 0) {
          const msg = JSON.parse(buf.slice(0, nl)) as { id: string; approval?: string };
          buf = buf.slice(nl + 1);
          if (msg.approval) {
            approvedSends.push(msg);
            s.write(JSON.stringify({ id: msg.id, ok: true, result: {} }) + '\n');
          } else {
            s.write(
              JSON.stringify({
                id: msg.id,
                ok: false,
                needsApproval: true,
                nonce: NONCE,
                prompt: 'Release it?',
              }) + '\n',
            );
          }
        }
      });
    });
    await new Promise<void>((r) => server.listen(socket(), r));
  });

  afterAll(() => {
    server.close();
  });

  it('treats an answer that comes after the caller gave up as a no, and sends nothing', async () => {
    let answer: (yes: boolean) => void = () => {};
    let seen: AbortSignal | undefined;
    const approver: Approver = (_n, _p, _a, signal) => {
      seen = signal;
      return new Promise((r) => (answer = r));
    };
    const client = await HelperClient.connect(socket(), approver);
    const stop = new AbortController();
    try {
      const call = client.call({ kind: 'process.resume', pid: 42 } as never, stop.signal);
      await new Promise((r) => setTimeout(r, 50));
      expect(seen?.aborted).toBe(false);
      stop.abort();
      expect(seen?.aborted).toBe(true);
      // The user's yes lands just after the app stopped waiting.
      answer(true);
      await expect(call).rejects.toMatchObject({ code: 'refused' });
      expect(approvedSends).toEqual([]);
    } finally {
      client.close();
    }
  });
});
