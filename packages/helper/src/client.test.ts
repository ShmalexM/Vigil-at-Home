import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { createServer, type Server } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  approvalOpen,
  HelperClient,
  isExecDenied,
  pkexecApprover,
  SHELL_BLOCKED,
  ShellBlockedError,
  shellBlocked,
  type Approver,
} from './client.js';

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

  it('says why when the dialog could not run because Santa blocks /bin/sh', async () => {
    const approver: Approver = () => Promise.reject(new ShellBlockedError());
    const client = await HelperClient.connect(socket(), approver);
    try {
      const held = client.hold({ kind: 'process.resume', pid: 43 } as never);
      await new Promise((r) => setTimeout(r, 50));
      const call = client.call({ kind: 'process.resume', pid: 42 } as never);
      // Not "not approved": the words that tell the user how to get out.
      await expect(call).rejects.toMatchObject({ code: 'refused', message: SHELL_BLOCKED });
      await expect(held).rejects.toMatchObject({ code: 'refused', message: SHELL_BLOCKED });
      expect(approvedSends).toEqual([]);
    } finally {
      client.close();
    }
  });
});

describe('a blocked /bin/sh', () => {
  it('is an exec refused with EPERM or EACCES, nothing else', () => {
    const err = (code: string) => Object.assign(new Error(code), { code });
    expect(isExecDenied(err('EPERM'))).toBe(true);
    expect(isExecDenied(err('EACCES'))).toBe(true);
    expect(isExecDenied(err('ENOENT'))).toBe(false);
    // A non-zero exit has a numeric code: the shell ran.
    expect(isExecDenied(Object.assign(new Error('exit'), { code: 1 }))).toBe(false);
    expect(isExecDenied(null)).toBe(false);
  });

  it('is only looked for on macOS', async () => {
    await expect(shellBlocked('linux')).resolves.toBe(false);
    if (process.platform === 'darwin')
      await expect(shellBlocked('darwin')).resolves.toBeTypeOf('boolean');
  });
});
