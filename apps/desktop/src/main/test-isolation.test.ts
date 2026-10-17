import { describe, expect, it } from 'vitest';
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { defaultPaths } from '@vigil/helper';
import {
  helperConnectFor,
  helperSocketFor,
  NO_HELPER_SOCKET,
  userDataFor,
} from './test-isolation.js';

const REAL = defaultPaths().socket;

describe('helperSocketFor', () => {
  it('always uses the installed helper in a packaged app', () => {
    expect(helperSocketFor(true, {})).toBe(REAL);
    expect(helperSocketFor(true, { VIGIL_HELPER_SOCKET: '/tmp/x.sock', VIGIL_E2E: '1' })).toBe(
      REAL,
    );
  });

  it('uses an isolated helper when a development build is given one', () => {
    expect(helperSocketFor(false, { VIGIL_HELPER_SOCKET: '/tmp/x.sock', VIGIL_E2E: '1' })).toBe(
      '/tmp/x.sock',
    );
  });

  it('keeps an e2e run off the installed helper unless it opted in', () => {
    expect(helperSocketFor(false, { VIGIL_E2E: '1' })).toBe(NO_HELPER_SOCKET);
    expect(helperSocketFor(false, { VIGIL_E2E: '1', VIGIL_ALLOW_REAL_ENFORCEMENT: 'true' })).toBe(
      NO_HELPER_SOCKET,
    );
    expect(helperSocketFor(false, { VIGIL_E2E: '1', VIGIL_ALLOW_REAL_ENFORCEMENT: '1' })).toBe(
      REAL,
    );
  });

  it('leaves plain development runs as they were', () => {
    expect(helperSocketFor(false, {})).toBe(REAL);
  });
});

describe('userDataFor', () => {
  it('takes a throwaway profile in development builds only', () => {
    expect(userDataFor(false, { VIGIL_USER_DATA: '/tmp/p' })).toBe('/tmp/p');
    expect(userDataFor(false, {})).toBeUndefined();
    expect(userDataFor(true, { VIGIL_USER_DATA: '/tmp/p' })).toBeUndefined();
  });
});

describe('helperConnectFor', () => {
  const env = { VIGIL_HELPER_SOCKET: '/tmp/x.sock', VIGIL_HELPER_APPROVALS: '/tmp/approvals' };

  it('keeps the normal password dialog unless a development build has an isolated helper', () => {
    expect(helperConnectFor(true, env)).toBeUndefined();
    expect(helperConnectFor(false, {})).toBeUndefined();
    expect(helperConnectFor(false, { VIGIL_HELPER_SOCKET: '/tmp/x.sock' })).toBeUndefined();
    expect(helperConnectFor(false, { VIGIL_HELPER_APPROVALS: '/tmp/approvals' })).toBeUndefined();
  });

  it("answers the isolated helper's password request in its approvals folder", async () => {
    const dir = mkdtempSync(join(tmpdir(), 'vigil-approve-'));
    const socket = join(dir, 'h.sock');
    const nonce = 'a'.repeat(32);
    // A helper that wants the password once, then checks the approval was written.
    const server = createServer((s) => {
      s.on('data', (d) => {
        const req = JSON.parse(d.toString().trim()) as { id: string; approval?: string };
        const reply = req.approval
          ? { id: req.id, ok: true, result: { approved: existsSync(join(dir, nonce)) } }
          : { id: req.id, ok: false, needsApproval: true, nonce, prompt: 'test' };
        s.write(JSON.stringify(reply) + '\n');
      });
    });
    await new Promise<void>((r) => server.listen(socket, r));
    try {
      const connect = helperConnectFor(false, {
        VIGIL_HELPER_SOCKET: socket,
        VIGIL_HELPER_APPROVALS: dir,
      })!;
      const client = await connect(socket);
      expect(await client.call({ kind: 'process.resume', pid: 5 })).toEqual({ approved: true });
      client.close();
    } finally {
      await new Promise<void>((r) => server.close(() => r()));
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
