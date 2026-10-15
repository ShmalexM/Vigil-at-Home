import { afterEach, describe, expect, it } from 'vitest';
import { chmodSync, existsSync, mkdtempSync, rmSync, utimesSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { APPROVAL_TTL_MS, Approvals, MAX_PENDING, approvalAppleScript } from './approval.js';
import type { HelperCommand } from './protocol.js';

const dirs: string[] = [];
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});
function make(now = () => Date.now()) {
  const dir = join(mkdtempSync(join(tmpdir(), 'vigil-appr-')), 'approvals');
  dirs.push(join(dir, '..'));
  return { dir, a: new Approvals({ dir, requiredOwnerUid: process.getuid!(), now }) };
}
const undo: HelperCommand = { kind: 'file.restore', quarantineId: 'a'.repeat(24) };

describe('approvals', () => {
  it('leaves a waiting approval alone when its nonce comes with another command', () => {
    const { dir, a } = make();
    const n = a.request(undo);
    const other: HelperCommand = { kind: 'file.restore', quarantineId: 'b'.repeat(24) };
    Approvals.writeApproval(dir, n);
    expect(a.consume(n, other)).toBe(false);
    expect(existsSync(join(dir, n))).toBe(true);
    expect(a.issuedFor(n, undo)).toBe(true);
    expect(a.consume(n, undo)).toBe(true);
  });

  it('keeps at most a fixed number waiting, dropping the oldest', () => {
    const { a } = make();
    const first = a.request(undo);
    const rest = Array.from({ length: MAX_PENDING }, () => a.request(undo));
    expect(a.issuedFor(first, undo)).toBe(false);
    expect(rest.every((n) => a.issuedFor(n, undo))).toBe(true);
  });

  it('accepts a matching approval file once', () => {
    const { dir, a } = make();
    const nonce = a.request(undo);
    Approvals.writeApproval(dir, nonce);
    expect(a.consume(nonce, undo)).toBe(true);
    expect(existsSync(join(dir, nonce))).toBe(false);
    expect(a.consume(nonce, undo)).toBe(false);
  });

  it('refuses without the file, for a different command, or an unissued nonce', () => {
    const { dir, a } = make();
    const n1 = a.request(undo);
    expect(a.consume(n1, undo)).toBe(false);
    const n2 = a.request(undo);
    Approvals.writeApproval(dir, n2);
    expect(a.consume(n2, { kind: 'file.restore', quarantineId: 'b'.repeat(24) })).toBe(false);
    const forged = 'c'.repeat(32);
    Approvals.writeApproval(dir, forged);
    expect(a.consume(forged, undo)).toBe(false);
  });

  it('refuses files owned by someone else or writable by others', () => {
    const { dir } = make();
    const strict = new Approvals({ dir, requiredOwnerUid: process.getuid!() + 1 });
    const n = strict.request(undo);
    Approvals.writeApproval(dir, n);
    expect(strict.consume(n, undo)).toBe(false);
    const { dir: d2, a } = make();
    const n2 = a.request(undo);
    writeFileSync(join(d2, n2), 'approved');
    chmodSync(join(d2, n2), 0o666);
    expect(a.consume(n2, undo)).toBe(false);
  });

  it('refuses stale approvals', () => {
    let t = Date.now();
    const { dir, a } = make(() => t);
    const n = a.request(undo);
    Approvals.writeApproval(dir, n);
    const old = (Date.now() - APPROVAL_TTL_MS - 10_000) / 1000;
    utimesSync(join(dir, n), old, old);
    expect(a.consume(n, undo)).toBe(false);
    const n2 = a.request(undo);
    Approvals.writeApproval(dir, n2);
    t += APPROVAL_TTL_MS + 1;
    expect(a.consume(n2, undo)).toBe(false);
  });

  it('builds a safe AppleScript and rejects injection', () => {
    const s = approvalAppleScript(
      '/Library/PrivilegedHelperTools/vigil-helper',
      'a'.repeat(32),
      'Undo "x"',
    );
    expect(s).toBe(
      `do shell script "'/Library/PrivilegedHelperTools/vigil-helper' approve ${'a'.repeat(32)}" with prompt "Undo \\"x\\"" with administrator privileges`,
    );
    expect(() => approvalAppleScript("/tmp/x'; rm -rf /; '", 'a'.repeat(32), 'p')).toThrow();
    expect(() => approvalAppleScript('/tmp/x', 'zz; reboot', 'p')).toThrow();
    // One password for several commands.
    expect(approvalAppleScript('/h', ['a'.repeat(32), 'b'.repeat(32)], 'p')).toContain(
      `'/h' approve ${'a'.repeat(32)} ${'b'.repeat(32)}"`,
    );
    expect(() => approvalAppleScript('/h', ['a'.repeat(32), 'zz; reboot'], 'p')).toThrow();
    expect(() => approvalAppleScript('/h', [], 'p')).toThrow();
  });
});
