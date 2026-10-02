// Releasing a block or allowing a program needs proof that the person at the
// keyboard typed their macOS admin password, not just a request from the app
// (malware running as the user can send the app's requests too).
//
//   app ──undo──► helper: needs approval, nonce N (bound to this exact command)
//   app runs:  osascript 'do shell script "<helper> approve N" with administrator privileges'
//              macOS shows its own password dialog; only a correct password runs it as root
//   <helper> approve N  ──► writes approvals/N, owned by root, containing the command hash
//   app ──undo + approval N──► helper checks the file is root-owned, fresh and matches, deletes it, acts
//
// Something running as the user cannot create a root-owned file, so it cannot
// fake the approval without the password.

import { createHash, randomBytes } from 'node:crypto';
import { lstatSync, mkdirSync, readFileSync, rmSync, writeFileSync, chmodSync } from 'node:fs';
import { join } from 'node:path';
import type { HelperCommand } from './protocol.js';

export const APPROVAL_TTL_MS = 2 * 60 * 1000;

export function commandHash(cmd: HelperCommand): string {
  // Stable key order so the same command always hashes the same.
  const ordered = Object.fromEntries(Object.entries(cmd).sort(([a], [b]) => a.localeCompare(b)));
  return createHash('sha256').update(JSON.stringify(ordered)).digest('hex');
}

interface Pending {
  hash: string;
  expiresAt: number;
}

export interface ApprovalOptions {
  dir: string;
  /** uid that must own approval files. 0 in production; the test's own uid in tests. */
  requiredOwnerUid?: number;
  now?: () => number;
}

export class Approvals {
  private readonly pending = new Map<string, Pending>();
  private readonly now: () => number;
  private readonly owner: number;

  constructor(private readonly opts: ApprovalOptions) {
    this.now = opts.now ?? Date.now;
    this.owner = opts.requiredOwnerUid ?? 0;
    mkdirSync(opts.dir, { recursive: true, mode: 0o700 });
    chmodSync(opts.dir, 0o700);
  }

  /** Start an approval for this command. Returns the nonce the app passes to `approve`. */
  request(cmd: HelperCommand): string {
    this.sweep();
    const nonce = randomBytes(16).toString('hex');
    this.pending.set(nonce, { hash: commandHash(cmd), expiresAt: this.now() + APPROVAL_TTL_MS });
    return nonce;
  }

  /** Called by `vigil-helper approve <nonce>`, which only runs as root after the password dialog. */
  static writeApproval(dir: string, nonce: string): void {
    if (!/^[a-f0-9]{32}$/.test(nonce)) throw new Error('bad nonce');
    // wx: never follow or overwrite something already at that path.
    writeFileSync(join(dir, nonce), 'approved', { mode: 0o600, flag: 'wx' });
  }

  /**
   * True if `nonce` was issued for exactly this command, has not expired, and
   * a root-owned approval file exists for it. Single use either way.
   */
  consume(nonce: string, cmd: HelperCommand): boolean {
    this.sweep();
    const p = this.pending.get(nonce);
    const file = join(this.opts.dir, nonce);
    try {
      if (!p || p.hash !== commandHash(cmd)) return false;
      const st = lstatSync(file);
      if (!st.isFile() || st.uid !== this.owner || (st.mode & 0o022) !== 0) return false;
      if (this.now() - st.mtimeMs > APPROVAL_TTL_MS) return false;
      readFileSync(file); // must be readable by us
      return true;
    } catch {
      return false;
    } finally {
      this.pending.delete(nonce);
      rmSync(file, { force: true });
    }
  }

  private sweep(): void {
    const t = this.now();
    for (const [n, p] of this.pending) if (p.expiresAt < t) this.pending.delete(n);
  }
}

/**
 * The AppleScript the app runs to show macOS's own admin password dialog.
 * Several nonces approve several commands with one password.
 */
export function approvalAppleScript(
  helperPath: string,
  nonce: string | string[],
  prompt: string,
): string {
  const nonces = typeof nonce === 'string' ? [nonce] : nonce;
  if (nonces.length === 0 || !nonces.every((n) => /^[a-f0-9]{32}$/.test(n)))
    throw new Error('bad nonce');
  if (!/^\/[A-Za-z0-9 ._/-]+$/.test(helperPath)) throw new Error('bad helper path');
  const esc = (s: string) => s.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
  const shell = `'${helperPath}' approve ${nonces.join(' ')}`;
  return `do shell script "${esc(shell)}" with prompt "${esc(prompt.slice(0, 200))}" with administrator privileges`;
}
