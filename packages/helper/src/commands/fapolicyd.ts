// Blocking a program before it runs on Linux, through fapolicyd: the
// file-access policy daemon in Fedora, RHEL, Debian and Ubuntu, which asks
// the kernel (fanotify) to hold every execute until it has decided.
//
//   "block this program" (santa.rule.set, binary, sha256)
//     ─► blocks.json (the helper's list)
//     ─► /etc/fapolicyd/rules.d/05-vigil.rules: deny_audit perm=execute all : sha256hash=<hex>
//     ─► fagenrules --load (compiles rules.d into compiled.rules)
//     ─► systemctl try-restart fapolicyd (a reload on SIGHUP lists the new
//        rule but, in fapolicyd 1.3, never matches a sha256hash with it; a
//        fresh start does, and takes a second with setup's trust = file)
//
// The file holds nothing but deny lines built from validated hashes, and it
// sorts ahead of the distribution's own rules, so it can only ever add a
// block. Where fapolicyd isn't installed the list is still kept: the helper
// stops a blocked program the moment osquery reports it starting (see
// daemon.ts), and the rules apply as soon as fapolicyd appears.

import { existsSync, mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import type { System } from '../system.js';
import { ActionError } from './errors.js';

export const FAPOLICYD_RULES_DIR = '/etc/fapolicyd/rules.d';
export const VIGIL_RULES_FILE = '05-vigil.rules';
const HEADER =
  '# Written by Vigil at Home: programs you blocked in Vigil. Change them in Vigil;\n' +
  '# edits here are replaced.\n';

const SHA256 = /^[0-9a-f]{64}$/;

interface Block {
  sha256: string;
  at: number;
}

export interface FapolicydOptions {
  /** The helper's own list, kept whether or not fapolicyd is installed. */
  store: string;
  rulesDir?: string;
  now?: () => number;
}

export interface FapolicydStatus {
  /** fapolicyd's rules folder exists. */
  installed: boolean;
  blocked: number;
  /** The last rules reload failed, with why. */
  lastError: string | null;
}

/** The rules file for these hashes. */
export function fapolicydRules(hashes: string[]): string {
  return HEADER + hashes.map((h) => `deny_audit perm=execute all : sha256hash=${h}\n`).join('');
}

export class FapolicydBlocks {
  private blocks: Block[] = [];
  private lastError: string | null = null;
  private readonly rulesDir: string;

  constructor(
    private readonly sys: System,
    private readonly opts: FapolicydOptions,
  ) {
    this.rulesDir = opts.rulesDir ?? FAPOLICYD_RULES_DIR;
    try {
      const saved = JSON.parse(readFileSync(opts.store, 'utf8')) as { blocks?: Block[] };
      this.blocks = (saved.blocks ?? []).filter((b) => SHA256.test(b.sha256));
    } catch {
      // First start, or an unreadable file: begin empty.
    }
  }

  has(sha256: string): boolean {
    return this.blocks.some((b) => b.sha256 === sha256);
  }

  list(): string[] {
    return this.blocks.map((b) => b.sha256);
  }

  status(): FapolicydStatus {
    return {
      installed: existsSync(dirname(this.rulesDir)),
      blocked: this.blocks.length,
      lastError: this.lastError,
    };
  }

  /** Add a block. Returns false when it was already there. */
  async block(sha256: string): Promise<boolean> {
    const h = sha256.toLowerCase();
    if (!SHA256.test(h)) throw new ActionError('invalid', 'a program is blocked by its sha256');
    if (this.has(h)) return false;
    this.blocks.push({ sha256: h, at: (this.opts.now ?? Date.now)() });
    this.save();
    await this.apply();
    return true;
  }

  /** Remove a block. Returns false when there was none. */
  async unblock(sha256: string): Promise<boolean> {
    const h = sha256.toLowerCase();
    const before = this.blocks.length;
    this.blocks = this.blocks.filter((b) => b.sha256 !== h);
    if (this.blocks.length === before) return false;
    this.save();
    await this.apply();
    return true;
  }

  /**
   * Bring fapolicyd's rules in line with the list. Does nothing until
   * fapolicyd is installed. A failed reload is reported in status, not
   * thrown: the block still stands through the helper's own check.
   */
  async apply(): Promise<boolean> {
    if (!existsSync(dirname(this.rulesDir))) return false;
    const file = join(this.rulesDir, VIGIL_RULES_FILE);
    const next = fapolicydRules(this.list());
    let current: string | undefined;
    try {
      current = readFileSync(file, 'utf8');
    } catch {
      current = undefined;
    }
    if (current === next && this.lastError === null) return true;
    if (this.blocks.length === 0 && current === undefined) return true;
    mkdirSync(this.rulesDir, { recursive: true, mode: 0o755 });
    if (this.blocks.length === 0) rmSync(file, { force: true });
    else {
      // fapolicyd reads its rules as root only; keep the file 0644 like its own.
      writeFileSync(file + '.tmp', next, { mode: 0o644 });
      renameSync(file + '.tmp', file);
    }
    const r = await this.sys.run('fagenrules', ['--load'], { timeoutMs: 60_000 });
    if (r.code !== 0) {
      this.lastError = r.stderr.trim() || `fagenrules exited with ${r.code}`;
      return false;
    }
    // Only if it runs: a stopped fapolicyd reads the rules when it starts.
    const s = await this.sys.run('systemctl', ['try-restart', 'fapolicyd'], { timeoutMs: 60_000 });
    this.lastError =
      s.code === 0 ? null : s.stderr.trim() || `restarting fapolicyd exited with ${s.code}`;
    return s.code === 0;
  }

  private save(): void {
    mkdirSync(dirname(this.opts.store), { recursive: true });
    writeFileSync(this.opts.store + '.tmp', JSON.stringify({ blocks: this.blocks }), {
      mode: 0o600,
    });
    renameSync(this.opts.store + '.tmp', this.opts.store);
  }
}
