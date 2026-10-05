// Network blocks on Linux through nftables, the kernel's packet filter on
// every current distribution (iptables there is a front end to it).
//
// Vigil owns one table, "inet vigil", with an input and an output chain
// hooked in just before the default filter priority. Each blocked address or
// range is a pair of drop rules tagged with a comment naming it, so blocks
// can overlap freely (a /24 and an address inside it) and each one is
// removed on its own. Nothing else in the system's firewall is touched, and
// deleting the table removes every trace. Like pf, nftables forgets
// everything at reboot; the helper re-applies active blocks from its journal.

import { isIP } from 'node:net';
import type { System } from '../system.js';
import { ActionError } from './errors.js';
import { normalizeTarget, type NetworkFirewall } from './firewall.js';

export const NFT_TABLE = 'vigil';

/**
 * Creates the table and chains if missing. Re-running it keeps existing rules.
 * Scripts go to nft as one argument rather than on stdin: nft refuses to read
 * a script from the socket Node gives a child as stdin, and commands joined
 * by ";" in one invocation still apply as a single transaction.
 */
export const NFT_SETUP =
  `table inet ${NFT_TABLE} { ` +
  `chain output { type filter hook output priority -10; policy accept; }; ` +
  `chain input { type filter hook input priority -10; policy accept; }; }`;

const TAG = 'vigil:';

interface NftRule {
  chain: string;
  handle: number;
  comment?: string;
}

/** Rules in Vigil's table that carry a block tag, from `nft -j -a list table`. */
export function parseNftRules(json: string): NftRule[] {
  let doc: { nftables?: { rule?: NftRule & { table?: string; family?: string } }[] };
  try {
    doc = JSON.parse(json) as typeof doc;
  } catch {
    return [];
  }
  return (doc.nftables ?? [])
    .map((o) => o.rule)
    .filter(
      (r): r is NftRule & { table?: string; family?: string } =>
        !!r && r.table === NFT_TABLE && r.family === 'inet' && !!r.comment?.startsWith(TAG),
    )
    .map((r) => ({ chain: r.chain, handle: r.handle, comment: r.comment! }));
}

export class NftFirewall implements NetworkFirewall {
  private loaded = false;

  constructor(private readonly sys: System) {}

  async ensureLoaded(): Promise<void> {
    if (this.loaded && (await this.exists())) return;
    const r = await this.sys.run('nft', [NFT_SETUP]);
    if (r.code !== 0)
      throw new ActionError('failed', `could not set up nftables: ${r.stderr.trim()}`);
    this.loaded = true;
  }

  /** Removes Vigil's table and with it every block. */
  async release(): Promise<void> {
    await this.sys.run('nft', ['delete', 'table', 'inet', NFT_TABLE]);
    this.loaded = false;
  }

  async block(address: string): Promise<string> {
    const a = normalizeTarget(address);
    await this.ensureLoaded();
    if ((await this.list()).includes(a)) return a;
    const fam = isIP(a.split('/')[0]!) === 6 ? 'ip6' : 'ip';
    const comment = `"${TAG}${a}"`;
    // One transaction, so a block is never half in place.
    const script =
      `add rule inet ${NFT_TABLE} output ${fam} daddr ${a} drop comment ${comment}; ` +
      `add rule inet ${NFT_TABLE} input ${fam} saddr ${a} drop comment ${comment}`;
    const r = await this.sys.run('nft', [script]);
    if (r.code !== 0) throw new ActionError('failed', `could not block ${a}: ${r.stderr.trim()}`);
    return a;
  }

  async unblock(address: string): Promise<void> {
    const rules = (await this.rules()).filter((r) => r.comment === `${TAG}${address}`);
    if (rules.length === 0) return;
    const script = rules
      .map((r) => `delete rule inet ${NFT_TABLE} ${r.chain} handle ${r.handle}`)
      .join('; ');
    const r = await this.sys.run('nft', [script]);
    if (r.code !== 0)
      throw new ActionError('failed', `could not unblock ${address}: ${r.stderr.trim()}`);
  }

  async list(): Promise<string[]> {
    const seen = new Set<string>();
    for (const r of await this.rules()) seen.add(r.comment!.slice(TAG.length));
    return [...seen];
  }

  private async exists(): Promise<boolean> {
    return (await this.sys.run('nft', ['list', 'table', 'inet', NFT_TABLE])).code === 0;
  }

  private async rules(): Promise<NftRule[]> {
    const r = await this.sys.run('nft', ['-j', '-a', 'list', 'table', 'inet', NFT_TABLE]);
    return r.code === 0 ? parseNftRules(r.stdout) : [];
  }
}
