// Network blocks through macOS's built-in packet filter (pf).
//
// macOS's /etc/pf.conf already evaluates every anchor under "com.apple/*",
// so Vigil loads its rules into "com.apple/vigil" without editing system
// files. The rules drop traffic to and from addresses in one table; blocking
// and unblocking just add and remove table entries. pf forgets everything at
// reboot, so the helper re-applies active blocks from its journal at start.

import { isIP } from 'node:net';
import type { System } from '../system.js';
import { ActionError } from './errors.js';

export const PF_ANCHOR = 'com.apple/vigil';
export const PF_TABLE = 'vigil_blocked';

export const PF_RULES =
  `table <${PF_TABLE}> persist\n` +
  `block drop out quick from any to <${PF_TABLE}>\n` +
  `block drop in quick from <${PF_TABLE}> to any\n`;

/**
 * Normalize and vet an address or CIDR range. Loopback, unspecified,
 * link-local and multicast are refused, and so are ranges wide enough to cut
 * off most of the internet (wider than /8 for IPv4 or /24 for IPv6).
 */
export function normalizeTarget(target: string): string {
  const t = target.trim().toLowerCase();
  const slash = t.indexOf('/');
  if (slash < 0) return normalizeAddress(t);
  const addr = normalizeAddress(t.slice(0, slash));
  const bits = t.slice(slash + 1);
  const max = isIP(addr) === 4 ? 32 : 128;
  const min = max === 32 ? 8 : 24;
  if (!/^\d{1,3}$/.test(bits) || Number(bits) > max)
    throw new ActionError('invalid', `${target} is not a valid range`);
  if (Number(bits) < min) throw new ActionError('refused', `${target} is too wide to block`);
  return Number(bits) === max ? addr : `${addr}/${Number(bits)}`;
}

/** Normalize and vet a single address. Loopback, unspecified, link-local and multicast are refused. */
export function normalizeAddress(address: string): string {
  const a = address.trim().toLowerCase();
  const family = isIP(a);
  if (family === 0) throw new ActionError('invalid', `${address} is not an IP address`);
  if (family === 4) {
    const [o1, o2] = a.split('.').map(Number) as [number, number];
    if (o1 === 0 || o1 === 127 || (o1 === 169 && o2 === 254) || o1 >= 224) {
      throw new ActionError('refused', `${address} is a local or special address`);
    }
    return a;
  }
  if (
    a === '::' ||
    a === '::1' ||
    a.startsWith('fe80:') ||
    a.startsWith('ff') ||
    a.startsWith('::ffff:127.')
  ) {
    throw new ActionError('refused', `${address} is a local or special address`);
  }
  return a;
}

/** What the executor needs from a packet filter: pf on macOS, nftables on Linux. */
export interface NetworkFirewall {
  /** Load Vigil's rules and make sure the filter is running. Safe to call repeatedly. */
  ensureLoaded(): Promise<void>;
  release(): Promise<void>;
  /** Blocks traffic both ways; returns the normalized address. */
  block(address: string): Promise<string>;
  unblock(address: string): Promise<void>;
  list(): Promise<string[]>;
}

export class Firewall implements NetworkFirewall {
  private token: string | undefined;

  constructor(private readonly sys: System) {}

  /** Load Vigil's anchor and make sure pf is running. Safe to call repeatedly. */
  async ensureLoaded(): Promise<void> {
    const load = await this.sys.run('pfctl', ['-a', PF_ANCHOR, '-f', '-'], { input: PF_RULES });
    if (load.code !== 0)
      throw new ActionError('failed', `could not load pf rules: ${load.stderr.trim()}`);
    if (!this.token) {
      // -E enables pf with a reference token, so Vigil turning pf on never
      // turns it off for anything else that also needs it.
      const en = await this.sys.run('pfctl', ['-E']);
      const m = /Token\s*:\s*(\d+)/.exec(en.stderr + en.stdout);
      if (m) this.token = m[1];
    }
  }

  async release(): Promise<void> {
    if (this.token) await this.sys.run('pfctl', ['-X', this.token]);
    this.token = undefined;
  }

  async block(address: string): Promise<string> {
    const a = normalizeTarget(address);
    await this.ensureLoaded();
    const add = await this.sys.run('pfctl', ['-a', PF_ANCHOR, '-t', PF_TABLE, '-T', 'add', a]);
    if (add.code !== 0)
      throw new ActionError('failed', `could not block ${a}: ${add.stderr.trim()}`);
    // Cut connections that are already open (both directions). Best effort.
    const any = isIP(a.split('/')[0]!) === 6 ? '::/0' : '0.0.0.0/0';
    await this.sys.run('pfctl', ['-k', a]);
    await this.sys.run('pfctl', ['-k', any, '-k', a]);
    return a;
  }

  async unblock(address: string): Promise<void> {
    const del = await this.sys.run('pfctl', [
      '-a',
      PF_ANCHOR,
      '-t',
      PF_TABLE,
      '-T',
      'delete',
      address,
    ]);
    if (del.code !== 0)
      throw new ActionError('failed', `could not unblock ${address}: ${del.stderr.trim()}`);
  }

  async list(): Promise<string[]> {
    const r = await this.sys.run('pfctl', ['-a', PF_ANCHOR, '-t', PF_TABLE, '-T', 'show']);
    if (r.code !== 0) return [];
    return r.stdout
      .split('\n')
      .map((l) => l.trim())
      .filter(Boolean);
  }
}
