import { BlockList, isIP } from 'node:net';
import type { FeedList } from './sources.js';

/**
 * Feed entries turn into automatic kills and firewall blocks, so everything is
 * checked here before it reaches a list. A feed can be wrong, stale or
 * tampered with; this is what stops one bad entry from cutting the Mac off
 * from Apple, a whole cloud provider, or the local network.
 */

/**
 * Domains whose subdomains or paths belong to many unrelated people, or that
 * macOS needs. An entry equal to one of these, a parent of one, or a subdomain
 * of one is dropped: lists match by parent domain, so "github.com" would block
 * all of GitHub.
 */
export const NEVER_LIST_DOMAINS = [
  'apple.com',
  'icloud.com',
  'icloud-content.com',
  'mzstatic.com',
  'apple-dns.net',
  'cdn-apple.com',
  'google.com',
  'googleapis.com',
  'googleusercontent.com',
  'gstatic.com',
  'goo.gl',
  'youtube.com',
  'github.com',
  'githubusercontent.com',
  'github.io',
  'gitlab.com',
  'bitbucket.org',
  'microsoft.com',
  'live.com',
  'office.com',
  'sharepoint.com',
  'onedrive.com',
  '1drv.ms',
  'windows.net',
  'azureedge.net',
  'amazonaws.com',
  'cloudfront.net',
  'cloudflare.com',
  'workers.dev',
  'pages.dev',
  'r2.dev',
  'dropbox.com',
  'dropboxusercontent.com',
  'discord.com',
  'discordapp.com',
  'discordapp.net',
  'telegram.org',
  't.me',
  'mediafire.com',
  'mega.nz',
  'bit.ly',
  'pastebin.com',
  'akamaized.net',
  'akamaihd.net',
  'fastly.net',
  'firebaseapp.com',
  'web.app',
  'herokuapp.com',
  'vercel.app',
  'netlify.app',
  'wetransfer.com',
  'box.com',
  'anthropic.com',
  'claude.ai',
  'openai.com',
  'chatgpt.com',
];

/** Addresses never put on a block list. */
const RESERVED_NETWORKS: Array<[string, number, 'ipv4' | 'ipv6']> = [
  ['0.0.0.0', 8, 'ipv4'],
  ['10.0.0.0', 8, 'ipv4'],
  ['100.64.0.0', 10, 'ipv4'],
  ['127.0.0.0', 8, 'ipv4'],
  ['169.254.0.0', 16, 'ipv4'],
  ['172.16.0.0', 12, 'ipv4'],
  ['192.0.0.0', 24, 'ipv4'],
  ['192.0.2.0', 24, 'ipv4'],
  ['192.168.0.0', 16, 'ipv4'],
  ['198.18.0.0', 15, 'ipv4'],
  ['198.51.100.0', 24, 'ipv4'],
  ['203.0.113.0', 24, 'ipv4'],
  ['224.0.0.0', 3, 'ipv4'],
  ['::', 128, 'ipv6'],
  ['::1', 128, 'ipv6'],
  ['fc00::', 7, 'ipv6'],
  ['fe80::', 10, 'ipv6'],
  ['ff00::', 8, 'ipv6'],
  ['2001:db8::', 32, 'ipv6'],
];

/** Ranges wider than this are dropped, matching the safety floor. */
const MIN_PREFIX = { ipv4: 16, ipv6: 48 } as const;

const HOST_RE = /^(?=.{4,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
const SHA256_RE = /^[a-f0-9]{64}$/;

export type DropReason =
  'malformed' | 'reserved_address' | 'range_too_wide' | 'protected_domain' | 'ip_in_domain_list';

export interface CleanResult {
  entries: string[];
  dropped: Partial<Record<DropReason, number>>;
}

export interface CleanOptions {
  /** Extra domains never listed (the user's employer, their own sites...). */
  neverListDomains?: readonly string[];
  /** Extra networks never listed (a VPN range, the user's servers...). */
  neverListNetworks?: readonly string[];
}

function reservedList(extra: readonly string[]): BlockList {
  const bl = new BlockList();
  for (const [a, p, t] of RESERVED_NETWORKS) bl.addSubnet(a, p, t);
  for (const n of extra) {
    const [addr, prefix] = n.split('/');
    const fam = addr ? isIP(addr) : 0;
    if (!addr || fam === 0) throw new Error(`neverListNetworks: not a network: ${n}`);
    const type = fam === 4 ? 'ipv4' : 'ipv6';
    if (prefix === undefined) bl.addAddress(addr, type);
    else bl.addSubnet(addr, Number(prefix), type);
  }
  return bl;
}

function related(entry: string, protectedDomain: string): boolean {
  return (
    entry === protectedDomain ||
    entry.endsWith(`.${protectedDomain}`) ||
    protectedDomain.endsWith(`.${entry}`)
  );
}

/** Normalize, validate and de-duplicate feed values for one list. */
export function cleanEntries(
  list: FeedList,
  values: Iterable<string>,
  opts: CleanOptions = {},
): CleanResult {
  const out = new Set<string>();
  const dropped: CleanResult['dropped'] = {};
  const drop = (r: DropReason) => (dropped[r] = (dropped[r] ?? 0) + 1);
  const never = [...NEVER_LIST_DOMAINS, ...(opts.neverListDomains ?? [])].map((d) =>
    d.toLowerCase(),
  );
  const reserved =
    list === 'known_bad_ips' ? reservedList(opts.neverListNetworks ?? []) : undefined;

  for (const raw of values) {
    const v = raw.trim().toLowerCase().replace(/\.$/, '');
    if (list === 'known_bad_sha256') {
      if (SHA256_RE.test(v)) out.add(v);
      else drop('malformed');
    } else if (list === 'known_bad_domains') {
      if (isIP(v.replace(/^\[|\]$/g, '')) !== 0) drop('ip_in_domain_list');
      else if (!HOST_RE.test(v)) drop('malformed');
      else if (never.some((d) => related(v, d))) drop('protected_domain');
      else out.add(v);
    } else {
      const [addr, prefixRaw, extra] = v.split('/');
      const fam = addr ? isIP(addr) : 0;
      const prefix = prefixRaw === undefined ? undefined : Number(prefixRaw);
      if (!addr || fam === 0 || extra !== undefined) {
        drop('malformed');
        continue;
      }
      const type = fam === 4 ? 'ipv4' : 'ipv6';
      const max = type === 'ipv4' ? 32 : 128;
      if (prefix !== undefined && (!Number.isInteger(prefix) || prefix < 0 || prefix > max)) {
        drop('malformed');
      } else if (prefix !== undefined && prefix < MIN_PREFIX[type]) {
        drop('range_too_wide');
      } else if (reserved!.check(addr, type)) {
        drop('reserved_address');
      } else {
        out.add(prefix === undefined || prefix === max ? addr : `${addr}/${prefix}`);
      }
    }
  }
  return { entries: [...out], dropped };
}
