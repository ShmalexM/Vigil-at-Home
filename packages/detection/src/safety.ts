import { authorizeAction, type Action, type ProcessRef } from '@vigil/core';
import { BlockList, isIP } from 'node:net';
import { clip, globMatcher, globToRegExp } from './rules/compile.js';
import type { DetectionEvent } from './types.js';

/**
 * The safety floor. Whatever a rule asks for, and whoever wrote it (a built-in
 * pack, the user, or an AI proposal the user approved), every action a rule
 * would run or propose passes through here last. Actions that could break the
 * Mac are dropped, and the detection falls back to telling the user.
 */
export interface SafetyConfig {
  /** Paths of Vigil's own binaries or bundle. Vigil never pauses, kills or blocks itself. */
  selfPaths: string[];
  /** Extra process path globs the user never wants touched. */
  protectedPathGlobs: string[];
  /** Networks never firewalled (the user's LAN, a VPN...). Loopback and link-local are always included. */
  neverBlockNetworks: string[];
}

export const DEFAULT_PROTECTED_PATH_GLOBS = [
  '/System/**',
  '/usr/sbin/**',
  '/usr/libexec/**',
  '/sbin/**',
  '/Library/Apple/**',
];

/** Never quarantined, whatever the rule says. */
const PROTECTED_FILE_GLOBS = [...DEFAULT_PROTECTED_PATH_GLOBS, '/usr/**', '/bin/**'];

/**
 * Apple command-line tools that malware drives (osascript, curl, bash,
 * python3...). An instance started by something else may be paused or killed;
 * one started by launchd (a system service) may not.
 */
const APPLE_TOOL_GLOBS = ['/bin/*', '/usr/bin/*'];

export const DEFAULT_NEVER_BLOCK_NETWORKS = [
  '0.0.0.0/8',
  '127.0.0.0/8',
  '::1/128',
  '::/128',
  '169.254.0.0/16',
  'fe80::/10',
  '224.0.0.0/4',
  'ff00::/8',
];

/** Refuse to firewall ranges wider than this: it would cut off too much. */
const MIN_PREFIX = { ipv4: 16, ipv6: 48 } as const;

const SYSTEM_PERSISTENCE_GLOBS = ['/System/**'];

function toBlockList(networks: string[], label: string): BlockList {
  const bl = new BlockList();
  for (const n of networks) {
    const [addr, prefix] = n.split('/');
    const fam = isIP(addr ?? '');
    if (!addr || fam === 0) throw new Error(`${label}: not a network: ${n}`);
    const type = fam === 4 ? 'ipv4' : 'ipv6';
    if (prefix === undefined) bl.addAddress(addr, type);
    else bl.addSubnet(addr, Number(prefix), type);
  }
  return bl;
}

export class SafetyFloor {
  private readonly protectedPaths: ((path: string) => boolean)[];
  private readonly protectedFiles: ((path: string) => boolean)[];
  private readonly appleTools = APPLE_TOOL_GLOBS.map((g) => globToRegExp(g));
  private readonly systemPersistence = SYSTEM_PERSISTENCE_GLOBS.map((g) => globToRegExp(g));
  private readonly selfPaths: string[];
  private readonly neverBlock: BlockList;

  constructor(cfg: Partial<SafetyConfig> = {}) {
    const extra = cfg.protectedPathGlobs ?? [];
    // Matched without a regex (globMatcher), in time linear in the path.
    const match = (g: string) => {
      try {
        return globMatcher(g);
      } catch (err) {
        throw new Error(`protectedPathGlobs: ${g}: ${(err as Error).message}`, { cause: err });
      }
    };
    this.protectedPaths = [...DEFAULT_PROTECTED_PATH_GLOBS, ...extra].map(match);
    this.protectedFiles = [...PROTECTED_FILE_GLOBS, ...extra].map(match);
    this.selfPaths = (cfg.selfPaths ?? []).map((p) => p.toLowerCase().replace(/\/+$/, ''));
    this.neverBlock = toBlockList(
      [...DEFAULT_NEVER_BLOCK_NETWORKS, ...(cfg.neverBlockNetworks ?? [])],
      'neverBlockNetworks',
    );
  }

  private isSelf(path: string): boolean {
    const p = path.toLowerCase();
    return this.selfPaths.some((s) => p === s || p.startsWith(`${s}/`));
  }

  /** Why this process must never be paused, killed or blocklisted, or undefined if it may be. */
  processProtection(p: ProcessRef | undefined): string | undefined {
    if (!p) return 'there is no process to act on';
    if (p.pid <= 1) return 'it is a core macOS process';
    if (p.signing === 'apple') {
      const tool = this.appleTools.some((r) => r.test(clip(p.path)));
      if (!tool || p.ppid === 1 || p.ppid === undefined) {
        return 'it is part of macOS (signed by Apple)';
      }
    }
    if (this.isSelf(p.path)) return 'it is Vigil itself';
    if (this.protectedPaths.some((fits) => fits(p.path))) {
      return 'it lives in a protected system folder';
    }
    return undefined;
  }

  /** Why this action must not run or be offered, or undefined when it is safe. */
  check(action: Action, e: DetectionEvent): string | undefined {
    const auth = authorizeAction('rule', action);
    if (!auth.ok) return auth.reason;
    const proc = 'process' in e ? e.process : undefined;

    switch (action.kind) {
      case 'process.suspend':
      case 'process.kill': {
        if (!proc || action.pid !== proc.pid || (action.path && action.path !== proc.path)) {
          return 'it does not name the process that was seen';
        }
        return this.processProtection(proc);
      }
      case 'network.block': {
        const [addr, prefixRaw] = action.address.split('/');
        const fam = isIP(addr ?? '');
        if (!addr || fam === 0) return `"${action.address}" is not an IP address`;
        const type = fam === 4 ? 'ipv4' : 'ipv6';
        if (prefixRaw !== undefined && Number(prefixRaw) < MIN_PREFIX[type]) {
          return 'the address range is too wide to block';
        }
        if (this.neverBlock.check(addr, type))
          return 'the address is local or on the never-block list';
        return undefined;
      }
      case 'persistence.disable':
        return this.systemPersistence.some((r) => r.test(clip(action.path)))
          ? 'the launch item belongs to macOS'
          : undefined;
      case 'file.quarantine': {
        if (this.isSelf(action.path)) return 'it is part of Vigil';
        if (this.protectedFiles.some((fits) => fits(action.path)))
          return 'the file is part of macOS';
        if (proc && proc.path === action.path) return this.processProtection(proc);
        return undefined;
      }
      case 'santa.rule.set': {
        if (action.identifier.startsWith('platform:')) return 'it would block part of macOS';
        const names = proc && [proc.sha256, proc.cdhash, proc.teamId, proc.signingId];
        if (proc && names?.includes(action.identifier)) {
          const why = this.processProtection(proc);
          // Blocking an Apple CLI tool binary blocks it for everyone, not just this instance.
          if (why || proc.signing === 'apple') return why ?? 'it would block part of macOS';
        }
        return undefined;
      }
      default:
        return undefined;
    }
  }
}
