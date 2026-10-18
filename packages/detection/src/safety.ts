import { authorizeAction, type Action, type Condition, type ProcessRef } from '@vigil/core';
import { selfKey, selfRoots, underSelfRoot } from '@vigil/core/self';
import { BlockList, isIP } from 'node:net';
import { globMatcher } from './rules/compile.js';
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
  /**
   * sha256 of the programs inside Vigil's AppImage. A program is blocked by
   * hash everywhere at once, so blocking one of these would stop Vigil too.
   */
  selfHashes: string[];
  /** Extra process path globs the user never wants touched. */
  protectedPathGlobs: string[];
  /** Networks never firewalled (the user's LAN, a VPN...). Loopback and link-local are always included. */
  neverBlockNetworks: string[];
}

// Shared with the helper, so both floors agree on what Vigil is.
export { selfKey, selfRoots, underSelfRoot };

export const DEFAULT_PROTECTED_PATH_GLOBS = [
  '/System/**',
  '/usr/sbin/**',
  '/usr/libexec/**',
  '/sbin/**',
  '/Library/Apple/**',
];

/** Never quarantined, whatever the rule says. */
export const PROTECTED_FILE_GLOBS = [...DEFAULT_PROTECTED_PATH_GLOBS, '/usr/**', '/bin/**'];

/**
 * Apple command-line tools that malware drives (osascript, curl, bash,
 * python3...). An instance started by something else may be paused or killed;
 * one started by launchd (a system service) may not.
 */
export const APPLE_TOOL_GLOBS = ['/bin/*', '/usr/bin/*'];

/**
 * Where the operating system's own programs live. A program here is part of
 * macOS (or the Linux distribution) whatever the event's signing field says:
 * events from Santa's log carry `signing: "unknown"`, and on 2026-10-10 a
 * "malicious" verdict on such an event blocked /bin/sh for the whole Mac.
 */
export const PLATFORM_PATH_GLOBS = [
  '/bin/**',
  '/sbin/**',
  '/usr/bin/**',
  '/usr/sbin/**',
  '/usr/libexec/**',
  '/System/**',
  '/Library/Apple/**',
];

/** Where Apple's developer tools live (Command Line Tools, Xcode). */
export const APPLE_TOOLCHAIN_GLOBS = [
  '/Library/Developer/CommandLineTools/**',
  '/Applications/Xcode*.app/Contents/Developer/**',
];
/** The team ID Apple signs its own non-platform programs with (Xcode, its tools). */
const APPLE_TEAM_ID = '59GAB85EFG';

/** Shells: blocking one by hash stops every script that uses it, Vigil's included. */
export const SHELL_NAMES = ['sh', 'bash', 'zsh', 'dash', 'ksh', 'mksh', 'tcsh', 'csh', 'fish'];

const baseName = (path: string): string => path.slice(path.lastIndexOf('/') + 1);

/**
 * The command a shell was asked to run with `-c`, or undefined when the
 * process is not a shell running `-c <command>`. Santa's log splits the
 * command on spaces, so everything after `-c` is joined back together.
 */
export function shellCommand(p: Pick<ProcessRef, 'path' | 'args'>): string | undefined {
  if (!SHELL_NAMES.includes(baseName(p.path))) return undefined;
  const args = p.args ?? [];
  // A short-option cluster holding c (`-c`, `-lc`, `-ec`). Tested as letters
  // plus an includes(), not `-[a-z]*c[a-z]*`, which backtracks on long runs.
  const at = args.findIndex((a, i) => i > 0 && /^-[a-z]+$/.test(a) && a.includes('c'));
  if (at < 0) return undefined;
  const cmd = args
    .slice(at + 1)
    .join(' ')
    .trim();
  return cmd || undefined;
}

/** Event fields that name one exact program, wherever it is and whoever runs it. */
const PROGRAM_HASH_FIELDS = new Set(['process.sha256', 'process.cdhash']);

/**
 * Whether the condition picks the program by its hash: an inList on its
 * sha256 or CDHash (user-blocked-hash, the malware lists), or an `eq` or `in`
 * test on one, anywhere outside a `not`. Such a rule fires on every run of
 * that program, so its kill stops the program as surely as a block by hash.
 */
export function matchesProgramHash(c: Condition): boolean {
  if ('inList' in c) return PROGRAM_HASH_FIELDS.has(c.inList.field);
  if ('all' in c) return c.all.some(matchesProgramHash);
  if ('any' in c) return c.any.some(matchesProgramHash);
  if ('not' in c || 'firstSeen' in c) return false;
  return PROGRAM_HASH_FIELDS.has(c.field) && (c.op === 'eq' || c.op === 'in');
}

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

export const SYSTEM_PERSISTENCE_GLOBS = ['/System/**'];

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
  private readonly appleTools = APPLE_TOOL_GLOBS.map((g) => globMatcher(g));
  private readonly platformPaths = PLATFORM_PATH_GLOBS.map((g) => globMatcher(g));
  private readonly toolchain = APPLE_TOOLCHAIN_GLOBS.map((g) => globMatcher(g));
  private readonly systemPersistence = SYSTEM_PERSISTENCE_GLOBS.map((g) => globMatcher(g));
  private readonly selfPaths: string[];
  private selfHashes: Set<string>;
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
    this.selfPaths = selfRoots(cfg.selfPaths ?? []);
    this.selfHashes = new Set();
    this.setSelfHashes(cfg.selfHashes ?? []);
    this.neverBlock = toBlockList(
      [...DEFAULT_NEVER_BLOCK_NETWORKS, ...(cfg.neverBlockNetworks ?? [])],
      'neverBlockNetworks',
    );
  }

  /** The app hashes its own programs after start-up, so they arrive late. */
  setSelfHashes(hashes: readonly string[]): void {
    this.selfHashes = new Set(hashes.map((h) => h.toLowerCase()));
  }

  private isSelf(path: string): boolean {
    return underSelfRoot(this.selfPaths, path);
  }

  /** Why this process must never be paused, killed or blocklisted, or undefined if it may be. */
  processProtection(p: ProcessRef | undefined): string | undefined {
    if (!p) return 'there is no process to act on';
    if (p.pid <= 1) return 'it is a core macOS process';
    if (this.isApple(p)) {
      const tool = this.appleTools.some((fits) => fits(p.path));
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

  private isPlatform(path: string): boolean {
    return this.platformPaths.some((fits) => fits(path));
  }

  /**
   * Part of the OS, by something an attacker can't choose: a path the OS
   * protects, or a `platform:` signing ID (Santa reports it from the kernel's
   * platform-binary flag; the helper's codesign lookup only after verifying
   * `anchor apple`). Not `signing: 'apple'` alone: from Santa's log and
   * osquery that rests on the leaf certificate's name ("Software Signing"),
   * which a self-signed certificate can carry, and it would make a program
   * that can't be stopped or blocked.
   */
  /**
   * Apple's developer tools, which /usr/bin/git, python3 and the like hand
   * off to: in their install folders and signed with Apple's own team ID (a
   * team ID comes only from an Apple-issued certificate). Root-owned, but
   * not under SIP, so never exempt from being stopped (processProtection),
   * only from a block by hash, which would stop git for the whole Mac.
   */
  private isAppleToolchain(p: ProcessRef): boolean {
    return p.teamId === APPLE_TEAM_ID && this.toolchain.some((fits) => fits(p.path));
  }

  private isApple(p: ProcessRef): boolean {
    return this.isPlatform(p.path) || p.signingId?.startsWith('platform:') === true;
  }

  /**
   * Why this program must never be blocked by hash, or undefined if it may
   * be. Stricter than {@link processProtection}: a block stops the program
   * everywhere, not just this instance, so no part of the operating system
   * may be blocked, whatever the signing field says. Only paths the OS
   * itself protects count (PLATFORM_PATH_GLOBS, under SIP on macOS): a shell
   * Homebrew, MacPorts or Nix installed sits in a folder the user's account
   * can write, so a program there named `bash` may be anything.
   */
  blockProtection(p: ProcessRef | undefined): string | undefined {
    if (!p) return 'there is no process to act on';
    if (this.isAppleToolchain(p))
      return `${p.path} is Apple's developer tool; blocking it would stop it for everything on the Mac`;
    if (this.isApple(p)) {
      return SHELL_NAMES.includes(baseName(p.path))
        ? `${p.path} is the macOS shell; blocking it would stop every script on the Mac`
        : `${p.path} is part of macOS; blocking it would stop it for everything on the Mac`;
    }
    return this.processProtection(p);
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
        return this.systemPersistence.some((fits) => fits(action.path))
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
        if (this.selfHashes.has(action.identifier.toLowerCase()))
          return 'it would block Vigil itself';
        const names = proc && [proc.sha256, proc.cdhash, proc.teamId, proc.signingId];
        // A block names the program everywhere, not just this instance.
        if (proc && names?.includes(action.identifier)) return this.blockProtection(proc);
        return undefined;
      }
      default:
        return undefined;
    }
  }
}
