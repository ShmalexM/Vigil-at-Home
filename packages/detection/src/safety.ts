import { BlockList, isIP } from "node:net";
import { globToRegExp } from "./rules/compile.js";
import type { Action, ResponseTarget, SensorEvent } from "./types.js";

/**
 * The safety floor. Whatever a rule asks for, and whoever wrote it (a built-in
 * pack, the user, or an AI proposal the user approved), these checks cap the
 * action at "alert" when acting would risk breaking the Mac. They run last and
 * cannot be configured away by a rule.
 */
export interface SafetyConfig {
  /** Paths of Vigil's own binaries. Vigil never pauses or kills itself. */
  selfPaths: string[];
  /** Extra process path globs the user never wants touched. */
  protectedPathGlobs: string[];
  /** Networks never firewalled (loopback, link-local, the user's LAN...). */
  neverBlockNetworks: string[];
}

export const DEFAULT_PROTECTED_PATH_GLOBS = ["/System/**", "/usr/sbin/**", "/usr/libexec/**", "/sbin/**", "/Library/Apple/**"];

/**
 * Apple command-line tools that malware drives (osascript, curl, bash,
 * python3...). An instance started by something else may be paused or killed;
 * one started by launchd (a system service) may not.
 */
const APPLE_TOOL_GLOBS = ["/bin/*", "/usr/bin/*"];

export const DEFAULT_NEVER_BLOCK_NETWORKS = [
  "127.0.0.0/8",
  "::1/128",
  "169.254.0.0/16",
  "fe80::/10",
  "224.0.0.0/4",
  "ff00::/8",
];

/** Persistence items under these paths belong to macOS. */
const SYSTEM_PERSISTENCE_GLOBS = ["/System/**"];

export const DEFAULT_SAFETY: SafetyConfig = {
  selfPaths: [],
  protectedPathGlobs: [],
  neverBlockNetworks: [],
};

export interface SafetyResult {
  action: Action;
  reason?: string;
}

export class SafetyFloor {
  private readonly protectedPaths: RegExp[];
  private readonly systemPersistence: RegExp[];
  private readonly appleTools = APPLE_TOOL_GLOBS.map((g) => globToRegExp(g));
  private readonly selfPaths: Set<string>;
  private readonly neverBlock = new BlockList();

  constructor(cfg: Partial<SafetyConfig> = {}) {
    const c = { ...DEFAULT_SAFETY, ...cfg };
    this.protectedPaths = [...DEFAULT_PROTECTED_PATH_GLOBS, ...c.protectedPathGlobs].map((g) => globToRegExp(g));
    this.systemPersistence = SYSTEM_PERSISTENCE_GLOBS.map((g) => globToRegExp(g));
    this.selfPaths = new Set(c.selfPaths.map((p) => p.toLowerCase()));
    for (const n of [...DEFAULT_NEVER_BLOCK_NETWORKS, ...c.neverBlockNetworks]) {
      const [addr, prefix] = n.split("/");
      const fam = isIP(addr ?? "");
      if (!addr || fam === 0) throw new Error(`neverBlockNetworks: not a network: ${n}`);
      const type = fam === 4 ? "ipv4" : "ipv6";
      if (prefix === undefined) this.neverBlock.addAddress(addr, type);
      else this.neverBlock.addSubnet(addr, Number(prefix), type);
    }
  }

  /** Why this process must never be paused or killed, or undefined if it may be. */
  processProtection(e: SensorEvent): string | undefined {
    const p = e.process;
    if (!p) return "there is no process to act on";
    if (p.pid <= 1) return "it is a core macOS process";
    if (p.signing?.status === "apple") {
      const tool = this.appleTools.some((r) => r.test(p.path));
      if (!tool || p.ppid === 1 || p.ppid === undefined) return "it is part of macOS (signed by Apple)";
    }
    const path = p.path.toLowerCase();
    if (this.selfPaths.has(path)) return "it is Vigil itself";
    for (const sp of this.selfPaths) if (path.startsWith(sp.endsWith("/") ? sp : `${sp}/`)) return "it is Vigil itself";
    if (this.protectedPaths.some((r) => r.test(p.path))) return "it lives in a protected system folder";
    return undefined;
  }

  networkProtection(e: SensorEvent): string | undefined {
    const n = e.network;
    if (!n || (!n.remoteAddress && !n.domain)) return "there is no remote address to block";
    const addr = n.remoteAddress;
    if (addr) {
      const fam = isIP(addr);
      if (fam !== 0 && this.neverBlock.check(addr, fam === 4 ? "ipv4" : "ipv6")) {
        return "the address is local or on the never-block list";
      }
    }
    return undefined;
  }

  persistenceProtection(e: SensorEvent): string | undefined {
    const item = e.persistence?.itemPath;
    if (!item) return "there is no launch item to disable";
    if (this.systemPersistence.some((r) => r.test(item))) return "the launch item belongs to macOS";
    return undefined;
  }

  /** Cap an action. record and alert always pass; suspend and block may be lowered to alert. */
  apply(e: SensorEvent, target: ResponseTarget, action: Action): SafetyResult {
    if (action === "record" || action === "alert") return { action };
    let why: string | undefined;
    if (target === "process") why = this.processProtection(e);
    else if (target === "network") why = this.networkProtection(e);
    else why = this.persistenceProtection(e);
    return why ? { action: "alert", reason: `Vigil will not act on this because ${why}.` } : { action };
  }
}
