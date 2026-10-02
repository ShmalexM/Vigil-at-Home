// Keeps Santa's pre-launch (CEL) rules in step with Vigil's blocking rules.
//
//   DetectionRule[] (mode block, kill on launch)
//     ─► preexecRules(): program + argument tests (CEL)
//     ─► find the program in the system folders, read its signature
//     ─► only Apple platform binaries: SIGNINGID platform:com.apple.osascript
//     ─► RuleStore: policy CEL, "(tests) ? BLOCKLIST : ALLOWLIST"
//     ─► santactl sync
//
// The helper builds every CEL expression itself from structured rules, so
// nothing the app sends is passed to Santa as code. The "otherwise" answer
// of a CEL rule is ALLOWLIST, which is why targets are limited to programs
// macOS ships: Santa allows those anyway, so the rule can only ever add a
// block. A rule the user or Vigil already set on the same target wins, and
// rules this module set are tagged so later syncs replace only their own.
//
// Vigil's own engine keeps running the same rules after launch, so on a Santa
// older than 2025.8 (no CEL) or when a program can't be matched, nothing is
// lost: the program is killed a few milliseconds after it starts instead.

import { celProgram, preexecRules, type PreexecRule } from '@vigil/detection/preexec';
import type { DetectionRule } from '@vigil/detection';
import type { RuleStore } from '@vigil/sensors';
import type { System } from './system.js';

export const PREEXEC_REASON = 'vigil-preexec';
/** First Santa release that evaluates CEL rules. */
export const CEL_MIN_VERSION: readonly [number, number] = [2025, 8];
const SYSTEM_DIRS = ['/usr/bin/', '/bin/', '/usr/sbin/', '/sbin/', '/usr/libexec/'];

/** Santa's version from `santactl version`, e.g. "santad | 2026.8 (build 1)". */
export function parseSantaVersion(out: string): [number, number] | undefined {
  const m = /\b(20\d\d)\.(\d+)\b/.exec(out);
  return m ? [Number(m[1]), Number(m[2])] : undefined;
}

export function supportsCel(v: readonly [number, number] | undefined): boolean {
  if (!v) return false;
  return v[0] > CEL_MIN_VERSION[0] || (v[0] === CEL_MIN_VERSION[0] && v[1] >= CEL_MIN_VERSION[1]);
}

/**
 * Santa's SIGNINGID for an Apple platform binary, from `codesign -dv`
 * (which writes to stderr): "Identifier=com.apple.osascript" plus a
 * "Platform identifier=" line, which only platform binaries carry.
 */
export function parsePlatformSigningId(codesignOutput: string): string | undefined {
  if (!/^Platform identifier=\d+/m.test(codesignOutput)) return undefined;
  const id = /^Identifier=([A-Za-z0-9._-]{1,255})$/m.exec(codesignOutput)?.[1];
  return id ? `platform:${id}` : undefined;
}

export interface InstalledPreexec {
  program: string;
  identifier: string;
  ruleIds: string[];
}

export interface PreexecOutcome {
  /** False when Santa is missing or too old for CEL; nothing was installed. */
  santaSupportsCel: boolean;
  installed: InstalledPreexec[];
  skipped: { ruleId?: string; program?: string; reason: string }[];
}

export class PreexecSync {
  private readonly signingIds = new Map<string, string | null>();

  constructor(
    private readonly sys: System,
    private readonly rules: RuleStore,
    private readonly fileExists: (path: string) => boolean,
  ) {}

  /** Replace Vigil's pre-launch rules with the ones these rules call for. */
  async apply(blocking: DetectionRule[]): Promise<PreexecOutcome> {
    const compiled = preexecRules(blocking.map((rule) => ({ rule, mode: 'block' as const })));
    const skipped: PreexecOutcome['skipped'] = compiled.skipped.map((s) => ({ ...s }));
    const version = parseSantaVersion(
      (await this.sys.run('santactl', ['version'], { timeoutMs: 10_000 })).stdout,
    );
    if (!supportsCel(version)) {
      // Leave any earlier pre-launch rules alone: an older Santa ignores them,
      // and dropping them here would lose them across a downgrade-and-back.
      return { santaSupportsCel: false, installed: [], skipped };
    }

    const wanted = new Map<string, { entry: PreexecRule; expr: string }>();
    for (const entry of compiled.rules) {
      const identifier = await this.signingIdFor(entry.program);
      if (!identifier) {
        skipped.push({ program: entry.program, reason: 'not an Apple program in a system folder' });
        continue;
      }
      wanted.set(identifier, { entry, expr: celProgram(entry.tests) });
    }

    const installed: InstalledPreexec[] = [];
    for (const [identifier, { entry, expr }] of wanted) {
      const existing = this.rules.get('SIGNINGID', identifier);
      if (existing && existing.reason !== PREEXEC_REASON) {
        skipped.push({ program: entry.program, reason: 'another Santa rule already covers it' });
        continue;
      }
      if (existing?.rule.cel_expr !== expr || existing.rule.custom_msg !== entry.message)
        this.rules.upsert({
          ruleType: 'SIGNINGID',
          identifier,
          policy: 'CEL',
          celExpr: expr,
          customMessage: entry.message,
          reason: PREEXEC_REASON,
        });
      installed.push({ program: entry.program, identifier, ruleIds: entry.ruleIds });
    }
    for (const r of this.rules.active())
      if (r.reason === PREEXEC_REASON && !wanted.has(r.rule.identifier))
        this.rules.remove(r.rule.rule_type, r.rule.identifier);

    return { santaSupportsCel: true, installed, skipped };
  }

  private async signingIdFor(program: string): Promise<string | undefined> {
    const cached = this.signingIds.get(program);
    if (cached !== undefined) return cached ?? undefined;
    let found: string | null = null;
    for (const dir of SYSTEM_DIRS) {
      const path = dir + program;
      if (!this.fileExists(path)) continue;
      const r = await this.sys.run('codesign', ['-dv', path], { timeoutMs: 10_000 });
      found = parsePlatformSigningId(r.stderr + '\n' + r.stdout) ?? null;
      break;
    }
    this.signingIds.set(program, found);
    return found ?? undefined;
  }
}
