// Keeps tests from enforcing anything on the machine they run on. A test
// context is Vitest, NODE_ENV=test, or a run id or e2e flag set by the
// harness (apps/desktop/e2e/harness.mjs). There, the real system refuses
// network blocks, Santa block rules, startup items turned off, processes
// paused or stopped and files quarantined, unless the run opts in with
// VIGIL_ALLOW_REAL_ENFORCEMENT=1 (docs/e2e-safety.md). The installed helper
// runs under launchd or systemd with none of these set, so it never trips.

import type { HelperCommand } from './protocol.js';
import { ActionError } from './commands/errors.js';

/** Set to 1 to let a test enforce for real (a throwaway CI runner or VM). */
export const ALLOW_REAL_ENFORCEMENT_ENV = 'VIGIL_ALLOW_REAL_ENFORCEMENT';
/** The id an opted-in run tags its helper actions with, for its teardown. */
export const TEST_RUN_ENV = 'VIGIL_TEST_RUN_ID';
/** Set by the e2e harness on everything it starts. */
export const E2E_ENV = 'VIGIL_E2E';

type Env = Record<string, string | undefined>;

export function inTestContext(env: Env = process.env): boolean {
  return !!(env['VITEST'] || env['NODE_ENV'] === 'test' || env[TEST_RUN_ENV] || env[E2E_ENV]);
}

export function realEnforcementAllowed(env: Env = process.env): boolean {
  return env[ALLOW_REAL_ENFORCEMENT_ENV] === '1';
}

/** Throws `refused` when a test would enforce `what` on the real machine without opting in. */
export function refuseRealEnforcement(what: string, env: Env = process.env): void {
  if (!inTestContext(env) || realEnforcementAllowed(env)) return;
  throw new ActionError(
    'refused',
    `refusing ${what} on the real system from a test; use an isolated helper, ` +
      `or set ${ALLOW_REAL_ENFORCEMENT_ENV}=1 on a throwaway machine (docs/e2e-safety.md)`,
  );
}

/** Helper commands that contain something: what a test must not do for real. */
export function isEnforcing(cmd: HelperCommand): boolean {
  switch (cmd.kind) {
    case 'network.block':
    case 'process.suspend':
    case 'process.kill':
    case 'persistence.disable':
    case 'file.quarantine':
      return true;
    case 'santa.rule.set':
      return cmd.policy !== 'allow';
    default:
      return false;
  }
}

/**
 * What a binary run would enforce on the machine, or undefined when it only
 * reads, undoes or sets up nothing that blocks. Matches how the helper's
 * commands call each binary (commands/*.ts).
 */
export function enforcingRun(bin: string, args: readonly string[]): string | undefined {
  const t = args.indexOf('-T');
  switch (bin) {
    case 'pfctl':
      if (t >= 0 && ['add', 'replace', 'load'].includes(args[t + 1] ?? '')) return 'a pf block';
      if (args.includes('-f')) return 'loading pf rules';
      if (args.includes('-E') || args.includes('-e')) return 'turning pf on';
      if (args.includes('-k')) return 'cutting connections with pf';
      return undefined;
    case 'launchctl':
      return ['bootout', 'unload', 'remove', 'disable', 'kill'].includes(args[0] ?? '')
        ? `launchctl ${args[0]}`
        : undefined;
    case 'santactl':
      return args[0] === 'rule' ? 'a Santa rule' : undefined;
    case 'nft':
      return /\b(add|insert|create)\b/.test(args.join(' ')) ? 'an nftables block' : undefined;
    case 'systemctl':
      return args.some((a) => ['stop', 'disable', 'mask', 'kill'].includes(a))
        ? 'stopping a systemd unit'
        : undefined;
    case 'fagenrules':
      return 'loading fapolicyd block rules';
    default:
      return undefined;
  }
}
