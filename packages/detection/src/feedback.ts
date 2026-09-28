import { canChangeMode, newId, type RuleMode, type UserDecision } from '@vigil/core';
import type { DetectionEngine } from './engine.js';
import { assertUserOrigin, type UserOrigin } from './origin.js';
import type { RuleException } from './state/stores.js';
import type { Detection } from './types.js';

/** List the built-in "user-blocked" rule reads. Confirming a detection adds its hash here. */
export const USER_BLOCKED_HASHES = 'user_blocked_sha256';

export interface DemotionPolicy {
  /** Look at verdicts from this many days back. */
  windowDays: number;
  /** Demote once at least this many detections were marked benign or expected... */
  minWrong: number;
  /** ...and they are at least this share of all verdicts. */
  wrongShare: number;
}

export const DEFAULT_DEMOTION: DemotionPolicy = { windowDays: 30, minWrong: 3, wrongShare: 0.5 };

export interface DecisionResult {
  exception?: RuleException;
  /** Set when the rule was moved down a mode because it keeps being wrong. */
  demoted?: { ruleId: string; from: RuleMode; to: RuleMode; message: string };
  /** Set when the user confirmed a threat: the Santa rule to add so it cannot start again. */
  santa?: NonNullable<Detection['santa']>;
}

const QUIETER: Partial<Record<RuleMode, RuleMode>> = { block: 'alert', alert: 'shadow' };

/** The narrowest exception for the scope the user picked, or undefined when the event lacks it. */
function exceptionMatch(
  scope: NonNullable<UserDecision['scope']>,
  d: Detection,
): Record<string, string> | undefined {
  const e = d.event;
  const p = 'process' in e ? e.process : undefined;
  if (scope === 'this_binary') {
    if (p?.sha256) return { 'process.sha256': p.sha256 };
    if (p?.cdhash) return { 'process.cdhash': p.cdhash };
    if (p) return { 'process.path': p.path };
    if ('path' in e && e.path) return { path: e.path };
    if (e.kind === 'network.connection') {
      return e.remoteHost ? { remoteHost: e.remoteHost } : { remoteAddress: e.remoteAddress };
    }
    if (e.kind === 'browser.extension') return { extensionId: e.extensionId };
    return undefined;
  }
  if (scope === 'this_signer') {
    // Team ID is required: an ad-hoc signature can claim any signing ID.
    if (p?.teamId && p.signingId) {
      return { 'process.teamId': p.teamId, 'process.signingId': p.signingId };
    }
    return undefined;
  }
  return undefined;
}

/**
 * Everything the user can do to rules. Every method needs a UserOrigin, so
 * none of it is reachable from the AI tool surface.
 */
export class Feedback {
  constructor(
    private readonly engine: DetectionEngine,
    private readonly policy: DemotionPolicy = DEFAULT_DEMOTION,
    private readonly now: () => number = Date.now,
  ) {}

  /**
   * The user's call on a detection (core's UserDecision).
   * - malicious: adds the hash to the user-blocked list and returns the Santa rule to add.
   * - benign or expected with `remember`: adds an exception for this binary or signer, or
   *   quiets the whole rule for `this_rule`.
   * Benign and expected answers count toward demoting a rule that keeps being wrong.
   */
  recordDecision(d: Detection, decision: UserDecision, origin: UserOrigin): DecisionResult {
    assertUserOrigin(origin);
    const ts = this.now();
    const { ruleState, exceptions, lists } = this.engine.stores;
    const ruleId = d.match.ruleId;
    ruleState.recordVerdict({ detectionId: d.match.id, ruleId, verdict: decision.verdict, ts });
    const result: DecisionResult = {};

    if (decision.verdict === 'malicious') {
      const e = d.event;
      const sha = 'process' in e ? e.process?.sha256 : undefined;
      if (sha) lists.add(USER_BLOCKED_HASHES, sha, { source: 'user', updatedAt: ts });
      const santa =
        d.santa ??
        (sha
          ? {
              kind: 'santa.rule.set' as const,
              ruleType: 'binary' as const,
              identifier: sha,
              policy: 'block' as const,
              message: d.alert?.title ?? ruleId,
            }
          : undefined);
      if (santa) result.santa = santa;
      return result;
    }

    if (decision.remember && decision.scope) {
      if (decision.scope === 'this_rule') {
        this.engine._setMode(ruleId, 'shadow');
      } else {
        const match = exceptionMatch(decision.scope, d);
        if (match) {
          const ex: RuleException = { id: newId(ts), ruleId, match, createdAt: ts };
          ex.note = decision.note ?? `Marked safe from alert ${d.alert?.id ?? d.match.id}`;
          exceptions.add(ex);
          result.exception = ex;
        }
      }
    }

    const rule = this.engine.getRule(ruleId);
    if (rule) {
      const since = ts - this.policy.windowDays * 86_400_000;
      const vs = ruleState.verdicts(ruleId, since);
      const wrong = vs.filter((v) => v.verdict !== 'malicious').length;
      const current = this.engine.modeOf(rule);
      const to = QUIETER[current];
      if (
        to &&
        wrong >= this.policy.minWrong &&
        wrong / vs.length >= this.policy.wrongShare &&
        canChangeMode('rule', current, to)
      ) {
        this.engine._setMode(ruleId, to);
        result.demoted = {
          ruleId,
          from: current,
          to,
          message: `"${rule.name}" was not a real threat ${wrong} of the last ${vs.length} times, so Vigil moved it from ${current} to ${to}. You can move it back in Rules.`,
        };
      }
    }
    return result;
  }

  /** Any mode change the user asks for. Only the user makes a rule louder. */
  setMode(ruleId: string, mode: RuleMode, origin: UserOrigin): void {
    assertUserOrigin(origin);
    if (!this.engine.getRule(ruleId)) throw new Error(`no rule ${ruleId}`);
    this.engine._setMode(ruleId, mode);
  }

  removeException(id: string, origin: UserOrigin): void {
    assertUserOrigin(origin);
    this.engine.stores.exceptions.remove(id);
  }
}
