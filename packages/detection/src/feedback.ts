import { canChangeMode, newId, type RuleMode, type UserDecision } from '@vigil/core';
import { isAgentField } from './agents/fields.js';
import type { DetectionEngine } from './engine.js';
import { assertUserOrigin, type UserOrigin } from './origin.js';
import { shellCommand } from './safety.js';
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
  /**
   * Set when the rule keeps being wrong and could move down a mode. Nothing
   * changes: the app queues it as a suggestion only the user can approve.
   */
  suggestDemotion?: { ruleId: string; from: RuleMode; to: 'alert' | 'shadow'; message: string };
  /** Set when the user confirmed a threat: the Santa rule to add so it cannot start again. */
  santa?: NonNullable<Detection['santa']>;
  /**
   * Set when the user confirmed a threat but the program must not be blocked
   * (part of macOS, a shell, Vigil itself): the block refused and why, in
   * words for the user. Nothing was added to the user-blocked list.
   */
  blockRefused?: { santa: NonNullable<Detection['santa']>; message: string };
}

/** What taking back a "malicious" verdict changed. */
export interface UndoBlockResult {
  /** The hash taken off the user-blocked list, when it was on it. */
  unlisted?: string;
  /** The Santa rule to remove: the one the verdict added. */
  santa?: { kind: 'santa.rule.remove'; ruleType: SantaRuleType; identifier: string };
}

type SantaRuleType = NonNullable<Detection['santa']>['ruleType'];

/** The Santa rule a "malicious" verdict adds for this detection, if any. */
function verdictBlock(d: Detection): NonNullable<Detection['santa']> | undefined {
  if (d.santa) return d.santa;
  const e = d.event;
  const sha = 'process' in e ? e.process?.sha256 : undefined;
  return sha
    ? {
        kind: 'santa.rule.set',
        ruleType: 'binary',
        identifier: sha,
        policy: 'block',
        message: d.alert?.title ?? d.match.ruleId,
      }
    : undefined;
}

/**
 * Why a confirmed threat was not blocked, in words for the user. A shell
 * running `-c <command>` names the program it ran: that is what to block.
 */
function refusedMessage(d: Detection, why: string): string {
  const e = d.event;
  const p = 'process' in e ? e.process : undefined;
  const cmd = p && shellCommand(p);
  if (p && cmd) {
    const shown = cmd.length > 120 ? `${cmd.slice(0, 117)}...` : cmd;
    const target = cmd.split(/\s+/)[0]?.replace(/^["']|["']$/g, '');
    return (
      `Vigil did not block ${p.path}: ${why}. It was only the shell that ran \`${shown}\`. ` +
      `If ${target} is the threat, block it from its own alert.`
    );
  }
  return `Vigil did not block ${p?.path ?? 'this program'}: ${why}.`;
}

const QUIETER: Partial<Record<RuleMode, 'alert' | 'shadow'>> = { block: 'alert', alert: 'shadow' };
const MODE_NAME: Record<RuleMode, string> = {
  block: 'Block',
  alert: 'Alert',
  shadow: 'Shadow',
  disabled: 'Off',
};

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
 * Refuse an exception that names only an agent or its tool request, e.g.
 * `{ 'process.agent.id': 'claude-code' }`: it would silence the rule for
 * everything that agent does. Exceptions name a program, signer or thing, so
 * an empty match is refused too.
 */
export function assertExceptionScope(match: Record<string, string>): void {
  if (Object.keys(match).every(isAgentField)) throw new Error('exception too broad');
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
   * Benign and expected answers count toward suggesting a quieter mode for a rule that keeps
   * being wrong; the rule itself stays as it is until the user approves.
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
      const santa = verdictBlock(d);
      // The floor every rule's block passes through, for the rule returned
      // and for the hash listed: the user-blocked rule turns a listed hash
      // into a Santa block of its own.
      const byHash = sha
        ? {
            kind: 'santa.rule.set' as const,
            ruleType: 'binary' as const,
            identifier: sha,
            policy: 'block' as const,
          }
        : undefined;
      for (const a of [santa, byHash]) {
        const why = a && this.engine.refusal(a, e);
        if (a && why) {
          result.blockRefused = { santa: a, message: refusedMessage(d, why) };
          return result;
        }
      }
      if (sha) lists.add(USER_BLOCKED_HASHES, sha, { source: 'user', updatedAt: ts });
      if (santa) result.santa = santa;
      return result;
    }

    if (decision.remember && decision.scope) {
      if (decision.scope === 'this_rule') {
        this.engine._setMode(ruleId, 'shadow');
      } else {
        const match = exceptionMatch(decision.scope, d);
        if (match) {
          assertExceptionScope(match);
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
        result.suggestDemotion = {
          ruleId,
          from: current,
          to,
          message: `You marked "${rule.name}" as not a real threat ${wrong} of the last ${vs.length} times. Move it from ${MODE_NAME[current]} to ${MODE_NAME[to]}?`,
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

  /** Put a rule back in its own mode, for an undo that restores "no override". */
  clearMode(ruleId: string, origin: UserOrigin): void {
    assertUserOrigin(origin);
    if (!this.engine.getRule(ruleId)) throw new Error(`no rule ${ruleId}`);
    this.engine._clearMode(ruleId);
  }

  /**
   * Take back a "malicious" verdict (the user reopened the alert): the hash
   * leaves the user-blocked list, and the Santa rule the verdict added is
   * returned for the app to remove through the helper, which asks the user.
   * A hash the list does not hold (a block that was refused, or one already
   * undone) returns nothing to remove.
   */
  undoBlock(d: Detection, origin: UserOrigin): UndoBlockResult {
    assertUserOrigin(origin);
    const santa = verdictBlock(d);
    if (!santa) return {};
    const e = d.event;
    const sha = 'process' in e ? e.process?.sha256 : undefined;
    const lists = this.engine.stores.lists;
    const result: UndoBlockResult = {};
    if (sha && lists.remove(USER_BLOCKED_HASHES, sha)) result.unlisted = sha;
    if (result.unlisted || !sha) {
      result.santa = {
        kind: 'santa.rule.remove',
        ruleType: santa.ruleType,
        identifier: santa.identifier,
      };
    }
    return result;
  }

  removeException(id: string, origin: UserOrigin): void {
    assertUserOrigin(origin);
    this.engine.stores.exceptions.remove(id);
  }
}
