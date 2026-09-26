import { randomUUID } from "node:crypto";
import type { DetectionEngine } from "./engine.js";
import { assertUserOrigin, type UserOrigin } from "./origin.js";
import type { RuleException, Verdict } from "./state/stores.js";
import { STAGES, type Detection, type SantaSuggestion, type SensorEvent, type Stage } from "./types.js";

/** List the built-in "user-blocked" rules read. Confirming a detection adds to it. */
export const USER_BLOCKED_HASHES = "user_blocked_sha256";

export interface DemotionPolicy {
  /** Look at verdicts from this many days back. */
  windowDays: number;
  /** Demote once at least this many detections were marked benign... */
  minBenign: number;
  /** ...and they are at least this share of all verdicts. */
  benignShare: number;
}

export const DEFAULT_DEMOTION: DemotionPolicy = { windowDays: 30, minBenign: 3, benignShare: 0.5 };

/** How narrowly a "this is fine" answer applies. Narrowest that has a value wins by default. */
export type ExceptionScope = "hash" | "signer" | "path" | "none";

export interface VerdictResult {
  exception?: RuleException;
  /** Set when the rule was moved down a stage because it keeps being wrong. */
  demoted?: { ruleId: string; from: Stage; to: Stage; message: string };
  /** Set when the user confirmed a threat: the Santa rule to install. */
  santaSuggestion?: SantaSuggestion;
}

function stageBelow(s: Stage): Stage {
  const i = STAGES.indexOf(s);
  return STAGES[Math.max(0, i - 1)]!;
}

function exceptionFor(
  scope: ExceptionScope,
  ruleId: string,
  e: SensorEvent | undefined,
  d: Detection,
  ts: number,
): RuleException | undefined {
  const p = e?.process;
  const pick = (): { field: string; value: string } | undefined => {
    const byHash = d.subject.sha256 ? { field: "process.sha256", value: d.subject.sha256 } : undefined;
    const bySigner = p?.signing?.signingId && p.signing.teamId
      ? { field: "process.signing.signingId", value: p.signing.signingId }
      : undefined;
    const byPath =
      d.subject.processPath ? { field: "process.path", value: d.subject.processPath }
      : d.subject.itemPath ? { field: "persistence.itemPath", value: d.subject.itemPath }
      : d.subject.domain ? { field: "network.domain", value: d.subject.domain }
      : d.subject.remoteAddress ? { field: "network.remoteAddress", value: d.subject.remoteAddress }
      : undefined;
    if (scope === "hash") return byHash;
    if (scope === "signer") return bySigner;
    if (scope === "path") return byPath;
    return undefined;
  };
  const f = pick();
  if (!f) return undefined;
  return { id: randomUUID(), ruleId, field: f.field, value: f.value, createdAt: ts, note: `Marked safe from detection ${d.id}` };
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
   * The user's answer to a detection. "benign" adds a narrow exception and may
   * demote a rule that keeps being wrong. "malicious" adds the hash to the
   * user-blocked list and returns the Santa rule to install.
   */
  recordVerdict(
    d: Detection,
    verdict: Verdict,
    origin: UserOrigin,
    opts: { event?: SensorEvent; scope?: ExceptionScope } = {},
  ): VerdictResult {
    assertUserOrigin(origin);
    const ts = this.now();
    const { ruleState, exceptions, lists } = this.engine.stores;
    ruleState.recordVerdict({ detectionId: d.id, ruleId: d.ruleId, verdict, ts });
    const result: VerdictResult = {};

    if (verdict === "malicious") {
      if (d.subject.sha256) lists.add(USER_BLOCKED_HASHES, d.subject.sha256, { source: "user", updatedAt: ts });
      result.santaSuggestion =
        d.santaSuggestion ??
        (d.subject.sha256
          ? { policy: "BLOCKLIST", ruleType: "BINARY", identifier: d.subject.sha256, customMsg: d.title }
          : undefined);
      return result;
    }

    const scope = opts.scope ?? (d.subject.sha256 ? "hash" : "path");
    const ex = exceptionFor(scope, d.ruleId, opts.event, d, ts);
    if (ex) {
      exceptions.add(ex);
      result.exception = ex;
    }

    const rule = this.engine.getRule(d.ruleId);
    if (rule) {
      const since = ts - this.policy.windowDays * 86_400_000;
      const vs = ruleState.verdicts(d.ruleId, since);
      const benign = vs.filter((v) => v.verdict === "benign").length;
      const current = this.engine.stageOf(rule);
      if (benign >= this.policy.minBenign && benign / vs.length >= this.policy.benignShare && current !== "shadow") {
        const to = stageBelow(current);
        this.engine._setStage(d.ruleId, to);
        result.demoted = {
          ruleId: d.ruleId,
          from: current,
          to,
          message: `"${rule.title}" was wrong ${benign} of the last ${vs.length} times, so Vigil moved it from ${current} to ${to}. You can move it back in Rules.`,
        };
      }
    }
    return result;
  }

  /** Only the user moves a rule up. */
  setStage(ruleId: string, stage: Stage, origin: UserOrigin): void {
    assertUserOrigin(origin);
    if (!this.engine.getRule(ruleId)) throw new Error(`no rule ${ruleId}`);
    this.engine._setStage(ruleId, stage);
  }

  removeException(id: string, origin: UserOrigin): void {
    assertUserOrigin(origin);
    this.engine.stores.exceptions.remove(id);
  }
}
