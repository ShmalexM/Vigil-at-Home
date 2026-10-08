import type { Alert } from '@vigil/core';
import { isNoticed, needsDecision } from '../shared/attention.js';
import { pileUp } from '../shared/piles.js';

export type Level = 'good' | 'fair' | 'poor';

export interface SensorHealth {
  /** Stable id, e.g. `osquery`, `santa`, `helper`. */
  id: string;
  name: string;
  state: 'ok' | 'degraded' | 'down' | 'not_installed';
  /** What the layer does, e.g. "Blocks programs before they run". */
  detail?: string;
  /** Why it is in this state, when that isn't obvious, e.g. "No events for 12 minutes". */
  note?: string;
  /** A fix Vigil can offer on the spot: santa-sync issues Santa a new sync certificate. */
  repair?: 'santa-sync';
  /**
   * Santa: the last connection the sync port turned away. A detail only,
   * never a reason for the level: any local program can open the port.
   */
  lastRefusal?: {
    at: number;
    reason: 'no_certificate' | 'wrong_certificate' | 'handshake_failed';
  };
}

export interface Status {
  /** How protection itself is doing: the layers only, never alerts. */
  level: Level;
  /** Open alerts that need the user's decision (shared/attention.ts). Shown apart from the level. */
  needsYou: number;
  /** Open alerts Vigil only noticed. */
  noticed: number;
  /** Why protection isn't Good, most serious first. Empty when every layer runs. */
  reasons: string[];
}

/**
 * Two separate answers for the menu-bar icon, the sidebar and Home: is
 * protection running (the level), and does anything need the user (needsYou).
 * An alert waiting on a decision never makes working protection look broken;
 * Needs you carries it. The level rules are spelled out to the user in
 * shared/levels.ts (LEVEL_RULES); keep them in step.
 * - Poor: an installed protection layer has stopped.
 * - Fair: a layer is missing or not working fully.
 * - Good: every layer is running.
 * Reasons come most serious first, so the first one is always why the level is what it is.
 */
export function computeStatus(
  openAlerts: readonly Alert[],
  sensors: readonly SensorHealth[],
): Status {
  const poor: string[] = [];
  const fair: string[] = [];
  for (const s of sensors) {
    if (s.state === 'down') poor.push(`${s.name} has stopped`);
    else if (s.state === 'not_installed') fair.push(`${s.name} is not installed`);
    else if (s.state === 'degraded') {
      fair.push(s.note ? `${s.name}: ${s.note}` : `${s.name} isn’t working fully`);
    }
  }
  const level: Level = poor.length ? 'poor' : fair.length ? 'fair' : 'good';
  return {
    level,
    // A pile is one decision, so it counts once.
    needsYou: pileUp(openAlerts.filter(needsDecision)).length,
    noticed: openAlerts.filter(isNoticed).length,
    reasons: [...poor, ...fair],
  };
}
