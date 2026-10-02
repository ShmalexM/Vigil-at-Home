import { compareSeverity, type Alert } from '@vigil/core';
import { isNoticed, needsDecision } from '../shared/attention.js';

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
}

export interface Status {
  level: Level;
  /** Open alerts that need the user's decision (shared/attention.ts). */
  needsYou: number;
  /** Open alerts Vigil only noticed: shown, but they don't count against the level. */
  noticed: number;
  reasons: string[];
}

/**
 * Overall health for the menu-bar icon, the sidebar and Home. The rules are
 * spelled out to the user in shared/levels.ts (LEVEL_RULES); keep them in step.
 * - Poor: a high or critical alert isn't contained, or an installed protection
 *   layer has stopped.
 * - Fair: an alert needs the user's decision, or a layer is missing or not working fully.
 * - Good: none of the above. Medium and low alerts that Vigil only noticed
 *   (nothing held, no popup) don't lower the level; they are usually the user.
 * Reasons come most serious first, so the first one is always why the level is what it is.
 */
export function computeStatus(
  openAlerts: readonly Alert[],
  sensors: readonly SensorHealth[],
): Status {
  const poor: string[] = [];
  const fair: string[] = [];

  const needsYou = openAlerts.filter(needsDecision).length;
  const noticed = openAlerts.filter(isNoticed).length;
  const uncontained = openAlerts.filter(
    (a) => a.containment !== 'active' && compareSeverity(a.severity, 'high') >= 0,
  );
  if (uncontained.length > 0) {
    poor.push(`${plural(uncontained.length, 'serious alert')} not contained`);
  }
  for (const s of sensors) {
    if (s.state === 'down') poor.push(`${s.name} has stopped`);
  }
  if (needsYou > 0) fair.push(`${plural(needsYou, 'alert')} waiting on you`);
  for (const s of sensors) {
    if (s.state === 'not_installed') fair.push(`${s.name} is not installed`);
    else if (s.state === 'degraded') {
      fair.push(s.note ? `${s.name}: ${s.note}` : `${s.name} isn’t working fully`);
    }
  }
  const level: Level = poor.length ? 'poor' : fair.length ? 'fair' : 'good';
  return { level, needsYou, noticed, reasons: [...poor, ...fair] };
}

function plural(n: number, word: string): string {
  return `${n} ${word}${n === 1 ? '' : 's'}`;
}
