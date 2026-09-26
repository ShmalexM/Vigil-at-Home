import { compareSeverity, type Alert } from '@vigil/core';

export type Level = 'good' | 'fair' | 'poor';

export interface SensorHealth {
  /** Stable id, e.g. `osquery`, `santa`, `helper`. */
  id: string;
  name: string;
  state: 'ok' | 'degraded' | 'down' | 'not_installed';
  detail?: string;
}

export interface Status {
  level: Level;
  /** Open alerts that need the user's decision. */
  needsYou: number;
  reasons: string[];
}

/**
 * Overall health for the menu-bar icon and Home.
 * - Poor: something serious is running uncontained, or a sensor is down.
 * - Fair: alerts wait on the user, or protection is partial.
 * - Good: nothing needs the user.
 */
export function computeStatus(
  openAlerts: readonly Alert[],
  sensors: readonly SensorHealth[],
): Status {
  const reasons: string[] = [];
  let level: Level = 'good';
  const raise = (to: Level) => {
    if (to === 'poor' || (to === 'fair' && level === 'good')) level = to;
  };

  const needsYou = openAlerts.filter((a) => !a.decision).length;
  const uncontained = openAlerts.filter(
    (a) => a.containment !== 'active' && compareSeverity(a.severity, 'high') >= 0,
  );
  if (uncontained.length > 0) {
    raise('poor');
    reasons.push(`${plural(uncontained.length, 'serious alert')} not contained`);
  }
  if (needsYou > 0) {
    raise('fair');
    reasons.push(`${plural(needsYou, 'alert')} waiting on you`);
  }
  for (const s of sensors) {
    if (s.state === 'down') {
      raise('poor');
      reasons.push(`${s.name} is not running`);
    } else if (s.state === 'not_installed') {
      raise('fair');
      reasons.push(`${s.name} is not installed`);
    } else if (s.state === 'degraded') {
      raise('fair');
      reasons.push(s.detail ?? `${s.name} is degraded`);
    }
  }
  return { level, needsYou, reasons };
}

function plural(n: number, word: string): string {
  return `${n} ${word}${n === 1 ? '' : 's'}`;
}
