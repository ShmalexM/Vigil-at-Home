import { EventEmitter } from 'node:events';
import { linearEngine } from '@vigil/detection';
import type { SensorHealth } from './status.js';

/**
 * Health of each protection layer. The sensor and helper packages call
 * `report` as their state changes; the menu-bar status reads `list`.
 */
export class SensorRegistry extends EventEmitter<{ changed: [] }> {
  private readonly sensors = new Map<string, SensorHealth>();

  constructor(initial: SensorHealth[] = DEFAULT_SENSORS) {
    super();
    for (const s of initial) this.sensors.set(s.id, s);
  }

  report(health: SensorHealth): void {
    this.sensors.set(health.id, health);
    this.emit('changed');
  }

  /** Take a row away, e.g. the threat-feeds line once nothing is held back. */
  remove(id: string): void {
    if (this.sensors.delete(id)) this.emit('changed');
  }

  get(id: string): SensorHealth | undefined {
    return this.sensors.get(id);
  }

  list(): SensorHealth[] {
    return [...this.sensors.values()];
  }
}

/**
 * One line when this runtime has no linear-time regex engine, checked at
 * startup; undefined when it has. Without it, a new rule's regex is refused
 * and older saved ones run as they did, without the time limit.
 */
export function ruleMatcherHealth(): SensorHealth | undefined {
  if (linearEngine()) return undefined;
  return {
    id: 'rule-matcher',
    name: 'Rule matcher',
    state: 'degraded',
    detail: 'Runs the patterns in rules you and AI write in limited time',
    note: 'Not available in this copy of Vigil: new rules can’t use regexes, and older ones run without a time limit',
  };
}

export const DEFAULT_SENSORS: SensorHealth[] = [
  { id: 'santa', name: 'Santa', state: 'not_installed', detail: 'Blocks programs before they run' },
  {
    id: 'osquery',
    name: 'osquery',
    state: 'not_installed',
    detail: 'Watches processes, files and network',
  },
  {
    id: 'helper',
    name: 'Vigil helper',
    state: 'not_installed',
    detail: 'Suspends, firewalls and quarantines',
  },
];
