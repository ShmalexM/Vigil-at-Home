import { EventEmitter } from 'node:events';
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

  get(id: string): SensorHealth | undefined {
    return this.sensors.get(id);
  }

  list(): SensorHealth[] {
    return [...this.sensors.values()];
  }
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
