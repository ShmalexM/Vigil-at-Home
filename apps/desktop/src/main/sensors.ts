import { EventEmitter } from 'node:events';
import type { SensorHealth } from './status.js';

/**
 * Health of each protection layer. The sensor and helper packages call
 * `report` as their state changes; the menu-bar status reads `list`.
 */
export class SensorRegistry extends EventEmitter<{ changed: [] }> {
  private readonly sensors = new Map<string, SensorHealth>();

  constructor(initial: SensorHealth[] = defaultSensors()) {
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

/**
 * Linux's layers, in the order checkHealth reports them. Santa is macOS only,
 * so starting from the Mac list would leave "Santa is not installed" on a
 * Linux Home and menu bar for good.
 */
export const LINUX_DEFAULT_SENSORS: SensorHealth[] = [
  {
    id: 'fapolicyd',
    name: 'fapolicyd',
    state: 'not_installed',
    detail: 'Blocks programs before they run',
  },
  DEFAULT_SENSORS[1]!,
  DEFAULT_SENSORS[2]!,
];

/** The layers to show before the first health check, for this OS. */
export function defaultSensors(platform: NodeJS.Platform = process.platform): SensorHealth[] {
  return (platform === 'linux' ? LINUX_DEFAULT_SENSORS : DEFAULT_SENSORS).map((s) => ({ ...s }));
}
