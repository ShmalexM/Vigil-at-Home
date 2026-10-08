import { describe, expect, it } from 'vitest';
import { defaultSensors, SensorRegistry } from './sensors.js';

describe('defaultSensors', () => {
  it('lists Santa on macOS and fapolicyd on Linux, never both', () => {
    expect(defaultSensors('darwin').map((s) => s.id)).toEqual(['santa', 'osquery', 'helper']);
    expect(defaultSensors('linux').map((s) => s.id)).toEqual(['fapolicyd', 'osquery', 'helper']);
  });

  it('hands out copies, so one registry never changes another', () => {
    const a = new SensorRegistry(defaultSensors('linux'));
    a.report({ id: 'osquery', name: 'osquery', state: 'ok' });
    expect(defaultSensors('linux')[1]!.state).toBe('not_installed');
  });
});
