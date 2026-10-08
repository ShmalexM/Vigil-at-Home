import { describe, expect, it } from 'vitest';
import { defaultSensors, SensorRegistry } from './sensors.js';
import { computeStatus } from './status.js';

describe('defaultSensors', () => {
  it('lists Santa on macOS and fapolicyd on Linux, in the order health checks report them', () => {
    expect(defaultSensors('darwin').map((s) => s.id)).toEqual(['santa', 'osquery', 'helper']);
    expect(defaultSensors('linux').map((s) => s.id)).toEqual(['fapolicyd', 'osquery', 'helper']);
  });

  it('lets a Linux computer reach Good once its own layers run', () => {
    const reg = new SensorRegistry(defaultSensors('linux'));
    for (const s of reg.list()) reg.report({ ...s, state: 'ok' });
    expect(computeStatus([], reg.list()).level).toBe('good');
  });
});
