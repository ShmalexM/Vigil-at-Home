import { EventEmitter } from 'node:events';
import { describe, expect, it } from 'vitest';
import { PowerPolicy, type PowerSource, type ThermalState } from './power.js';

function fakeSource(battery = false, thermal: ThermalState = 'nominal') {
  const em = new EventEmitter();
  const source = {
    isOnBatteryPower: () => battery,
    getCurrentThermalState: () => thermal,
    on: em.on.bind(em),
  } as unknown as PowerSource;
  return { source, emit: (event: string, arg?: unknown) => em.emit(event, arg) };
}

describe('PowerPolicy', () => {
  it('starts from the current power state', () => {
    expect(new PowerPolicy(fakeSource(false).source, () => 0).mode).toBe('normal');
    expect(new PowerPolicy(fakeSource(true).source, () => 0).mode).toBe('saving');
    expect(new PowerPolicy(fakeSource(false, 'serious').source, () => 0).mode).toBe('constrained');
  });

  it('follows battery, heat and sleep, and announces each change once', () => {
    const { source, emit } = fakeSource();
    const p = new PowerPolicy(source, () => 0);
    const seen: string[] = [];
    p.on('change', (m) => seen.push(m));
    emit('on-battery');
    emit('on-battery');
    emit('thermal-state-change', { state: 'critical' });
    emit('thermal-state-change', { state: 'fair' });
    emit('suspend');
    emit('resume');
    emit('on-ac');
    expect(seen).toEqual(['saving', 'constrained', 'saving', 'constrained', 'saving', 'normal']);
  });

  it('is busy off mains power or when the Mac is loaded', () => {
    let load = 0.1;
    const { source, emit } = fakeSource();
    const p = new PowerPolicy(source, () => load);
    expect(p.isBusy()).toBe(false);
    load = 0.95;
    expect(p.isBusy()).toBe(true);
    load = 0.1;
    emit('on-battery');
    expect(p.isBusy()).toBe(true);
  });

  it('says whether it is busy from power (battery, heat) or only from load', () => {
    let load = 0.95;
    const { source, emit } = fakeSource();
    const p = new PowerPolicy(source, () => load);
    expect(p.busyReason()).toBe('load');
    load = 0.1;
    expect(p.busyReason()).toBeUndefined();
    emit('on-battery');
    expect(p.busyReason()).toBe('power');
    emit('on-ac');
    emit('thermal-state-change', { state: 'serious' });
    load = 0.95;
    expect(p.busyReason()).toBe('power');
  });
});
