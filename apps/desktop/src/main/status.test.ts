import type { Alert } from '@vigil/core';
import { describe, expect, it } from 'vitest';
import { computeStatus } from './status.js';

const alert = (over: Partial<Alert>): Alert => ({
  id: 'a',
  createdAt: 1,
  updatedAt: 1,
  ruleId: 'r',
  ruleVersion: 1,
  title: 't',
  summary: 's',
  severity: 'high',
  fidelity: 'high',
  notify: 'popup',
  status: 'open',
  containment: 'active',
  eventIds: ['e'],
  actionIds: [],
  ...over,
});

describe('computeStatus', () => {
  const ok = [{ id: 'osquery', name: 'osquery', state: 'ok' as const }];

  it('is good when nothing needs the user', () => {
    expect(computeStatus([], ok)).toEqual({ level: 'good', needsYou: 0, reasons: [] });
  });

  it('is fair when a contained alert waits on the user', () => {
    expect(computeStatus([alert({})], ok)).toMatchObject({ level: 'fair', needsYou: 1 });
  });

  it('is poor when a serious alert is not contained or a sensor is down', () => {
    expect(computeStatus([alert({ containment: 'none' })], ok).level).toBe('poor');
    expect(computeStatus([], [{ id: 'santa', name: 'Santa', state: 'down' }]).level).toBe('poor');
  });

  it('is fair when a sensor is missing', () => {
    const s = computeStatus([], [{ id: 'santa', name: 'Santa', state: 'not_installed' }]);
    expect(s).toMatchObject({ level: 'fair', reasons: ['Santa is not installed'] });
  });
});
