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

  it('is good when every layer runs and nothing needs the user', () => {
    expect(computeStatus([], ok)).toEqual({
      level: 'good',
      needsYou: 0,
      noticed: 0,
      noticedClearable: 0,
      reasons: [],
    });
  });

  it('keeps protection good while an alert waits on the user, and counts it apart', () => {
    expect(computeStatus([alert({})], ok)).toEqual({
      level: 'good',
      needsYou: 1,
      noticed: 0,
      noticedClearable: 0,
      reasons: [],
    });
    expect(computeStatus([alert({ containment: 'none', severity: 'critical' })], ok)).toMatchObject(
      { level: 'good', needsYou: 1 },
    );
  });

  it('is poor when an installed layer has stopped', () => {
    expect(computeStatus([], [{ id: 'santa', name: 'Santa', state: 'down' }]).level).toBe('poor');
  });

  it('counts what Vigil only noticed without touching the level', () => {
    const noticed = alert({
      severity: 'medium',
      fidelity: 'medium',
      notify: 'badge',
      containment: 'none',
    });
    expect(computeStatus([noticed, noticed], ok)).toEqual({
      level: 'good',
      needsYou: 0,
      noticed: 2,
      noticedClearable: 2,
      reasons: [],
    });
  });

  it('is fair when a layer is missing', () => {
    const s = computeStatus([], [{ id: 'santa', name: 'Santa', state: 'not_installed' }]);
    expect(s).toMatchObject({ level: 'fair', reasons: ['Santa is not installed'] });
  });

  it('puts the reason that sets the level first, and leaves alerts out of the reasons', () => {
    const s = computeStatus(
      [alert({})],
      [
        { id: 'santa', name: 'Santa', state: 'not_installed' },
        { id: 'osquery', name: 'osquery', state: 'down' },
      ],
    );
    expect(s.level).toBe('poor');
    expect(s.needsYou).toBe(1);
    expect(s.reasons).toEqual(['osquery has stopped', 'Santa is not installed']);
  });
});
