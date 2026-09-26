import { newId, type Rule, type SensorEvent } from '@vigil/core';
import type { AlertService } from './alerts.js';

/** Raised from Settings so the user can see what a detection looks like. Runs no actions. */
export const TEST_RULE: Rule = {
  id: 'vigil.test-alert',
  version: 1,
  name: 'Test alert',
  description:
    'You asked Vigil to show a test alert. Nothing was blocked and nothing on your Mac changed.',
  origin: 'builtin',
  mode: 'alert',
  severity: 'medium',
  fidelity: 'high',
  eventKinds: ['process.exec'],
  condition: { field: 'process.path', op: 'eq', value: '/usr/bin/true' },
  response: [],
  exclusions: [],
  reasons: [],
  tags: [],
  createdAt: 0,
  updatedAt: 0,
};

export function sendTestAlert(alerts: AlertService, now = Date.now()) {
  const event: SensorEvent = {
    id: newId(now),
    ts: now,
    source: 'vigil',
    kind: 'process.exec',
    process: {
      pid: process.pid,
      path: '/usr/bin/true',
      args: ['true'],
      signing: 'apple',
      parentPath: '/Applications/Vigil at Home.app',
    },
  };
  return alerts.raise({
    rule: TEST_RULE,
    events: [event],
    actions: [],
    title: 'Test alert',
    subject: { kind: 'process', label: 'true', path: '/usr/bin/true' },
  });
}
