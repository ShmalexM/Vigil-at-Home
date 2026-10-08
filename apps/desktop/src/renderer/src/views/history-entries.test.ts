import { describe, expect, it } from 'vitest';
import type { ActionRecord, Alert } from '@vigil/core';
import { filterEntries, historyEntries, outcome } from './history-entries';

const now = Date.UTC(2026, 9, 2, 12);
const alert = (id: string, at: number, extra: Partial<Alert> = {}): Alert => ({
  id,
  createdAt: at,
  updatedAt: at,
  ruleId: 'r',
  ruleVersion: 1,
  title: id,
  summary: '',
  severity: 'medium',
  fidelity: 'high',
  notify: 'badge',
  status: 'resolved',
  containment: 'none',
  eventIds: ['e'],
  actionIds: [],
  ...extra,
});
const action = (id: string, at: number, alertId?: string): ActionRecord => ({
  id,
  action: { kind: 'process.suspend', pid: 1 } as ActionRecord['action'],
  actor: 'rule',
  ...(alertId ? { alertId } : {}),
  reason: '',
  requestedAt: at,
  status: 'done',
});

describe('historyEntries', () => {
  it('puts actions under their handled alert and lists the rest on their own', () => {
    const entries = historyEntries(
      [alert('a1', now - 1000)],
      [
        action('x1', now - 2000, 'a1'),
        action('x2', now - 500, 'open-alert'),
        action('x3', now - 3000),
      ],
      now,
    );
    expect(entries.map((e) => (e.kind === 'alert' ? e.alert.id : e.record.id))).toEqual([
      'x2',
      'a1',
      'x3',
    ]);
    const first = entries[1];
    expect(first?.kind === 'alert' && first.actions.map((r) => r.id)).toEqual(['x1']);
  });

  it('leaves out anything older than 30 days', () => {
    expect(historyEntries([alert('old', now - 31 * 86_400_000)], [], now)).toEqual([]);
  });
});

const ran = (simulated: boolean | undefined, over: Partial<ActionRecord> = {}): ActionRecord => ({
  ...action(`r${String(simulated)}`, 1, 'a'),
  result: { at: 1, ...(simulated === undefined ? {} : { simulated }) },
  ...over,
});
const real = ran(false);
const dry = ran(true);
const kill = (simulated: boolean) =>
  ran(simulated, { action: { kind: 'process.kill', pid: 1 } as ActionRecord['action'] });

describe('outcome', () => {
  it('says what happened in plain words', () => {
    const t = 1;
    expect(outcome(alert('a', t, { containment: 'active' }), [real])).toBe('Still blocked');
    expect(
      outcome(alert('a', t, { decision: { at: t, verdict: 'malicious', remember: false } }), [
        real,
      ]),
    ).toBe('You kept it blocked');
    expect(
      outcome(
        alert('a', t, {
          containment: 'released',
          decision: { at: t, verdict: 'benign', remember: false },
        }),
        [],
      ),
    ).toBe('You allowed it');
    expect(
      outcome(alert('a', t, { decision: { at: t, verdict: 'expected', remember: false } }), []),
    ).toBe('You marked it fine');
    expect(outcome(alert('a', t), [])).toBe('Closed');
  });

  const held = alert('a', 1, { containment: 'active' });
  const kept = alert('a', 1, {
    containment: 'active',
    decision: { at: 1, verdict: 'malicious', remember: false },
  });

  it('never says blocked when it was only simulated', () => {
    expect(outcome(held, [dry])).toBe('Would have been blocked (simulated)');
    // A kill has no undo, and counts the same.
    expect(outcome(held, [kill(true)])).toBe('Would have been blocked (simulated)');
    expect(outcome({ ...kept, containment: 'none' }, [dry])).toBe(
      'You marked it malicious (simulated)',
    );
  });

  it('says when only part of it was real', () => {
    expect(outcome(held, [kill(false), dry])).toBe('Still blocked (partly simulated)');
    expect(outcome({ ...kept, containment: 'none' }, [kill(false), dry])).toBe(
      'You kept it blocked (partly simulated)',
    );
  });

  it('reads rows from older builds as maybe simulated, never as blocked', () => {
    const legacy = ran(undefined);
    expect(outcome(held, [legacy])).toBe('Vigil acted (may have been simulated)');
    expect(outcome({ ...kept, containment: 'none' }, [legacy, real])).toBe(
      'You marked it malicious (may have been simulated)',
    );
    // An older build's dry-run quarantine still says it was simulated.
    const dryQuarantine = ran(undefined, {
      action: { kind: 'file.quarantine', path: '/tmp/x' },
      result: { at: 1, quarantineId: 'dry-1' },
    });
    expect(outcome(held, [dryQuarantine])).toBe('Would have been blocked (simulated)');
  });

  it('is what a search for the row matches', () => {
    const entries = historyEntries(
      [{ ...held, updatedAt: now }],
      [{ ...dry, requestedAt: now }],
      now,
    );
    expect(filterEntries(entries, 'would have', () => '')).toHaveLength(1);
    expect(filterEntries(entries, 'still blocked', () => '')).toHaveLength(0);
  });
});

describe('filterEntries', () => {
  const entries = historyEntries(
    [
      alert('a1', now - 1000, {
        title: 'Unsigned zoom_update connected out',
        subject: { kind: 'process', label: 'Zoom Helper', path: '/Users/me/Downloads/zoom_update' },
      }),
      alert('a2', now - 2000, { title: 'Launch agent pipes curl' }),
    ],
    [action('x1', now - 500)],
    now,
  );
  const describe = (r: ActionRecord) => `Pause process ${r.id}`;
  const ids = (q: string) =>
    filterEntries(entries, q, describe).map((e) => (e.kind === 'alert' ? e.alert.id : e.record.id));

  it('keeps everything for an empty search', () => {
    expect(ids('  ')).toEqual(['x1', 'a1', 'a2']);
  });

  it('matches every word, ignoring case, across title, path and actions', () => {
    expect(ids('ZOOM downloads')).toEqual(['a1']);
    expect(ids('curl')).toEqual(['a2']);
    expect(ids('Zoom Helper')).toEqual(['a1']);
    expect(ids('pause x1')).toEqual(['x1']);
    expect(ids('zoom curl')).toEqual([]);
  });

  it('matches what the row says happened', () => {
    expect(ids('closed')).toEqual(['a1', 'a2']);
  });
});
