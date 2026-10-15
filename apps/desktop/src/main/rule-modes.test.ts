import { describe, expect, it } from 'vitest';
import type { Rule } from '@vigil/core';
import { notifyLevel } from './alerts.js';
import { interruptLevel, quieterMode, visibleRules } from '../renderer/src/rule-modes';

describe('interruptLevel', () => {
  const severities = ['info', 'low', 'medium', 'high', 'critical'] as const;
  const fidelities = ['low', 'medium', 'high'] as const;
  it('matches how the alert service notifies, for alert and block rules', () => {
    for (const mode of ['alert', 'block'] as const)
      for (const severity of severities)
        for (const fidelity of fidelities) {
          const rule = { mode, severity, fidelity } as unknown as Rule;
          expect(interruptLevel({ mode, severity, fidelity })).toBe(notifyLevel(rule));
        }
  });
  it('never interrupts while the baseline is being learned', () => {
    expect(interruptLevel({ mode: 'block', severity: 'critical', fidelity: 'high' }, true)).toBe(
      'none',
    );
  });
  it('never interrupts for shadow or off', () => {
    expect(interruptLevel({ mode: 'shadow', severity: 'critical', fidelity: 'high' })).toBe('none');
    expect(interruptLevel({ mode: 'disabled', severity: 'critical', fidelity: 'high' })).toBe(
      'none',
    );
  });
});

describe('quieterMode', () => {
  const kinds = ['process.exec'];
  it('offers Shadow for an alerting rule only', () => {
    expect(quieterMode({ id: 'r', eventKinds: kinds, mode: 'alert' })).toBe('shadow');
    expect(quieterMode({ id: 'r', eventKinds: kinds, mode: 'block' })).toBeUndefined();
    expect(quieterMode({ id: 'r', eventKinds: kinds, mode: 'shadow' })).toBeUndefined();
  });
  it("offers nothing for Vigil's own checks", () => {
    expect(
      quieterMode({ id: 'preflight-probing', eventKinds: ['agent.tool_request'], mode: 'alert' }),
    ).toBeUndefined();
  });
});

describe('visibleRules', () => {
  const v = (id: string, name: string, matches: number, mode = 'alert' as const) => ({
    rule: { id, name, description: `about ${name}`, mode },
    matches,
  });
  const views = [v('a', 'Alpha', 1), v('b', 'Beta', 9), v('c', 'Gamma', 9), v('d', 'Delta', 0)];
  it('searches name, description and id, case-insensitively', () => {
    expect(visibleRules(views, { text: 'BET', filter: 'all', sort: 'default' })).toHaveLength(1);
    expect(
      visibleRules(views, { text: 'about g', filter: 'all', sort: 'default' })[0]?.rule.id,
    ).toBe('c');
    expect(visibleRules(views, { text: ' d ', filter: 'all', sort: 'default' })).toHaveLength(1);
  });
  it('sorts noisiest first and keeps ties in order', () => {
    expect(
      visibleRules(views, { text: '', filter: 'all', sort: 'matches' }).map((x) => x.rule.id),
    ).toEqual(['b', 'c', 'a', 'd']);
  });
  it('filters to shadow rules', () => {
    const withShadow = [
      ...views,
      { ...v('e', 'Eps', 2), rule: { ...v('e', 'Eps', 2).rule, mode: 'shadow' as const } },
    ];
    expect(
      visibleRules(withShadow, { text: '', filter: 'review', sort: 'default' }).map(
        (x) => x.rule.id,
      ),
    ).toEqual(['e']);
  });
});
