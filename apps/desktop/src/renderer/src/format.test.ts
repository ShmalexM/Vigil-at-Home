import type { Alert } from '@vigil/core';
import { describe, expect, it } from 'vitest';
import { headline } from './format';

const alert = (containment: Alert['containment']) => ({ containment }) as Alert;

describe('headline', () => {
  it('never says blocked while blocks are only simulated', () => {
    expect(headline(alert('active'), 'real')).toBe('Vigil blocked something');
    expect(headline(alert('active'), 'simulated')).toBe('Vigil would have blocked this');
    expect(headline(alert('none'), 'simulated')).toBe('Vigil needs you');
  });

  it('says what really happened when only part was simulated', () => {
    expect(headline(alert('active'), 'mixed')).toBe(
      'Vigil blocked part of this; the rest was only simulated',
    );
  });

  it("doesn't claim a block it can't vouch for", () => {
    expect(headline(alert('active'), 'unknown')).toBe('Vigil acted on this');
    expect(headline(alert('active'), undefined)).toBe('Vigil acted on this');
  });
});
