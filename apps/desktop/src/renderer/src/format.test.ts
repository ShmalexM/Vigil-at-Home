import type { Alert } from '@vigil/core';
import { describe, expect, it } from 'vitest';
import { headline } from './format';

const alert = (containment: Alert['containment']) => ({ containment }) as Alert;

describe('headline', () => {
  it('never says blocked while blocks are only simulated', () => {
    expect(headline(alert('active'))).toBe('Vigil blocked something');
    expect(headline(alert('active'), true)).toBe('Vigil would have blocked this');
    expect(headline(alert('none'), true)).toBe('Vigil needs you');
  });
});
