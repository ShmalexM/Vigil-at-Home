import { describe, expect, it } from 'vitest';
import { shownAlert, tabFor } from './alerts-selection';

const a = (id: string) => ({ id });

describe('tabFor', () => {
  it('finds the list an alert is in, once both are loaded', () => {
    expect(tabFor('x', [a('x')], [])).toBe('open');
    expect(tabFor('y', [a('x')], [a('y')])).toBe('resolved');
    expect(tabFor('z', [a('x')], [a('y')])).toBeUndefined();
    expect(tabFor('y', undefined, [a('y')])).toBeUndefined();
    expect(tabFor(undefined, [], [])).toBeUndefined();
  });
});

describe('shownAlert', () => {
  it('shows the selected alert only while it is in the list on screen', () => {
    expect(shownAlert('b', [a('a'), a('b')])).toBe('b');
    expect(shownAlert('gone', [a('a'), a('b')])).toBe('a');
    expect(shownAlert(undefined, [a('a')])).toBe('a');
    expect(shownAlert('b', [])).toBeUndefined();
  });
});
