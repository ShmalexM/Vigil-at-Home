import { describe, expect, it } from 'vitest';
import { emailSpans, replaceEmails } from './email.js';

describe('replaceEmails', () => {
  it('replaces plain addresses and leaves other text alone', () => {
    expect(replaceEmails('mail alice@example.com now')).toBe('mail <email> now');
    expect(replaceEmails('a@b c@d.e x@y.12 @example.com')).toBe('a@b c@d.e x@y.12 @example.com');
    expect(replaceEmails('to alice@example.com.')).toBe('to <email>.');
  });

  it('hides long or dotted names whole', () => {
    const cases = [
      '/tmp/' + 'quarterly.customer.export.'.repeat(3) + 'alice@example.com.csv',
      'alice.'.repeat(10) + 'smith@example.com',
      'a'.repeat(65) + '@example.com',
      'x@' + 'a'.repeat(256) + '.com',
      'x@example.' + 'a'.repeat(64),
      'open "https%3A%2F%2Fmail.example.com%2Fcompose%3Fto%3Dalex.margaris@example.com"',
    ];
    for (const text of cases) {
      const out = replaceEmails(text);
      expect(out, text).toContain('<email>');
      expect(out, text).not.toMatch(/@|alice|margaris/);
      expect(out, text).not.toMatch(/a{2,}$/);
    }
  });

  it('hides addresses glued together, stacked @ signs, %40 and non-ASCII names', () => {
    expect(replaceEmails('cp alice@example.com-bob@example.org.csv x')).toBe('cp <email> x');
    expect(replaceEmails('alice@example.com.bob@example.org')).toBe('<email>');
    expect(replaceEmails('a@b.cd@ef.gh')).toBe('<email>');
    expect(replaceEmails('a@b@example.com')).toBe('<email>');
    expect(replaceEmails('to=alice%40example.com&x=1')).toBe('to=<email>&x=1');
    expect(replaceEmails('jürgen@münchen.de')).toBe('<email>');
    expect(replaceEmails('alice@example.com2')).toBe('<email>');
  });

  it('keeps separate addresses separate', () => {
    expect(emailSpans('a@x.com,b@y.org')).toEqual([
      [0, 7],
      [8, 15],
    ]);
  });

  it('runs in linear time', () => {
    for (const text of [
      'a'.repeat(200_000) + '@',
      '@'.repeat(200_000),
      'a@'.repeat(100_000),
      'a.'.repeat(100_000) + '@' + 'b.'.repeat(100_000),
      '%40'.repeat(100_000),
      'a@b.co'.repeat(50_000),
      'a.@'.repeat(100_000),
    ]) {
      const start = performance.now();
      replaceEmails(text);
      expect(performance.now() - start, text.slice(0, 8)).toBeLessThan(500);
    }
  });
});
