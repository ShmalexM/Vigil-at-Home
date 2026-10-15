import { describe, expect, it } from 'vitest';
import { redactCommandLine, redactPath } from '../proposals/telemetry.js';

describe('telemetry redaction', () => {
  it('replaces emails in command lines and paths', () => {
    expect(redactCommandLine('mail -s hi alex.m@example.com')).toBe('mail -s hi <email>');
    expect(redactPath('/Volumes/x/alex.m@example.com/inbox')).toBe('/Volumes/x/<email>/inbox');
  });

  it('still hides an address at the end of a long name run', () => {
    const out = redactCommandLine(
      'open "https%3A%2F%2Fmail.example.com%2Fu%2F0%2Fcompose%3Fto%3Dalex.margaris@example.com"',
    );
    expect(out).not.toContain('margaris@');
    expect(out).toContain('<email>');
  });

  it('hides long and dotted names in paths and command lines', () => {
    const dotted = 'quarterly.customer.export.'.repeat(3) + 'alice@example.com.csv';
    expect(redactCommandLine(`curl --upload-file /tmp/${dotted}`)).toBe(
      'curl --upload-file /tmp/<email>',
    );
    expect(redactPath('/Volumes/x/' + 'a'.repeat(65) + '@example.com')).toBe('/Volumes/x/<email>');
    expect(redactCommandLine('cp ' + 'a'.repeat(65) + '@example.com .')).toBe('cp <email> .');
  });

  it('stays fast on long runs with no address', () => {
    const start = performance.now();
    redactCommandLine('a'.repeat(100_000) + '@' + 'b.'.repeat(50_000));
    expect(performance.now() - start).toBeLessThan(2000);
  });
});
