import { MAX_REDACT_CHARS, REDACTED, WITHHELD } from '@vigil/ai/redact';
import { describe, expect, it } from 'vitest';
import { redactDataForPack, redactForPack, redactTextForPack } from './redaction.js';

/** Joined at run time so code scanning doesn't take the samples for real keys. */
const KEY = ['sk', 'ant', 'Abc123Def456Ghi789Jkl012Mno'].join('-');
const PASSWORD = ['hunter2', 'Plain', 'Word'].join('');

describe('the pack’s redaction', () => {
  it('redacts data as data, and keeps its shape', () => {
    const out = redactForPack({ q: `find ${KEY}`, n: 3, password: PASSWORD }) as {
      q: string;
      n: number;
      password: string;
    };
    expect(JSON.stringify(out)).not.toContain(KEY);
    expect(out.n).toBe(3);
    expect(out.password).toBe(REDACTED);
    const text = redactDataForPack({ rows: [{ token: PASSWORD }] });
    expect(text).toMatch(/^\{"rows":\[\{"token":/);
    expect(text).not.toContain(PASSWORD);
  });

  it('withholds a field too long to read whole, rather than cutting it', () => {
    const long = `${'word '.repeat(MAX_REDACT_CHARS / 5)}${KEY}`;
    expect(redactTextForPack(long)).toBe(WITHHELD);
  });

  it('withholds what it can’t read rather than passing it on', () => {
    const loop: Record<string, unknown> = { a: 1 };
    loop.self = loop;
    expect(JSON.stringify(redactForPack(loop))).toContain(WITHHELD);
    const throws = {
      get secret(): string {
        throw new Error('no');
      },
    };
    expect(JSON.stringify(redactForPack(throws))).toContain(WITHHELD);
  });
});
