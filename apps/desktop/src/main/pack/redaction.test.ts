import { describe, expect, it } from 'vitest';
import { cutBefore, redactDataForPack, redactForPack, redactTextForPack } from './redaction.js';

/** Joined at run time so code scanning doesn't take the sample for a real key. */
const KEY = ['sk', 'ant', 'Abc123Def456Ghi789Jkl012Mno'].join('-');

describe('the pack’s redaction', () => {
  it('redacts data as data, and keeps its shape', () => {
    const out = redactForPack({ q: `find ${KEY}`, n: 3, list: [`a ${KEY}`] }) as {
      q: string;
      n: number;
      list: string[];
    };
    expect(JSON.stringify(out)).not.toContain(KEY);
    expect(out.n).toBe(3);
    expect(redactDataForPack({ rows: [{ key: KEY }] })).toMatch(/^\{"rows":\[\{"key":/);
    expect(redactDataForPack({ rows: [{ key: KEY }] })).not.toContain(KEY);
  });

  it('cuts an over-long field back to a word break before redacting, so no half key is left', () => {
    // The limit falls inside the key: cut there, "sk-ant-Abc123" would be left, too short to spot.
    const text = `${'word '.repeat(20)}${KEY} tail`;
    const limit = text.indexOf(KEY) + 13;
    const out = redactTextForPack(text, limit);
    expect(out).not.toContain('sk-ant');
    expect(out.endsWith('word…')).toBe(true);
    // Nested strings are kept within the limit too.
    expect(JSON.stringify(redactForPack({ a: [text] }, limit))).not.toContain('sk-ant');
  });

  it('drops a private key block the cut leaves open', () => {
    const text = `before\n-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\nmore`;
    expect(cutBefore(text, text.length - 3)).toBe('before\n…');
    expect(cutBefore('oneverylongword', 5)).toBe('…');
  });

  it('withholds what it can’t read rather than passing it on', () => {
    const loop: Record<string, unknown> = { a: 1 };
    loop.self = loop;
    expect(JSON.stringify(redactForPack(loop))).toContain('withheld');
  });
});
