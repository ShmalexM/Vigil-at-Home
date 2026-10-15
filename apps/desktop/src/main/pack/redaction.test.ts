import { MAX_REDACT_CHARS, REDACTED, WITHHELD } from '@vigil/ai/redact';
import { describe, expect, it } from 'vitest';
import {
  redactDataForPack,
  redactForPack,
  redactJsonText,
  redactMarkdown,
  redactSerialized,
  redactTextForPack,
} from './redaction.js';

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

describe('the pack’s sinks', () => {
  it('redacts keys too, and JSON text inside a value as data', () => {
    const text = redactSerialized({ [KEY]: 1, result: JSON.stringify({ [KEY]: 'x', n: 2 }) });
    expect(text).not.toContain(KEY);
    expect(JSON.parse(text)).toMatchObject({ result: expect.stringContaining('"n":2') });
  });

  it('leaves clean Markdown alone, and keeps a withheld line’s heading marker', () => {
    const clean = '# Pip’s notebook\n\n**Asked:** what ran?';
    expect(redactMarkdown(clean)).toBe(clean);
    const out = redactMarkdown(`# ${KEY}’s notebook\n\n**Asked:** what ran?`);
    expect(out).not.toContain(KEY);
    expect(out).toMatch(/^# /);
    expect(out).toContain('**Asked:** what ran?');
  });

  it('reads JSON encoded twice, at any depth, as data', () => {
    const secret = ['hunter2', 'xyzQ'].join('');
    const once = JSON.stringify({ api_token: secret });
    for (const text of [JSON.stringify(once), JSON.stringify(JSON.stringify(once))]) {
      expect(redactJsonText(text)).not.toContain(secret);
      expect(redactSerialized({ a: { b: [text] } })).not.toContain(secret);
      expect(redactDataForPack({ arg: text })).not.toContain(secret);
    }
  });

  it('withholds a note section whose secret spans lines, keeping its heading', () => {
    const secret = ['hunter2', 'xyzQ'].join('');
    const md = [
      '# Pip’s notebook',
      '',
      'Exported today.',
      '',
      '## 2026-10-09 12:00 UTC · Chat',
      '',
      '**Asked:** machine db.internal',
      '',
      '**Answered:** login bob',
      '',
      '**Thinking summary (from the provider):**',
      '',
      `password ${secret}`,
      '',
      '## 2026-10-09 11:00 UTC · Chat',
      '',
      '**Asked:** what ran?',
      '',
    ].join('\n');
    const out = redactMarkdown(md);
    expect(out).not.toContain(secret);
    expect(out).toContain('# Pip’s notebook');
    expect(out).toContain('## 2026-10-09 12:00 UTC · Chat');
    expect(out).toContain('**Asked:** what ran?');
    expect(out).not.toContain('login bob');
  });
});
