import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { versionMismatch } from './config.js';

const plist = readFileSync(
  fileURLToPath(new URL('../launchd/com.vigilathome.helper.plist', import.meta.url)),
  'utf8',
);

/** The <string>s of one <array> key in the plist. */
function strings(key: string): string[] {
  const body = new RegExp(`<key>${key}</key>\\s*<array>([\\s\\S]*?)</array>`).exec(plist)?.[1];
  return [...(body ?? '').matchAll(/<string>([^<]*)<\/string>/g)].map((m) => m[1]!);
}

describe('the launchd job', () => {
  it('starts Node on helper.mjs itself, with no shell in between', () => {
    // On 2026-10-10 Santa blocked /bin/sh by hash; the launcher is a /bin/sh script.
    const D = '/Library/PrivilegedHelperTools/vigil-helper.d/current';
    expect(strings('ProgramArguments')).toEqual([`${D}/node`, `${D}/helper.mjs`, 'daemon']);
  });

  it('gives the helper the launcher’s PATH', () => {
    expect(plist).toMatch(
      /<key>PATH<\/key>\s*<string>\/usr\/bin:\/bin:\/usr\/sbin:\/sbin<\/string>/,
    );
  });
});

describe('a helper started from two versions', () => {
  const D = '/Library/PrivilegedHelperTools/vigil-helper.d';
  const node = `${D}/versions/20261017.1.abc/node`;
  const links = (to: string) => (p: string) => (p === `${D}/current/helper.mjs` ? to : p);

  it('runs when helper.mjs is the one beside its Node', () => {
    expect(
      versionMismatch(
        node,
        `${D}/current/helper.mjs`,
        links(`${D}/versions/20261017.1.abc/helper.mjs`),
      ),
    ).toBeUndefined();
  });

  it('stops when an install switched current between launchd’s two reads of it', () => {
    expect(
      versionMismatch(
        node,
        `${D}/current/helper.mjs`,
        links(`${D}/versions/20261018.2.def/helper.mjs`),
      ),
    ).toContain('is not the helper beside');
  });

  it('leaves a Node that is not an installed version alone (development, tests)', () => {
    expect(
      versionMismatch('/opt/homebrew/bin/node', '/repo/helper.mjs', () => '/x'),
    ).toBeUndefined();
  });
});
