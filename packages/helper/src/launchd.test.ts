import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

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
