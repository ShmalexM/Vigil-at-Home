import { afterEach, describe, expect, it } from 'vitest';
import { mkdirSync, mkdtempSync, rmSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { helperPayloadDir } from './helper-install.js';
import {
  buildName,
  helperFailureWords,
  helperVersionInfo,
  installedHelperAt,
  outdatedNote,
} from './helper-version.js';

describe('helper version', () => {
  let root: string | undefined;
  afterEach(() => root && rmSync(root, { recursive: true, force: true }));

  it('reads when the running helper was installed from its version folder', () => {
    root = mkdtempSync(join(tmpdir(), 'vigil-hv-'));
    const dest = join(root, helperPayloadDir('darwin'));
    mkdirSync(join(dest, 'versions', '20261006153012.4242.AbC123'), { recursive: true });
    expect(installedHelperAt('darwin', root)).toBeNull();
    symlinkSync('versions/20261006153012.4242.AbC123', join(dest, 'current'));
    expect(installedHelperAt('darwin', root)).toBe(Date.UTC(2026, 9, 6, 15, 30, 12));
  });

  it('says why an update failed in plain words', () => {
    expect(helperFailureWords('cancelled')).toBe(
      'the password dialog was closed before the update ran',
    );
    expect(helperFailureWords('sh: /bin/sh: Operation not permitted')).toMatch(
      /could not run the shell \(\/bin\/sh\)/,
    );
    expect(helperFailureWords('Not running the helper script: lib.sh changed')).toMatch(
      /changed after Vigil checked them/,
    );
    expect(helperFailureWords('')).toBe('the update script failed without saying why');
    expect(helperFailureWords('install.sh: no space left\nmore')).toBe('install.sh: no space left');
  });

  it('keeps a failure only while the update is still to do', () => {
    const base = {
      running: { version: '0.1.0-alpha.5', commit: '' },
      bundled: { version: '0.1.0-alpha.6', commit: 'abc1234' },
      installedAt: null,
      last: { kind: 'update' as const, at: 7, ok: false, error: 'cancelled' },
    };
    const pending = helperVersionInfo({ ...base, updatePending: true });
    expect(pending).toEqual({
      running: '0.1.0-alpha.5',
      bundled: '0.1.0-alpha.6 (abc1234)',
      installedAt: null,
      updatePending: true,
      lastFailure: { at: 7, reason: 'the password dialog was closed before the update ran' },
    });
    expect(outdatedNote(pending)).toBe(
      'Out of date: running 0.1.0-alpha.5, this app ships 0.1.0-alpha.6 (abc1234); the last update failed: the password dialog was closed before the update ran',
    );
    const done = helperVersionInfo({ ...base, updatePending: false });
    expect(done.lastFailure).toBeUndefined();
    expect(outdatedNote(done)).toBeUndefined();
    // A helper too old to report its build.
    expect(
      outdatedNote(helperVersionInfo({ ...base, running: null, last: null, updatePending: true })),
    ).toBe('Out of date: running an older build, this app ships 0.1.0-alpha.6 (abc1234)');
    expect(buildName(null)).toBeNull();
  });
});
