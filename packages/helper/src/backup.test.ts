import { mkdtempSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type * as Fs from 'node:fs';

// Lets a test act between the copy and the link, as another install would.
const hook = vi.hoisted(() => ({ beforeLink: undefined as (() => void) | undefined }));
vi.mock('node:fs', async (importOriginal) => {
  const fs = await importOriginal<typeof Fs>();
  return {
    ...fs,
    linkSync: (from: string, to: string) => {
      hook.beforeLink?.();
      fs.linkSync(from, to);
    },
  };
});

const { backUpOnce } = await import('./backup.js');

afterEach(() => (hook.beforeLink = undefined));

describe('backUpOnce', () => {
  it('copies the file once, and never replaces a backup that is there', () => {
    const dir = mkdtempSync(join(tmpdir(), 'vigil-backup-'));
    const conf = join(dir, 'osquery.conf');
    writeFileSync(conf, 'mine');
    expect(backUpOnce(conf, `${conf}.before-vigil`)).toBe(true);
    writeFileSync(conf, 'vigil');
    expect(backUpOnce(conf, `${conf}.before-vigil`)).toBe(false);
    expect(readFileSync(`${conf}.before-vigil`, 'utf8')).toBe('mine');
    expect(readdirSync(dir).sort()).toEqual(['osquery.conf', 'osquery.conf.before-vigil']);
    // Nothing to back up.
    expect(backUpOnce(join(dir, 'missing'), join(dir, 'missing.bak'))).toBe(false);
  });

  it('keeps the first copy to land when another install backs up at the same time', () => {
    const dir = mkdtempSync(join(tmpdir(), 'vigil-backup-'));
    const conf = join(dir, 'osquery.conf');
    const backup = `${conf}.before-vigil`;
    writeFileSync(conf, 'mine');
    // This run has copied "mine" but not linked it yet when another run
    // lands its own backup and writes Vigil's config.
    hook.beforeLink = () => {
      hook.beforeLink = undefined;
      writeFileSync(conf, 'vigil');
      writeFileSync(backup, 'first');
    };
    expect(backUpOnce(conf, backup)).toBe(false);
    expect(readFileSync(backup, 'utf8')).toBe('first');
    // A run whose copy was taken after Vigil's config went in loses too.
    expect(backUpOnce(conf, backup)).toBe(false);
    expect(readFileSync(backup, 'utf8')).toBe('first');
    expect(readdirSync(dir).sort()).toEqual(['osquery.conf', 'osquery.conf.before-vigil']);
  });
});
