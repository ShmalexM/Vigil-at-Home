import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { bundleOf, SelfUpdater, sumFor } from './self-update.js';

const ZIP = 'Vigil-at-Home-0.1.0-alpha.5-arm64.zip';
const BASE = 'https://github.com/ShmalexM/Vigil-at-Home/releases/download/v0.1.0-alpha.5/';
const assets = {
  version: '0.1.0-alpha.5',
  zipName: ZIP,
  zipUrl: BASE + ZIP,
  sumsUrl: BASE + 'SHA256SUMS.txt',
};

describe('bundleOf', () => {
  it('finds the .app a packaged Mac app runs from, and nothing for a dev build', () => {
    expect(bundleOf('/Applications/Vigil at Home.app/Contents/MacOS/Vigil at Home')).toBe(
      '/Applications/Vigil at Home.app',
    );
    expect(
      bundleOf('/x/node_modules/electron/dist/Electron.app/Contents/MacOS/Electron'),
    ).toBeUndefined();
    expect(bundleOf('/usr/bin/node')).toBeUndefined();
  });
});

describe('sumFor', () => {
  it('reads sha256sum output, text or binary mode', () => {
    const a = 'a'.repeat(64);
    const b = 'b'.repeat(64);
    const sums = `${a}  Vigil-at-Home-1-x64.zip\n${b} *${ZIP}\n`;
    expect(sumFor(sums, ZIP)).toBe(b);
    expect(sumFor(sums, 'Vigil-at-Home-1-x64.zip')).toBe(a);
    expect(sumFor(sums, 'other.zip')).toBeUndefined();
  });
});

describe('SelfUpdater', () => {
  function setup(o: { zip?: Buffer; listed?: string; id?: string; version?: string } = {}) {
    const root = mkdtempSync(join(tmpdir(), 'vigil-self-update-'));
    const apps = join(root, 'Applications');
    const bundle = join(apps, 'Vigil at Home.app');
    mkdirSync(join(bundle, 'Contents'), { recursive: true });
    writeFileSync(join(bundle, 'Contents', 'which'), 'old');
    const zip = o.zip ?? Buffer.from('zip bytes');
    const sum = o.listed ?? createHash('sha256').update(zip).digest('hex');
    const fetched: string[] = [];
    const ran: string[] = [];
    const u = new SelfUpdater({
      bundle,
      bundleId: 'app.vigilathome.desktop',
      downloads: join(root, 'data', 'updates'),
      fetch: (async (url: string) => {
        fetched.push(url);
        if (url.endsWith('SHA256SUMS.txt'))
          return new Response(`${sum}  ${ZIP}\n`, { status: 200 });
        return new Response(zip, { status: 200 });
      }) as never,
      run: async (file, args) => {
        ran.push([file.split('/').pop(), ...args.slice(0, 1)].join(' '));
        if (file === '/usr/bin/ditto') {
          const app = join(args[3]!, 'Vigil at Home.app', 'Contents');
          mkdirSync(app, { recursive: true });
          writeFileSync(join(app, 'which'), 'new');
          return '';
        }
        if (file === '/usr/bin/plutil')
          return args[1] === 'CFBundleIdentifier'
            ? `${o.id ?? 'app.vigilathome.desktop'}\n`
            : `${o.version ?? '0.1.0-alpha.5'}\n`;
        return '';
      },
    });
    return { u, root, apps, bundle, fetched, ran };
  }

  it('stages a matching download beside the app, then swaps it in and keeps the old one aside', async () => {
    const { u, bundle, apps, ran } = setup();
    expect(await u.canInstall()).toBe(true);
    const s = await u.stage(assets);
    expect(s.app.startsWith(join(apps, '.vigil-update'))).toBe(true);
    expect(ran).toEqual(['ditto -x', 'plutil -extract', 'plutil -extract', 'codesign --verify']);
    // The zip doesn't linger in the data folder.
    expect(existsSync(join(apps, '..', 'data', 'updates', ZIP))).toBe(false);
    await u.swap(s);
    expect(readFileSync(join(bundle, 'Contents', 'which'), 'utf8')).toBe('new');
    expect(
      readFileSync(join(apps, '.vigil-update', 'previous.app', 'Contents', 'which'), 'utf8'),
    ).toBe('old');
    await u.cleanup();
    expect(existsSync(join(apps, '.vigil-update'))).toBe(false);
  });

  it('swaps synchronously at quit', async () => {
    const { u, bundle } = setup();
    u.swapSync(await u.stage(assets));
    expect(readFileSync(join(bundle, 'Contents', 'which'), 'utf8')).toBe('new');
  });

  it('refuses a download that doesn’t match the checksum, before unpacking anything', async () => {
    const { u, ran, apps, bundle } = setup({ listed: 'c'.repeat(64) });
    await expect(u.stage(assets)).rejects.toThrow(/checksum/);
    expect(ran).toEqual([]);
    expect(existsSync(join(apps, '.vigil-update'))).toBe(false);
    expect(readFileSync(join(bundle, 'Contents', 'which'), 'utf8')).toBe('old');
  });

  it('refuses another app or another version', async () => {
    await expect(setup({ id: 'com.example.other' }).u.stage(assets)).rejects.toThrow(
      /different app/,
    );
    await expect(setup({ version: '0.1.0-alpha.4' }).u.stage(assets)).rejects.toThrow(
      /says it is 0\.1\.0-alpha\.4/,
    );
  });

  it('can’t install from a disk image or a translocated copy', async () => {
    const dmg = new SelfUpdater({
      bundle: '/Volumes/Vigil at Home/Vigil at Home.app',
      bundleId: 'x',
      downloads: '/tmp',
    });
    expect(await dmg.canInstall()).toBe(false);
    const moved = new SelfUpdater({
      bundle: '/private/var/folders/x/AppTranslocation/y/d/Vigil at Home.app',
      bundleId: 'x',
      downloads: '/tmp',
    });
    expect(await moved.canInstall()).toBe(false);
  });
});
