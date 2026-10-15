import { createHash } from 'node:crypto';
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  renameSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
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
  const respond = (body: string | Buffer, url: string) => {
    const r = new Response(body, { status: 200 });
    Object.defineProperty(r, 'url', { value: url });
    return r;
  };

  function setup(
    o: {
      zip?: Buffer;
      listed?: string;
      id?: string;
      version?: string;
      lands?: string;
      rename?: (from: string, to: string) => void;
      copy?: (from: string, to: string) => void;
    } = {},
  ) {
    const root = mkdtempSync(join(tmpdir(), 'vigil-self-update-'));
    const apps = join(root, 'Applications');
    const bundle = join(apps, 'Vigil at Home.app');
    mkdirSync(join(bundle, 'Contents'), { recursive: true });
    writeFileSync(join(bundle, 'Contents', 'which'), 'old');
    const zip = o.zip ?? Buffer.from('zip bytes');
    const sum = o.listed ?? createHash('sha256').update(zip).digest('hex');
    const fetched: string[] = [];
    const ran: string[] = [];
    const dittoArgs: string[] = [];
    const u = new SelfUpdater({
      bundle,
      bundleId: 'app.vigilathome.desktop',
      downloads: join(root, 'data', 'updates'),
      fetch: (async (url: string) => {
        fetched.push(url);
        if (url.endsWith('SHA256SUMS.txt')) return respond(`${sum}  ${ZIP}\n`, url);
        return respond(
          zip,
          o.lands ??
            'https://release-assets.githubusercontent.com/github-production-release-asset/1389784855/abc?sp=r',
        );
      }) as never,
      ...(o.rename ? { rename: o.rename } : {}),
      ...(o.copy ? { copy: o.copy } : {}),
      run: async (file, args) => {
        ran.push([file.split('/').pop(), ...args.slice(0, 1)].join(' '));
        if (file === '/usr/bin/ditto') {
          dittoArgs.push(...args);
          const app = join(args.at(-1)!, 'Vigil at Home.app', 'Contents');
          mkdirSync(app, { recursive: true });
          writeFileSync(join(app, 'which'), 'new');
          writeFileSync(join(app, 'Info.plist'), '<plist>new</plist>');
          return '';
        }
        if (file === '/usr/bin/plutil')
          return args[1] === 'CFBundleIdentifier'
            ? `${o.id ?? 'app.vigilathome.desktop'}\n`
            : `${o.version ?? '0.1.0-alpha.5'}\n`;
        return '';
      },
    });
    return { u, root, apps, bundle, fetched, ran, dittoArgs };
  }

  it('stages a matching download beside the app, then swaps it in and keeps the old one aside', async () => {
    const { u, bundle, apps, ran, dittoArgs } = setup();
    expect(await u.canInstall()).toBe(true);
    const s = await u.stage(assets);
    // The new app never carries a download flag, so the "Unsigned download
    // opened" rule (which needs one) can't stop Vigil's own update.
    expect(dittoArgs).toContain('--noqtn');
    expect(s.app.startsWith(join(apps, '.vigil-update'))).toBe(true);
    expect(ran).toEqual(['ditto -x', 'plutil -extract', 'plutil -extract', 'codesign --verify']);
    // The zip doesn't linger in the data folder.
    expect(existsSync(join(apps, '..', 'data', 'updates', ZIP))).toBe(false);
    u.swap(s);
    expect(readFileSync(join(bundle, 'Contents', 'which'), 'utf8')).toBe('new');
    expect(
      readFileSync(join(apps, '.vigil-update', 'previous.app', 'Contents', 'which'), 'utf8'),
    ).toBe('old');
    u.cleanup();
    expect(existsSync(join(apps, '.vigil-update'))).toBe(false);
  });

  it('refuses a download a redirect took anywhere but GitHub, and an odd zip name', async () => {
    await expect(setup({ lands: 'https://evil.test/x.zip' }).u.stage(assets)).rejects.toThrow(
      /other than GitHub/,
    );
    await expect(
      setup({ lands: 'http://release-assets.githubusercontent.com/x' }).u.stage(assets),
    ).rejects.toThrow(/other than GitHub/);
    await expect(
      setup().u.stage({ ...assets, zipName: '../../Library/LaunchAgents/x.zip' }),
    ).rejects.toThrow(/unexpected name/);
  });

  it('refuses to swap in a staged app that changed or became a link after it was checked', async () => {
    const changed = setup();
    const s = await changed.u.stage(assets);
    writeFileSync(join(s.app, 'Contents', 'Info.plist'), '<plist>other</plist>');
    expect(() => changed.u.swap(s)).toThrow(/changed after it was checked/);
    expect(readFileSync(join(changed.bundle, 'Contents', 'which'), 'utf8')).toBe('old');

    const linked = setup();
    const t = await linked.u.stage(assets);
    const real = join(linked.root, 'elsewhere.app');
    renameSync(t.app, real);
    symlinkSync(real, t.app);
    expect(() => linked.u.swap(t)).toThrow(/plain folder/);
    expect(readFileSync(join(linked.bundle, 'Contents', 'which'), 'utf8')).toBe('old');
  });

  it('puts the old app back when the new one can’t go in, by rename or else by copy', async () => {
    // The second rename fails; the restoring rename works.
    let n = 0;
    const once = setup({
      rename: (a, b) => {
        if (++n === 2) throw new Error('EIO');
        renameSync(a, b);
      },
    });
    const s1 = await once.u.stage(assets);
    expect(() => once.u.swap(s1)).toThrow(/EIO/);
    expect(readFileSync(join(once.bundle, 'Contents', 'which'), 'utf8')).toBe('old');

    // Only the first rename works: the old app is copied back.
    let m = 0;
    const copy = setup({
      rename: (a, b) => {
        if (++m >= 2) throw new Error('EIO');
        renameSync(a, b);
      },
    });
    const s2 = await copy.u.stage(assets);
    expect(() => copy.u.swap(s2)).toThrow(/EIO/);
    expect(readFileSync(join(copy.bundle, 'Contents', 'which'), 'utf8')).toBe('old');
  });

  it('says where the previous version is when it can’t be put back, and stages nothing after', async () => {
    let k = 0;
    const stuck = setup({
      rename: (a, b) => {
        if (++k >= 2) throw new Error('EIO');
        renameSync(a, b);
      },
      // The copy back fails too.
      copy: () => {
        throw new Error('ENOSPC');
      },
    });
    const s = await stuck.u.stage(assets);
    expect(() => stuck.u.swap(s)).toThrow(/previous version is at .*previous\.app/);
    // Staging would clear the folder holding the only copy, so it refuses.
    await expect(stuck.u.stage(assets)).rejects.toThrow(/moved back/);
    expect(
      readFileSync(join(stuck.apps, '.vigil-update', 'previous.app', 'Contents', 'which'), 'utf8'),
    ).toBe('old');
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
