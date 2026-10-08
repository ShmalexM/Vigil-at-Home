import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { SafetyFloor } from '@vigil/detection';
import { describe, expect, it } from 'vitest';
import { hashSelf, selfPaths } from './self-path.js';

const proc = (path: string) => ({ pid: 4242, ppid: 900, name: 'x', path });

const MOUNT = '/tmp/.mount_VigilaB1c2D';
const MOUNTINFO = [
  '22 1 259:2 / / rw,relatime shared:1 - ext4 /dev/nvme0n1p2 rw',
  '40 22 0:35 / /tmp rw,nosuid,nodev shared:20 - tmpfs tmpfs rw',
  `612 40 0:71 / ${MOUNT} ro,nosuid,nodev,relatime shared:350 - fuse.Vigil.AppImage Vigil.AppImage ro,user_id=1000,group_id=1000`,
].join('\n');
const deps = (real: (p: string) => string = (p) => p) => ({
  realpath: real,
  mountInfo: () => MOUNTINFO,
  fileId: (p: string) => (p === '/home/alex/Apps/Vigil.AppImage' ? '2049:5501' : undefined),
});

describe('selfPaths', () => {
  it('is the .app bundle on macOS', () => {
    const p = selfPaths(
      '/Applications/Vigil at Home.app/Contents/MacOS/Vigil at Home',
      'darwin',
      true,
    );
    expect(p.app).toEqual(['/Applications/Vigil at Home.app']);
    expect(p.helper).toEqual({ paths: p.app, images: [], hashes: [] });
  });

  it('is the install folder for the Linux package, not /', () => {
    const p = selfPaths('/opt/Vigil at Home/vigil-at-home', 'linux', true, {}, deps());
    expect(p.app).toEqual(['/opt/Vigil at Home']);
    expect(p.helper.paths).toEqual(['/opt/Vigil at Home']);
    expect(p.mount).toBeUndefined();
  });

  it('covers the AppImage mount in the app and names the image to the helper by identity', () => {
    const env = { APPIMAGE: '/home/alex/Apps/Vigil.AppImage' };
    const p = selfPaths(`${MOUNT}/vigil-at-home`, 'linux', true, env, deps());
    expect(p.app).toEqual([MOUNT, '/home/alex/Apps/Vigil.AppImage']);
    expect(p.mount).toBe(MOUNT);
    // Never by its path: a file put there after a move would be trusted too.
    expect(p.helper).toEqual({
      paths: [],
      images: [{ path: '/home/alex/Apps/Vigil.AppImage', id: '2049:5501' }],
      hashes: [],
    });
    // A symlinked image is named by its real path, as the kernel names it.
    const linked = selfPaths(
      `${MOUNT}/vigil-at-home`,
      'linux',
      true,
      { APPIMAGE: '/home/alex/Desktop/Vigil' },
      deps(() => '/home/alex/Apps/Vigil.AppImage'),
    );
    expect(linked.helper.images).toEqual(p.helper.images);
  });

  it('finds the mount in the mount table, not by its folder name', () => {
    // Run from a resources folder deep in the mount: still the mount's root.
    const env = { APPIMAGE: '/home/alex/Apps/Vigil.AppImage' };
    const deep = selfPaths(`${MOUNT}/resources/bin/vigil`, 'linux', true, env, deps());
    expect(deep.mount).toBe(MOUNT);
    // A folder that only looks like a mount is not one.
    const fake = selfPaths('/home/alex/.mount_Vigil/vigil-at-home', 'linux', true, env, deps());
    expect(fake.mount).toBeUndefined();
  });

  it('leaves other programs actionable on Linux', () => {
    const floor = new SafetyFloor({
      selfPaths: selfPaths('/opt/Vigil at Home/vigil-at-home', 'linux', true, {}, deps()).app,
    });
    expect(floor.processProtection(proc('/tmp/payload'))).toBeUndefined();
    expect(floor.processProtection(proc('/opt/Vigil at Home/vigil-at-home'))).toBe(
      'it is Vigil itself',
    );
  });
});

describe('hashSelf', () => {
  it('hashes only the programs inside the mount', async () => {
    const root = mkdtempSync(join(tmpdir(), 'vigil-self-'));
    try {
      mkdirSync(join(root, 'resources'));
      writeFileSync(join(root, 'vigil-at-home'), 'main', { mode: 0o755 });
      writeFileSync(join(root, 'resources', 'node'), 'node', { mode: 0o755 });
      writeFileSync(join(root, 'resources', 'app.asar'), 'data', { mode: 0o644 });
      symlinkSync('/usr/bin/env', join(root, 'env'));
      const sha = (s: string) => createHash('sha256').update(s).digest('hex');
      expect(await hashSelf(root)).toEqual([sha('main'), sha('node')].sort());
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});
