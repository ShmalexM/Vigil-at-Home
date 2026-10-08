import { describe, expect, it } from 'vitest';
import {
  installedRoots,
  insideInstalledRoot,
  mountContaining,
  parseMountInfo,
  runsFromMount,
  selfMount,
} from './self.js';

describe('the installer’s own folder', () => {
  it('is compared without case on macOS', () => {
    for (const path of [
      '/Applications/Vigil at Home.app',
      '/Applications/Vigil at Home.app/Contents/MacOS/Vigil at Home',
      '/applications/vigil at home.app/Contents/MacOS/Vigil at Home',
      '/APPLICATIONS/VIGIL AT HOME.APP/Contents/Frameworks/x',
    ])
      expect(insideInstalledRoot(path, 'darwin'), path).toBe(true);
    for (const path of [
      '/Applications/Vigil at Home Evil.app/Contents/MacOS/x',
      '/Applications/Vigil at Home.apps/x',
      '/Users/a/Downloads/Vigil at Home.app/Contents/MacOS/Vigil at Home',
      '/opt/Vigil at Home/vigil-at-home',
    ])
      expect(insideInstalledRoot(path, 'darwin'), path).toBe(false);
  });

  it('is compared with case on Linux', () => {
    expect(insideInstalledRoot('/opt/Vigil at Home', 'linux')).toBe(true);
    expect(insideInstalledRoot('/opt/Vigil at Home/vigil-at-home', 'linux')).toBe(true);
    for (const path of [
      '/opt/vigil at home/vigil-at-home',
      '/opt/VIGIL AT HOME/vigil-at-home',
      '/opt/Vigil at Home2/vigil-at-home',
      '/Applications/Vigil at Home.app/Contents/MacOS/Vigil at Home',
    ])
      expect(insideInstalledRoot(path, 'linux'), path).toBe(false);
  });

  it('takes other roots, and never one that would cover everything', () => {
    expect(insideInstalledRoot('/srv/app/x', 'linux', ['/srv/app'])).toBe(true);
    expect(insideInstalledRoot('/usr/bin/x', 'linux', ['/'])).toBe(false);
    expect(installedRoots('linux')).toEqual(['/opt/Vigil at Home']);
    expect(installedRoots('darwin')).toEqual(['/Applications/Vigil at Home.app']);
  });
});

const MOUNTINFO = [
  '22 1 259:2 / / rw,relatime shared:1 - ext4 /dev/nvme0n1p2 rw',
  '40 22 0:35 / /tmp rw,nosuid,nodev shared:20 - tmpfs tmpfs rw',
  '612 40 0:71 / /tmp/.mount_VigilaB1c2D ro,nosuid,nodev,relatime shared:350 - fuse.Vigil.AppImage Vigil.AppImage ro,user_id=1000,group_id=1000',
  '613 22 0:72 / /home/alex/My\\040Files rw,nosuid,nodev - fuse.sshfs alex@nas:/ rw,user_id=1000',
].join('\n');

describe('mount table', () => {
  it('parses mountinfo, including escaped spaces', () => {
    const m = parseMountInfo(MOUNTINFO);
    expect(m.map((e) => e.mountPoint)).toEqual([
      '/',
      '/tmp',
      '/tmp/.mount_VigilaB1c2D',
      '/home/alex/My Files',
    ]);
    expect(m[2]).toMatchObject({
      id: 612,
      dev: '0:71',
      fsType: 'fuse.Vigil.AppImage',
      readOnly: true,
    });
  });

  it('finds the mount a path lives on by whole path parts', () => {
    const m = parseMountInfo(MOUNTINFO);
    expect(mountContaining(m, '/tmp/.mount_VigilaB1c2D/vigil-at-home')?.id).toBe(612);
    expect(mountContaining(m, '/tmp/.mount_VigilaB1c2Dx/vigil-at-home')?.id).toBe(40);
    expect(mountContaining(m, '/usr/bin/node')?.id).toBe(22);
    expect(runsFromMount(m, '/tmp/.mount_VigilaB1c2D/resources/x', m[2]!)).toBe(true);
  });

  it('knows Vigil’s own mount only when it is a read-only FUSE mount', () => {
    expect(selfMount(MOUNTINFO, '/tmp/.mount_VigilaB1c2D/vigil-at-home')?.id).toBe(612);
    // A folder named like a mount is not one.
    expect(selfMount(MOUNTINFO, '/home/alex/.mount_Vigil/vigil-at-home')).toBeUndefined();
    // Writable FUSE (sshfs) is not an image.
    expect(selfMount(MOUNTINFO, '/home/alex/My Files/vigil-at-home')).toBeUndefined();
    expect(selfMount(MOUNTINFO, '/opt/Vigil at Home/vigil-at-home')).toBeUndefined();
  });
});
