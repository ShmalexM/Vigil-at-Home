import { SafetyFloor } from '@vigil/detection';
import { describe, expect, it } from 'vitest';
import { selfPaths } from './self-path.js';

const proc = (path: string) => ({ pid: 4242, ppid: 900, name: 'x', path });

describe('selfPaths', () => {
  it('is the .app bundle on macOS', () => {
    const p = selfPaths(
      '/Applications/Vigil at Home.app/Contents/MacOS/Vigil at Home',
      'darwin',
      true,
    );
    expect(p.app).toEqual(['/Applications/Vigil at Home.app']);
    expect(p.helper).toEqual(p.app);
  });

  it('is the install folder for the Linux package, not /', () => {
    const p = selfPaths('/opt/Vigil at Home/vigil-at-home', 'linux', true);
    expect(p.app).toEqual(['/opt/Vigil at Home']);
    expect(p.helper).toEqual(['/opt/Vigil at Home']);
  });

  it('covers the AppImage mount in the app but tells the helper only the stable image path', () => {
    const p = selfPaths('/tmp/.mount_VigilAbc/vigil-at-home', 'linux', true, {
      APPIMAGE: '/home/alex/Apps/Vigil.AppImage',
    });
    expect(p.app).toEqual(['/tmp/.mount_VigilAbc', '/home/alex/Apps/Vigil.AppImage']);
    expect(p.helper).toEqual(['/home/alex/Apps/Vigil.AppImage']);
  });

  it('leaves other programs actionable on Linux', () => {
    const floor = new SafetyFloor({
      selfPaths: selfPaths('/opt/Vigil at Home/vigil-at-home', 'linux', true).app,
    });
    expect(floor.processProtection(proc('/tmp/payload'))).toBeUndefined();
    expect(floor.processProtection(proc('/opt/Vigil at Home/vigil-at-home'))).toBe(
      'it is Vigil itself',
    );
  });
});
