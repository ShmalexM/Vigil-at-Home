import { dirname, join } from 'node:path';

/** Where Vigil's own programs live, for the safety floor. */
export interface SelfPaths {
  /** What the app's own engine never pauses, kills or quarantines. */
  app: string[];
  /** What the helper is told. Kept stable across launches, since a new path asks for the password. */
  helper: string[];
}

/**
 * The installed app's own folder. On macOS the binary is
 * `X.app/Contents/MacOS/X`, so the bundle is three levels up; on Linux the
 * binary sits directly in its folder (`/opt/Vigil at Home/vigil-at-home`), and
 * an AppImage runs from a fresh mount under /tmp on every launch.
 */
export function selfPaths(
  execPath: string,
  platform: NodeJS.Platform,
  packaged: boolean,
  env: NodeJS.ProcessEnv = {},
): SelfPaths {
  if (!packaged) return { app: [execPath], helper: [execPath] };
  if (platform === 'darwin') {
    const bundle = join(execPath, '../../..');
    return { app: [bundle], helper: [bundle] };
  }
  const dir = dirname(execPath);
  const image = env['APPIMAGE'];
  if (image) return { app: [dir, image], helper: [image] };
  return { app: [dir], helper: [dir] };
}
