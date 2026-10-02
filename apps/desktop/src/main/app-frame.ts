import { pathToFileURL } from 'node:url';

/**
 * Whether a frame URL is Vigil's own page. In development that is the dev
 * server's origin; in a build it is exactly the bundled index.html, so no
 * other file:// page (a download, a dropped file) passes. Hash and query are
 * ignored: the route lives in the hash.
 */
export function isAppFrameUrl(url: string, devUrl: string | undefined, indexPath: string): boolean {
  let u: URL;
  try {
    u = new URL(url);
  } catch {
    return false;
  }
  if (devUrl) return u.origin === new URL(devUrl).origin;
  u.hash = '';
  u.search = '';
  return u.protocol === 'file:' && u.href === pathToFileURL(indexPath).href;
}
