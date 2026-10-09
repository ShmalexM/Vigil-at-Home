import { randomBytes } from 'node:crypto';
import { constants, copyFileSync, existsSync, linkSync, rmSync } from 'node:fs';

/**
 * Keep a copy of `path` at `backup`, unless there is one already. Returns
 * whether this call made it.
 *
 * Two installs can run at once, each copying the original before writing
 * Vigil's own file over it. So the copy goes to a temporary file of its own
 * first and is then hard-linked into place: link() fails when `backup`
 * exists, so the first copy to land is the one kept, and a later copy, which
 * may have been taken after another run had already written Vigil's file,
 * never replaces it.
 */
export function backUpOnce(path: string, backup: string): boolean {
  if (!existsSync(path) || existsSync(backup)) return false;
  const tmp = `${backup}.tmp.${process.pid}.${randomBytes(6).toString('hex')}`;
  try {
    copyFileSync(path, tmp, constants.COPYFILE_EXCL);
    try {
      linkSync(tmp, backup);
      return true;
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code === 'EEXIST') return false;
      throw e;
    }
  } finally {
    rmSync(tmp, { force: true });
  }
}
