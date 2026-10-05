// The Linux trust answer the sensor hub puts on every launch: whether dpkg,
// rpm or a system snap installed the program. See @vigil/sensors
// linux/packages.ts for the model.

import { execFileSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { PackageIndex, dpkgSource, rpmSource, type PackageSource } from '@vigil/sensors';
import { LINUX_BINARIES } from './system.js';

/** rpm's whole file list, one "path<TAB>package" per line. Run only when the database changed. */
function rpmList(rpm: string): string | undefined {
  try {
    return execFileSync(rpm, ['-qa', '--qf', '[%{FILENAMES}\\t%{NAME}\\n]'], {
      encoding: 'utf8',
      maxBuffer: 256 * 1024 * 1024,
      timeout: 60_000,
      env: { PATH: '/usr/bin:/bin' },
    });
  } catch {
    return undefined;
  }
}

export function linuxPackageIndex(): PackageIndex {
  const sources: PackageSource[] = [dpkgSource()];
  // Some Debian systems have rpm installed as a tool with an empty database;
  // that source then simply yields nothing.
  if (existsSync(LINUX_BINARIES.rpm)) sources.push(rpmSource(() => rpmList(LINUX_BINARIES.rpm)));
  const index = new PackageIndex({ sources });
  index.refresh();
  return index;
}
