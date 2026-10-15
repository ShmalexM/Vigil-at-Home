// Keeps osquery running with Vigil's queries on Linux. osquery's .deb and
// .rpm install osqueryd as the systemd service "osqueryd", which reads
// /etc/osquery/osquery.flags and /etc/osquery/osquery.conf, but leave it
// stopped. The helper writes both files, enables the service and restarts
// it when they change. Whatever osquery had before is kept next to the
// original as *.before-vigil and put back by removeLinuxOsquery.

import {
  chmodSync,
  existsSync,
  mkdirSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { dirname } from 'node:path';
import {
  LINUX_OSQUERY_CONFIG_PATH,
  LINUX_OSQUERY_FLAGS_PATH,
  LINUX_OSQUERY_SERVICE,
  LINUX_OSQUERYD_PATH,
  LINUX_QUERY_NAMES,
  OSQUERY_RESULTS_LOG,
  osqueryLinuxConfig,
  osqueryLinuxFlags,
} from '@vigil/sensors';
import { backUpOnce } from './backup.js';
import type { OsqueryState } from './osquery.js';
import type { System } from './system.js';

const BACKUP = '.before-vigil';

export interface LinuxOsqueryPaths {
  osqueryd: string;
  config: string;
  flags: string;
  logDir: string;
}

export function defaultLinuxOsqueryPaths(): LinuxOsqueryPaths {
  return {
    osqueryd: LINUX_OSQUERYD_PATH,
    config: LINUX_OSQUERY_CONFIG_PATH,
    flags: LINUX_OSQUERY_FLAGS_PATH,
    logDir: dirname(OSQUERY_RESULTS_LOG),
  };
}

function read(path: string): string | undefined {
  try {
    return readFileSync(path, 'utf8');
  } catch {
    return undefined;
  }
}

function put(path: string, content: string): boolean {
  if (read(path) === content) return false;
  writeFileSync(path, content, { mode: 0o644 });
  chmodSync(path, 0o644);
  return true;
}

function isVigils(config: string | undefined): boolean {
  return !!config?.includes(LINUX_QUERY_NAMES.processEvents);
}

export async function ensureLinuxOsquery(
  sys: System,
  p: LinuxOsqueryPaths = defaultLinuxOsqueryPaths(),
): Promise<OsqueryState> {
  if (!existsSync(p.osqueryd)) return 'not-installed';
  mkdirSync(dirname(p.config), { recursive: true, mode: 0o755 });
  mkdirSync(p.logDir, { recursive: true, mode: 0o755 });
  if (!isVigils(read(p.config))) {
    // First writer wins, so an install running at the same time can't
    // replace the original with Vigil's config (see backUpOnce).
    for (const f of [p.config, p.flags]) backUpOnce(f, f + BACKUP);
  }
  let changed = put(p.config, osqueryLinuxConfig());
  changed = put(p.flags, osqueryLinuxFlags()) || changed;

  const active =
    (await sys.run('systemctl', ['is-active', '--quiet', LINUX_OSQUERY_SERVICE])).code === 0;
  if (!active) {
    const r = await sys.run('systemctl', ['enable', '--now', LINUX_OSQUERY_SERVICE], {
      timeoutMs: 60_000,
    });
    if (r.code !== 0) throw new Error(`could not start osqueryd: ${r.stderr.trim()}`);
    return 'started';
  }
  if (changed) {
    await sys.run('systemctl', ['restart', LINUX_OSQUERY_SERVICE], { timeoutMs: 60_000 });
    return 'restarted';
  }
  return 'unchanged';
}

/**
 * Stop osquery if Vigil set it up, and put back what it had before. Keeps the logs.
 *
 * Known limit: a removal overlapping an install can lose the original config
 * (the removal renames the backup back while the install writes Vigil's file
 * over it). Not guarded against, since it takes two password-approved
 * operations running at once.
 */
export async function removeLinuxOsquery(
  sys: System,
  p: LinuxOsqueryPaths = defaultLinuxOsqueryPaths(),
): Promise<void> {
  if (!isVigils(read(p.config))) return;
  const hadOwn = existsSync(p.config + BACKUP);
  for (const f of [p.config, p.flags]) {
    if (existsSync(f + BACKUP)) renameSync(f + BACKUP, f);
    else rmSync(f, { force: true });
  }
  if (hadOwn) await sys.run('systemctl', ['restart', LINUX_OSQUERY_SERVICE], { timeoutMs: 60_000 });
  else
    await sys.run('systemctl', ['disable', '--now', LINUX_OSQUERY_SERVICE], { timeoutMs: 60_000 });
}
