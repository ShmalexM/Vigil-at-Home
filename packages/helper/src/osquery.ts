// Keeps osquery running with Vigil's queries. Installing osquery (the pkg or
// `brew install --cask osquery`) puts osqueryd on disk but starts nothing, so
// the helper writes Vigil's config and flags, installs osquery's launchd job
// and loads it. It checks again every few minutes, which covers osquery being
// installed after the helper. Anything osquery had before is kept next to the
// original as *.before-vigil and put back by removeOsquery (the uninstaller).

import {
  chmodSync,
  copyFileSync,
  existsSync,
  mkdirSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { dirname } from 'node:path';
import {
  OSQUERY_CONFIG_PATH,
  OSQUERY_FLAGS_PATH,
  OSQUERY_RESULTS_LOG,
  OSQUERYD_PATH,
  QUERY_NAMES,
  osqueryConfig,
  osqueryFlags,
} from '@vigil/sensors';
import type { System } from './system.js';

export const OSQUERY_LABEL = 'io.osquery.agent';
const MARKER = 'Written by Vigil at Home';
const BACKUP = '.before-vigil';

export interface OsqueryPaths {
  osqueryd: string;
  config: string;
  flags: string;
  logDir: string;
  plist: string;
}

export function defaultOsqueryPaths(): OsqueryPaths {
  return {
    osqueryd: OSQUERYD_PATH,
    config: OSQUERY_CONFIG_PATH,
    flags: OSQUERY_FLAGS_PATH,
    logDir: dirname(OSQUERY_RESULTS_LOG),
    plist: `/Library/LaunchDaemons/${OSQUERY_LABEL}.plist`,
  };
}

/** osquery's launchd job: started at boot, restarted if it exits, kept in the background. */
export function osqueryLaunchDaemon(p: OsqueryPaths): string {
  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<!-- ${MARKER}. Removed when Vigil's helper is uninstalled. -->
<plist version="1.0">
<dict>
  <key>Label</key><string>${OSQUERY_LABEL}</string>
  <key>ProgramArguments</key>
  <array>
    <string>${p.osqueryd}</string>
    <string>--flagfile=${p.flags}</string>
    <string>--config_path=${p.config}</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ThrottleInterval</key><integer>60</integer>
  <key>ProcessType</key><string>Background</string>
  <key>LowPriorityIO</key><true/>
  <key>Nice</key><integer>10</integer>
  <key>StandardErrorPath</key><string>${p.logDir}/osqueryd.stderr</string>
</dict>
</plist>
`;
}

function read(path: string): string | undefined {
  try {
    return readFileSync(path, 'utf8');
  } catch {
    return undefined;
  }
}

/** Write a root-owned, world-readable file if its content differs. Returns true if it changed. */
function put(path: string, content: string): boolean {
  if (read(path) === content) return false;
  writeFileSync(path, content, { mode: 0o644 });
  // The daemon runs with umask 077; launchd and osquery want these readable.
  chmodSync(path, 0o644);
  return true;
}

function backUpOnce(path: string): void {
  if (existsSync(path) && !existsSync(path + BACKUP)) copyFileSync(path, path + BACKUP);
}

export type OsqueryState = 'not-installed' | 'unchanged' | 'started' | 'restarted';

export async function ensureOsquery(
  sys: System,
  p: OsqueryPaths = defaultOsqueryPaths(),
): Promise<OsqueryState> {
  if (!existsSync(p.osqueryd)) return 'not-installed';
  mkdirSync(dirname(p.config), { recursive: true, mode: 0o755 });
  mkdirSync(p.logDir, { recursive: true, mode: 0o755 });

  // Keep a config and flags Vigil didn't write, once, before replacing them.
  if (!read(p.config)?.includes(QUERY_NAMES.networkConnections)) {
    backUpOnce(p.config);
    backUpOnce(p.flags);
  }
  const plist = osqueryLaunchDaemon(p);
  const current = read(p.plist);
  if (current !== undefined && !current.includes(MARKER)) backUpOnce(p.plist);

  let changed = put(p.config, osqueryConfig());
  changed = put(p.flags, osqueryFlags()) || changed;
  const plistChanged = put(p.plist, plist);

  const target = `system/${OSQUERY_LABEL}`;
  let loaded = (await sys.run('launchctl', ['print', target])).code === 0;
  if (loaded && plistChanged) {
    await sys.run('launchctl', ['bootout', target]);
    loaded = false;
  }
  if (!loaded) {
    const r = await sys.run('launchctl', ['bootstrap', 'system', p.plist]);
    if (r.code !== 0) throw new Error(`launchctl bootstrap osquery failed: ${r.stderr.trim()}`);
    return 'started';
  }
  if (changed) {
    await sys.run('launchctl', ['kickstart', '-k', target]);
    return 'restarted';
  }
  return 'unchanged';
}

/** Stop Vigil's osquery job and put back whatever osquery had before. Keeps osquery's logs. */
export async function removeOsquery(
  sys: System,
  p: OsqueryPaths = defaultOsqueryPaths(),
): Promise<void> {
  const target = `system/${OSQUERY_LABEL}`;
  if (read(p.plist)?.includes(MARKER)) {
    await sys.run('launchctl', ['bootout', target]);
    rmSync(p.plist, { force: true });
    if (existsSync(p.plist + BACKUP)) {
      renameSync(p.plist + BACKUP, p.plist);
      await sys.run('launchctl', ['bootstrap', 'system', p.plist]);
    }
  }
  for (const path of [p.config, p.flags]) {
    if (existsSync(path + BACKUP)) renameSync(path + BACKUP, path);
    else if (
      path === p.config
        ? read(path)?.includes(QUERY_NAMES.networkConnections)
        : read(path) === osqueryFlags()
    )
      rmSync(path, { force: true });
  }
}
