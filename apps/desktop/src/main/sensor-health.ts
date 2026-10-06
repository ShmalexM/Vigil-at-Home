import { execFile } from 'node:child_process';
import { existsSync } from 'node:fs';
import type { EventSource } from '@vigil/core';
import type { HelperState } from './helper.js';
import type { SensorRegistry } from './sensors.js';
import type { SensorHealth } from './status.js';

/** How often the Protection card is re-checked. */
export const HEALTH_CHECK_MS = 60_000;
/**
 * A sensor that has sent nothing for this long needs a look. Santa logs every
 * program launch; osquery only logs changes.
 */
export const QUIET_AFTER_MS = { santa: 5 * 60_000, osquery: 30 * 60_000 } as const;

export const SANTA_PATHS = ['/Applications/Santa.app', '/usr/local/bin/santactl'];
/** Santa's system extension daemon, by the names current and older releases use. */
export const SANTA_PROCESSES = [
  'com.northpolesec.santa.daemon',
  'com.google.santa.daemon',
  'santad',
];
export const OSQUERY_PATHS = [
  '/opt/osquery/lib/osquery.app',
  '/usr/local/bin/osqueryd',
  '/opt/homebrew/bin/osqueryd',
];
/** Where osquery's Linux packages put osqueryd. */
export const LINUX_OSQUERY_PATHS = ['/opt/osquery/bin/osqueryd', '/usr/bin/osqueryd'];
/** fapolicyd, which blocks programs by hash on Linux, as Fedora and Debian install it. */
export const FAPOLICYD_PATHS = ['/usr/sbin/fapolicyd', '/usr/bin/fapolicyd'];

/** What helper.status reports about the sensors, when the helper has that (PR #14). */
export interface HelperSensors {
  santa?: { installed: boolean; lastEventAt: number | null };
  osquery?: { installed: boolean; lastEventAt: number | null };
}

export interface HealthProbe {
  exists(path: string): boolean;
  /** Is a process with this exact name running? */
  running(name: string): Promise<boolean>;
  lastEventAt(source: EventSource): number | null;
  helper(): HelperState;
  /** The helper's own view; it can see files and logs the app can't. */
  helperSensors?(): Promise<HelperSensors | null>;
  now(): number;
  /** Which OS's layers to check; defaults to macOS. */
  platform?: NodeJS.Platform;
}

export function macProbe(
  lastEventAt: HealthProbe['lastEventAt'],
  helper: HealthProbe['helper'],
  helperSensors?: HealthProbe['helperSensors'],
  platform: NodeJS.Platform = process.platform,
): HealthProbe {
  return {
    platform,
    ...(helperSensors ? { helperSensors } : {}),
    exists: existsSync,
    running: (name) =>
      new Promise((resolve) => execFile('/usr/bin/pgrep', ['-x', name], (err) => resolve(!err))),
    lastEventAt,
    helper,
    now: Date.now,
  };
}

const minutes = (ms: number) => Math.max(1, Math.round(ms / 60_000));

/**
 * What the Protection card shows for each layer, from what is installed,
 * what is running and whether its events are actually arriving. Nothing
 * here needs root.
 */
export async function checkHealth(p: HealthProbe): Promise<SensorHealth[]> {
  const helperState = p.helper();
  const fromHelper =
    helperState === 'connected' ? await p.helperSensors?.().catch(() => null) : null;
  const helper: SensorHealth = {
    id: 'helper',
    name: 'Vigil helper',
    detail: 'Suspends, firewalls and quarantines',
    ...(helperState === 'connected'
      ? { state: 'ok' }
      : helperState === 'not_running'
        ? { state: 'down', note: 'Installed but not answering' }
        : { state: 'not_installed', note: 'Blocks are simulated until it is installed' }),
  };

  const sensor = async (
    id: 'santa' | 'osquery',
    name: string,
    detail: string,
    paths: string[],
    processes: string[],
  ): Promise<SensorHealth> => {
    const base = { id, name, detail };
    const reported = fromHelper?.[id];
    const installed = reported?.installed || paths.some((path) => p.exists(path));
    if (!installed) return { ...base, state: 'not_installed' };
    const running = await Promise.all(processes.map((name) => p.running(name)));
    if (!running.some(Boolean)) {
      // The helper writes osquery's settings and starts osqueryd, so before the
      // helper is installed, osquery not running is expected, not a failure.
      if (id === 'osquery' && helperState !== 'connected') {
        return { ...base, state: 'degraded', note: 'Starts once the Vigil helper is installed' };
      }
      return { ...base, state: 'down', note: 'Installed, not running' };
    }
    // Its events reach Vigil through the helper, which reads the logs as root.
    if (helperState !== 'connected') {
      return { ...base, state: 'degraded', note: 'Running; Vigil needs its helper to read it' };
    }
    const times = [p.lastEventAt(id), reported?.lastEventAt ?? null].filter(
      (t): t is number => t !== null,
    );
    const last = times.length ? Math.max(...times) : null;
    if (last === null) return { ...base, state: 'ok', note: 'Starting; no events yet' };
    const quiet = p.now() - last;
    if (quiet > QUIET_AFTER_MS[id]) {
      return { ...base, state: 'degraded', note: `No events for ${minutes(quiet)} minutes` };
    }
    return { ...base, state: 'ok' };
  };

  if (p.platform === 'linux') {
    return [await fapolicyd(p, helperState), await linuxOsquery(), helper];
  }
  return [
    await sensor('santa', 'Santa', 'Blocks programs before they run', SANTA_PATHS, SANTA_PROCESSES),
    await sensor('osquery', 'osquery', 'Watches processes, files and network', OSQUERY_PATHS, [
      'osqueryd',
    ]),
    helper,
  ];

  async function linuxOsquery(): Promise<SensorHealth> {
    return sensor(
      'osquery',
      'osquery',
      'Watches processes, files and network',
      LINUX_OSQUERY_PATHS,
      ['osqueryd'],
    );
  }
}

/**
 * Linux: fapolicyd blocks a program by hash before it runs, from the deny
 * rules the helper writes. It sends Vigil no events, so being installed and
 * running is all there is to check.
 */
async function fapolicyd(p: HealthProbe, helperState: HelperState): Promise<SensorHealth> {
  const base = { id: 'fapolicyd', name: 'fapolicyd', detail: 'Blocks programs before they run' };
  if (!FAPOLICYD_PATHS.some((path) => p.exists(path))) return { ...base, state: 'not_installed' };
  if (!(await p.running('fapolicyd')))
    return { ...base, state: 'down', note: 'Installed, not running' };
  if (helperState !== 'connected') {
    return { ...base, state: 'degraded', note: 'Running; Vigil needs its helper to add blocks' };
  }
  return { ...base, state: 'ok' };
}

/** Re-check and report every layer. */
export async function reportHealth(registry: SensorRegistry, probe: HealthProbe): Promise<void> {
  for (const h of await checkHealth(probe)) {
    const prev = registry.get(h.id);
    if (prev?.state !== h.state || prev?.note !== h.note) registry.report(h);
  }
}
