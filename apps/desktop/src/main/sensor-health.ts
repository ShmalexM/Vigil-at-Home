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

/**
 * How Santa's syncs with the helper are going, from helper.status. Every
 * field is optional: older helpers report fewer of them.
 */
export interface HelperSantaSync {
  /** When Santa last finished a sync (since the helper started). */
  lastSyncAt?: number | null;
  /** Why the sync port isn't listening, or null. */
  syncError?: string | null;
  /** The sync port takes only Santa's client certificate. */
  clientCertRequired?: boolean;
  /** The helper has made Santa a client certificate. */
  clientCertIssued?: boolean;
  /** When Santa last presented that certificate (kept across helper restarts). */
  clientCertSeenAt?: number | null;
  clientCertExpiresAt?: number | null;
  /** The last connection the sync port turned away. */
  lastRefusal?: {
    at: number;
    reason: 'no_certificate' | 'wrong_certificate' | 'handshake_failed';
  } | null;
  syncIntervalSeconds?: number;
}

/** What helper.status reports about the sensors, when the helper has that (PR #14). */
export interface HelperSensors {
  santa?: { installed: boolean; lastEventAt: number | null } & HelperSantaSync;
  osquery?: { installed: boolean; lastEventAt: number | null };
}

/** Santa missing this many syncs in a row means its syncs are failing. */
const MISSED_SYNCS = 3;
/** A client certificate this close to expiry means its renewal is failing. */
const CERT_EXPIRY_WARN_MS = 7 * 86_400_000;

const REFUSAL_WORDS: Record<NonNullable<HelperSantaSync['lastRefusal']>['reason'], string> = {
  no_certificate: 'it came without its certificate',
  wrong_certificate: 'it presented a certificate Vigil didn’t make for it',
  handshake_failed: 'the secure connection failed',
};

/**
 * Why rule updates aren't reaching Santa, or undefined when its syncs are
 * fine. Once Santa's certificate is required, a Santa that can't present it
 * stops getting rules without any other sign, so every failure shows here:
 * the port not listening, a refused connection since the last good sync,
 * no sync for three intervals, or a certificate about to lapse.
 * `since` is when the app could first expect a sync (start, or wake from sleep).
 */
export function santaSyncProblem(
  s: HelperSantaSync | undefined,
  now: number,
  since = 0,
): string | undefined {
  if (!s) return undefined;
  if (s.syncError)
    return `Rule updates can’t reach Santa: Vigil’s sync port isn’t open (${s.syncError})`;
  const times = [s.lastSyncAt, s.clientCertSeenAt].filter(
    (t): t is number => typeof t === 'number',
  );
  const lastGood = times.length ? Math.max(...times) : null;
  const refusal = s.lastRefusal;
  // Before the certificate is required, only Santa presenting a bad one, or
  // a failed handshake, can be refused; a Santa without one is served.
  if (refusal && (lastGood === null || refusal.at > lastGood)) {
    return `Santa’s last sync was refused: ${REFUSAL_WORDS[refusal.reason]}`;
  }
  if (s.clientCertRequired && lastGood !== null) {
    const intervalMs = (s.syncIntervalSeconds ?? 600) * 1000;
    const quiet = now - Math.max(lastGood, since);
    if (quiet > MISSED_SYNCS * intervalMs) {
      return `Santa hasn’t synced with Vigil for ${minutes(now - lastGood)} minutes`;
    }
  }
  if (s.clientCertRequired && s.clientCertExpiresAt != null) {
    const left = s.clientCertExpiresAt - now;
    if (left < CERT_EXPIRY_WARN_MS) {
      return left <= 0
        ? 'Santa’s sync certificate has expired'
        : `Santa’s sync certificate expires in ${Math.max(1, Math.round(left / 86_400_000))} days and hasn’t renewed`;
    }
  }
  return undefined;
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
  /** When the Mac last woke (or the app started): Santa can't have synced while asleep. */
  awakeSince?(): number;
  /** Which OS's layers to check; defaults to macOS. */
  platform?: NodeJS.Platform;
}

export function macProbe(
  lastEventAt: HealthProbe['lastEventAt'],
  helper: HealthProbe['helper'],
  helperSensors?: HealthProbe['helperSensors'],
  platform: NodeJS.Platform = process.platform,
  awakeSince?: HealthProbe['awakeSince'],
): HealthProbe {
  return {
    platform,
    ...(helperSensors ? { helperSensors } : {}),
    ...(awakeSince ? { awakeSince } : {}),
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
    // Rule updates (blocks included) reach Santa only through its syncs.
    const syncProblem =
      id === 'santa' ? santaSyncProblem(fromHelper?.santa, p.now(), p.awakeSince?.()) : undefined;
    if (syncProblem) {
      return { ...base, state: 'degraded', note: syncProblem, repair: 'santa-sync' };
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
