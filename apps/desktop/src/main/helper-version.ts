// Which helper is running next to the one this app ships, and how the last
// try to update it went. After the app is updated the old helper keeps
// running until install.sh runs again, and that can fail without a sound (a
// blocked /bin/sh stops the password dialog), so the Protection card says so.

import { readlinkSync } from 'node:fs';
import { basename, join } from 'node:path';
import { z } from 'zod';
import { helperPayloadDir } from './helper-install.js';

export interface HelperBuild {
  version: string;
  commit: string;
}

/** Shown on the helper's row; see SensorHealth.helperVersion. */
export interface HelperVersionInfo {
  /** The build running, as the helper reports it; null for a helper too old to say. */
  running: string | null;
  /** The build this app ships. */
  bundled: string;
  /** When the running helper was installed, from its versions/<id> folder, or null. */
  installedAt: number | null;
  /** The installed helper isn't the one this app ships. */
  updatePending: boolean;
  /** Why the last install or update didn't go through, in plain words; absent if it did. */
  lastFailure?: { at: number; reason: string };
}

export function buildName(b: HelperBuild | null | undefined): string | null {
  if (!b) return null;
  return b.commit ? `${b.version} (${b.commit})` : b.version;
}

/**
 * When the helper `current` points at was installed. install.sh names each
 * version folder by its UTC install time (YYYYMMDDHHMMSS.<pid>.<random>).
 */
export function installedHelperAt(
  platform: NodeJS.Platform = process.platform,
  root = '',
): number | null {
  let target: string;
  try {
    target = readlinkSync(join(root, helperPayloadDir(platform), 'current'));
  } catch {
    return null;
  }
  const m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})\./.exec(basename(target));
  if (!m) return null;
  const [, y, mo, d, h, mi, s] = m.map(Number) as number[];
  return Date.UTC(y!, mo! - 1, d!, h!, mi!, s!);
}

/** The setting the outcome of the last install or update is kept in. */
export const LAST_HELPER_SCRIPT = 'helper.lastScript';

export const HelperScriptOutcome = z.object({
  kind: z.enum(['install', 'update']),
  at: z.number(),
  ok: z.boolean(),
  error: z.string().optional(),
});
export type HelperScriptOutcome = z.infer<typeof HelperScriptOutcome>;

/** Why an install or update failed, said so the user knows what happened and what to do. */
export function helperFailureWords(error: string | undefined): string {
  const e = (error ?? '').trim();
  if (e === 'cancelled') return 'the password dialog was closed before the update ran';
  if (/\/bin\/sh\b|(^|\s)sh: |operation not permitted/i.test(e)) {
    return 'macOS could not run the shell (/bin/sh) the password dialog needs; something, such as a Santa block, is stopping it';
  }
  if (e.includes('Not running the helper script')) {
    return 'the helper files changed after Vigil checked them, so the update was refused';
  }
  if (!e) return 'the update script failed without saying why';
  const line = e.split('\n')[0]!;
  return line.length > 160 ? `${line.slice(0, 160)}…` : line;
}

export function helperVersionInfo(o: {
  running: HelperBuild | null | undefined;
  bundled: HelperBuild;
  installedAt: number | null;
  updatePending: boolean;
  last: HelperScriptOutcome | null;
}): HelperVersionInfo {
  return {
    running: buildName(o.running),
    bundled: buildName(o.bundled)!,
    installedAt: o.installedAt,
    updatePending: o.updatePending,
    // A failure only matters while the update it was for is still to do.
    ...(o.updatePending && o.last && !o.last.ok
      ? { lastFailure: { at: o.last.at, reason: helperFailureWords(o.last.error) } }
      : {}),
  };
}

/** The helper row's note while it is out of date, or undefined when it isn't. */
export function outdatedNote(v: HelperVersionInfo): string | undefined {
  if (!v.updatePending) return undefined;
  const running = v.running
    ? `running ${v.running}`
    : v.installedAt !== null
      ? `running a build from ${new Date(v.installedAt).toLocaleDateString()}`
      : 'running an older build';
  const failed = v.lastFailure ? `; the last update failed: ${v.lastFailure.reason}` : '';
  return `Out of date: ${running}, this app ships ${v.bundled}${failed}`;
}
