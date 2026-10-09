// Disables a launch agent or daemon: unloads it from launchd, then moves its
// plist into quarantine so it does not come back at the next login or boot.
// Undo moves the plist back and loads it again.

import { basename, dirname } from 'node:path';
import { actorFor, readAs } from './transfer.js';
import type { System } from '../system.js';
import { ActionError } from './errors.js';
import {
  quarantine,
  resolveTarget,
  restore,
  type QuarantineOptions,
  type QuarantineRecord,
} from './quarantine.js';

export interface PersistenceRecord {
  quarantine: QuarantineRecord;
  label?: string | undefined;
  domain: string;
  wasLoaded: boolean;
}

export const LAUNCH_DIR_RE =
  /^(\/Library\/LaunchDaemons|\/Library\/LaunchAgents|\/Users\/[^/]+\/Library\/LaunchAgents)$/;

/** launchd domain for a plist location: system for daemons, the user's GUI session for agents. */
export function launchdDomain(
  plistPath: string,
  ownerUid: number,
  consoleUid: number | undefined,
): string {
  const dir = dirname(plistPath);
  if (dir === '/Library/LaunchDaemons') return 'system';
  if (dir === '/Library/LaunchAgents') {
    if (consoleUid === undefined)
      throw new ActionError('failed', 'nobody is logged in to unload an agent for');
    return `gui/${consoleUid}`;
  }
  return `gui/${ownerUid}`;
}

/**
 * The real location of a startup item at `path`, which must be the folder
 * as written: a startup folder that is a link elsewhere is refused, so the
 * folder checked is the one acted on. Vetted like any quarantine.
 */
export function startupTarget(path: string, opts: QuarantineOptions): string {
  const real = resolveTarget(path, opts);
  if (dirname(real) !== dirname(path))
    throw new ActionError(
      'refused',
      `${dirname(path)} leads to another folder; Vigil only turns off items in the startup folder itself`,
    );
  return real;
}

/**
 * A user's own startup item (one in a home folder) is turned off only for
 * that user: it must be theirs, and they must be the one asking (the
 * helper's socket belongs to the console user).
 */
export function checkOwnItem(path: string, ownerUid: number, consoleUid: number | undefined): void {
  if (consoleUid === undefined || ownerUid !== consoleUid)
    throw new ActionError('refused', `${path} belongs to another user`);
}

async function readLabel(sys: System, plist: Buffer): Promise<string | undefined> {
  // From stdin: plutil never opens a path here.
  const r = await sys.run('plutil', ['-extract', 'Label', 'raw', '-o', '-', '-'], {
    input: plist,
  });
  const label = r.stdout.trim();
  // Labels are reverse-DNS style; refuse anything that could confuse launchctl.
  return r.code === 0 && /^[A-Za-z0-9._-]{1,255}$/.test(label) ? label : undefined;
}

export async function disablePersistence(
  sys: System,
  path: string,
  actionId: string,
  opts: QuarantineOptions,
  launchDirs: RegExp = LAUNCH_DIR_RE,
): Promise<PersistenceRecord> {
  if (!launchDirs.test(dirname(path)) || !basename(path).endsWith('.plist')) {
    throw new ActionError(
      'invalid',
      'only plists directly inside a LaunchAgents or LaunchDaemons folder can be disabled',
    );
  }
  // Vetted before launchd is touched, so a protected file is never even unloaded.
  const real = startupTarget(path, opts);
  // Read as whoever controls the path (commands/transfer.ts), never by root through it.
  const file = await readAs(await (opts.actorFor ?? actorFor)(sys, real), real);
  // Anywhere but the two system folders, an agent is a user's own.
  if (!['/Library/LaunchDaemons', '/Library/LaunchAgents'].includes(dirname(real)))
    checkOwnItem(real, file.uid, sys.consoleUid());

  const label = await readLabel(sys, file.data);
  const domain = launchdDomain(real, file.uid, sys.consoleUid());
  let wasLoaded = false;
  if (label) {
    const print = await sys.run('launchctl', ['print', `${domain}/${label}`]);
    wasLoaded = print.code === 0;
    if (wasLoaded) {
      const out = await sys.run('launchctl', ['bootout', `${domain}/${label}`]);
      if (out.code !== 0)
        throw new ActionError('failed', `could not unload ${label}: ${out.stderr.trim()}`);
    }
  }
  const q = await quarantine(sys, path, actionId, opts);
  return { quarantine: q, label, domain, wasLoaded };
}

export async function restorePersistence(
  sys: System,
  rec: PersistenceRecord,
  opts: QuarantineOptions,
): Promise<void> {
  await restore(sys, rec.quarantine, opts);
  if (rec.wasLoaded) {
    const r = await sys.run('launchctl', ['bootstrap', rec.domain, rec.quarantine.originalPath]);
    if (r.code !== 0) {
      throw new ActionError(
        'failed',
        `restored the file but launchd would not load it: ${r.stderr.trim()}`,
      );
    }
  }
}
