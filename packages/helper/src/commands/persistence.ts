// Disables a launch agent or daemon: unloads it from launchd, then moves its
// plist into quarantine so it does not come back at the next login or boot.
// Undo moves the plist back and loads it again.

import { basename, dirname } from 'node:path';
import { lstatSync, readFileSync } from 'node:fs';
import type { System } from '../system.js';
import { ActionError } from './errors.js';
import {
  quarantine,
  resolveTarget,
  restore,
  type GuardedFile,
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

async function readLabel(sys: System, path: string): Promise<string | undefined> {
  const r = await sys.run('plutil', ['-extract', 'Label', 'raw', '-o', '-', path]);
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
  resolveTarget(path, opts);
  let st;
  try {
    st = lstatSync(path);
  } catch {
    throw new ActionError('not_found', `${path} does not exist`);
  }
  if (!st.isFile()) throw new ActionError('refused', `${path} is not a regular file`);
  readFileSync(path); // readable

  const label = await readLabel(sys, path);
  const domain = launchdDomain(path, st.uid, sys.consoleUid());
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
  const q = quarantine(path, actionId, opts);
  return { quarantine: q, label, domain, wasLoaded };
}

export async function restorePersistence(
  sys: System,
  rec: PersistenceRecord,
  guards?: readonly GuardedFile[],
): Promise<void> {
  restore(rec.quarantine, guards);
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
