// Disables a launch agent or daemon: unloads it from launchd, then moves its
// plist into quarantine so it does not come back at the next login or boot.
// Undo moves the plist back and loads it again.

import { lstatSync, realpathSync } from 'node:fs';
import { basename, dirname, join } from 'node:path';
import { actorFor, readAs, rootOnly } from './transfer.js';
import type { System } from '../system.js';
import { PROTECTED_LABEL_PREFIXES } from '../config.js';
import { ActionError } from './errors.js';
import { runsProtectedProgram } from './protectedSet.js';
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
 * Launch items of Vigil itself and of the tools it relies on. They are never
 * unloaded, whatever folder they sit in or whatever they are named on disk.
 */
export { PROTECTED_LABEL_PREFIXES };

function isProtectedLabel(name: string): boolean {
  const lower = name.toLowerCase();
  return PROTECTED_LABEL_PREFIXES.some((p) => lower.startsWith(p));
}

const isTheirs = (what: string) =>
  new ActionError('refused', `${what} belongs to Vigil or its sensors`);

/** The user's home folder `dir` is in, as written (…/home/<name>, …/Users/<name>, /root). */
export function homeOf(dir: string): string | undefined {
  if (dir === '/root' || dir.startsWith('/root/')) return '/root';
  return /^(.*?\/(?:home|Users)\/[^/]+)(?=\/|$)/.exec(dir)?.[1];
}

const linked = (dir: string) =>
  new ActionError(
    'startup-folder-linked',
    `${dir} is a link to somewhere else; Vigil only turns off items in the startup folder itself`,
  );

/**
 * The real location of a startup item at `path`. The folder is taken as
 * written, with one exception: a link only root could have made, above the
 * user's home (or anywhere, in a path with no home in it), like
 * /home -> var/home on ostree systems or /var -> private/var on macOS.
 * Such a link must be root's, in a folder that is root's alone, and lead to
 * a folder that is root's alone too (rootOnly). Every other link on the way
 * (one a user made or could replace, or one at or under the home, like a
 * startup folder a dotfile manager links in) is refused, so the folder
 * checked is the one acted on. Vetted like any quarantine.
 */
export async function startupTarget(
  sys: System,
  path: string,
  opts: QuarantineOptions,
): Promise<string> {
  const real = resolveTarget(path, opts);
  const dir = dirname(path);
  if (dirname(real) === dir) return real;
  const home = homeOf(dir);
  let written = '/';
  let resolved = '/';
  for (const name of dir.split('/').filter(Boolean)) {
    written = join(written, name);
    let st;
    try {
      st = lstatSync(written);
    } catch {
      throw linked(dir);
    }
    if (!st.isSymbolicLink()) {
      resolved = join(resolved, name);
      continue;
    }
    const aboveHome = home === undefined || home.startsWith(written + '/');
    let target: string;
    try {
      target = realpathSync(written);
    } catch {
      throw linked(dir);
    }
    if (
      !aboveHome ||
      st.uid !== 0 ||
      !(await rootOnly(sys, resolved)) ||
      !(await rootOnly(sys, target))
    )
      throw linked(dir);
    resolved = target;
  }
  // The rest of the path, after the trusted links, is exactly as written.
  if (dirname(real) !== resolved) throw linked(dir);
  return real;
}

/**
 * A user's own startup item (one in a home folder) is turned off only for
 * that user: it must be theirs, and they must be the one asking (the
 * helper's socket belongs to the console user). Vigil is a single-user
 * personal tool, so this also stops its own rules from acting on another
 * local user's startup items.
 */
export function checkOwnItem(path: string, ownerUid: number, consoleUid: number | undefined): void {
  if (consoleUid === undefined || ownerUid !== consoleUid)
    throw new ActionError('not-your-item', `${path} belongs to another user`);
}

/** One key of a plist, read from its bytes on stdin: plutil never opens a path here. */
async function plistValue(sys: System, plist: Buffer, key: string): Promise<string | undefined> {
  const r = await sys.run('plutil', ['-extract', key, 'raw', '-o', '-', '-'], { input: plist });
  const value = r.stdout.trim();
  return r.code === 0 && value ? value : undefined;
}

async function readLabel(sys: System, plist: Buffer): Promise<string | undefined> {
  const label = await plistValue(sys, plist, 'Label');
  // Labels are reverse-DNS style; refuse anything that could confuse launchctl.
  return label && /^[A-Za-z0-9._-]{1,255}$/.test(label) ? label : undefined;
}

/** The program a launch item runs: Program, else the first of ProgramArguments. */
async function readPrograms(sys: System, plist: Buffer): Promise<string[]> {
  const out: string[] = [];
  for (const key of ['Program', 'ProgramArguments.0']) {
    const value = await plistValue(sys, plist, key);
    if (value) out.push(value);
  }
  return out;
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
  if (isProtectedLabel(basename(path))) throw isTheirs(basename(path));
  // Vetted before launchd is touched, so a protected file is never even unloaded.
  const real = await startupTarget(sys, path, opts);
  if (isProtectedLabel(basename(real))) throw isTheirs(basename(real));
  // Read as whoever controls the path (commands/transfer.ts), never by root through it.
  const file = await readAs(await (opts.actorFor ?? actorFor)(sys, real), real);
  // Anywhere but the two system folders, an agent is a user's own.
  if (!['/Library/LaunchDaemons', '/Library/LaunchAgents'].includes(dirname(real)))
    checkOwnItem(real, file.uid, sys.consoleUid());

  const label = await readLabel(sys, file.data);
  if (label && isProtectedLabel(label)) throw isTheirs(label);
  // Whatever it is called, an item that runs Vigil or a sensor is theirs.
  for (const program of await readPrograms(sys, file.data)) {
    if (runsProtectedProgram(program, opts))
      throw new ActionError(
        'refused',
        `${basename(path)} runs ${program}, part of Vigil or its sensors`,
      );
  }
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
