// Disables a Linux startup item: a systemd unit someone added, or an XDG
// autostart entry. A unit is stopped first, then its file goes into
// quarantine and systemd reloads, so it neither runs now nor comes back at
// the next boot or login. The "enabled" links in *.wants/ are left alone:
// with the file gone they point at nothing, and restoring the file brings
// the unit back exactly as it was. Undo moves the file back, reloads, and
// starts the unit again if it was running.
//
// Only the folders where users and admins add their own items are accepted.
// Units the package manager installed (/usr/lib/systemd, /lib/systemd) are
// part of the system and never touched.

import { basename, dirname } from 'node:path';
import { lstatSync, readFileSync } from 'node:fs';
import type { System } from '../system.js';
import { protectionFor } from '../config.js';
import { ActionError } from './errors.js';
import { quarantine, resolveTarget, restore, type QuarantineOptions } from './quarantine.js';
import type { PersistenceRecord } from './persistence.js';

/** Folders whose items persistence.disable accepts on Linux. */
export const LINUX_STARTUP_DIR_RE =
  /^(\/etc\/systemd\/system|\/etc\/systemd\/user|\/etc\/xdg\/autostart|\/root\/\.config\/(systemd\/user|autostart)|\/home\/[^/]+\/\.config\/(systemd\/user|autostart))$/;

const UNIT_RE = /^[A-Za-z0-9@._:\\-]{1,250}\.(service|timer|socket|path)$/;
const DESKTOP_RE = /^[A-Za-z0-9@._-]{1,250}\.desktop$/;

/** How systemctl reaches the manager that owns a unit file. */
export type UnitScope = { kind: 'system' } | { kind: 'user'; user: string } | { kind: 'autostart' };

/** The user name for a uid, from /etc/passwd. */
export function userName(
  uid: number,
  passwd: () => string = () => readFileSync('/etc/passwd', 'utf8'),
): string | undefined {
  for (const line of passwd().split('\n')) {
    const [name, , id] = line.split(':');
    if (name && Number(id) === uid && /^[a-z_][a-z0-9_.-]{0,31}\$?$/i.test(name)) return name;
  }
  return undefined;
}

export function unitScope(path: string, ownerUid: number, passwd?: () => string): UnitScope {
  const dir = dirname(path);
  if (dir.endsWith('/autostart')) return { kind: 'autostart' };
  if (dir === '/etc/systemd/system') return { kind: 'system' };
  if (dir === '/etc/systemd/user') {
    // A unit for every user's manager; stopping it in each session is
    // beyond a single action, so only the file is moved.
    return { kind: 'autostart' };
  }
  const user = userName(ownerUid, passwd);
  if (!user) throw new ActionError('failed', `no user owns ${path}`);
  return { kind: 'user', user };
}

function scopeArgs(scope: UnitScope): string[] {
  // As root, `--user -M name@` reaches that user's own systemd manager.
  return scope.kind === 'user' ? ['--user', '-M', `${scope.user}@`] : [];
}

function domainOf(scope: UnitScope): string {
  return scope.kind === 'user' ? `user:${scope.user}` : scope.kind;
}

function scopeOf(domain: string): UnitScope {
  if (domain.startsWith('user:')) return { kind: 'user', user: domain.slice(5) };
  return domain === 'system' ? { kind: 'system' } : { kind: 'autostart' };
}

/** /etc is protected from quarantine in general; its startup folders are the exception. */
function startupQuarantine(opts: QuarantineOptions): QuarantineOptions {
  const base = opts.protectedPrefixes ?? protectionFor('linux').prefixes;
  return {
    ...opts,
    platform: 'linux',
    protectedPrefixes: base.filter((p) => p !== '/etc/'),
  };
}

export async function disableLinuxPersistence(
  sys: System,
  path: string,
  actionId: string,
  opts: QuarantineOptions,
  startupDirs: RegExp = LINUX_STARTUP_DIR_RE,
  passwd?: () => string,
): Promise<PersistenceRecord> {
  const name = basename(path);
  const isDesktop = DESKTOP_RE.test(name);
  if (!startupDirs.test(dirname(path)) || !(isDesktop || UNIT_RE.test(name))) {
    throw new ActionError(
      'invalid',
      'only systemd units or autostart entries directly inside a startup folder can be disabled',
    );
  }
  if (dirname(path).endsWith('/autostart') !== isDesktop) {
    throw new ActionError('invalid', `${name} does not belong in ${dirname(path)}`);
  }
  // Vetted before systemd is touched, so a protected file is never even stopped.
  resolveTarget(path, startupQuarantine(opts));
  let st;
  try {
    st = lstatSync(path);
  } catch {
    throw new ActionError('not_found', `${path} does not exist`);
  }
  if (!st.isFile()) throw new ActionError('refused', `${path} is not a regular file`);
  readFileSync(path); // readable

  const scope = unitScope(path, st.uid, passwd);
  let wasLoaded = false;
  if (scope.kind !== 'autostart') {
    const args = scopeArgs(scope);
    wasLoaded = (await sys.run('systemctl', [...args, 'is-active', '--quiet', name])).code === 0;
    if (wasLoaded) {
      const stop = await sys.run('systemctl', [...args, 'stop', name], { timeoutMs: 60_000 });
      if (stop.code !== 0)
        throw new ActionError('failed', `could not stop ${name}: ${stop.stderr.trim()}`);
    }
  }
  const q = await quarantine(sys, path, actionId, startupQuarantine(opts));
  if (scope.kind !== 'autostart')
    await sys.run('systemctl', [...scopeArgs(scope), 'daemon-reload']);
  return { quarantine: q, label: name, domain: domainOf(scope), wasLoaded };
}

export async function restoreLinuxPersistence(
  sys: System,
  rec: PersistenceRecord,
  opts: QuarantineOptions,
): Promise<void> {
  await restore(sys, rec.quarantine, startupQuarantine(opts));
  const scope = scopeOf(rec.domain);
  if (scope.kind === 'autostart') return;
  const args = scopeArgs(scope);
  await sys.run('systemctl', [...args, 'daemon-reload']);
  if (rec.wasLoaded && rec.label) {
    const r = await sys.run('systemctl', [...args, 'start', rec.label], { timeoutMs: 60_000 });
    if (r.code !== 0) {
      throw new ActionError(
        'failed',
        `restored the file but systemd would not start it: ${r.stderr.trim()}`,
      );
    }
  }
}
