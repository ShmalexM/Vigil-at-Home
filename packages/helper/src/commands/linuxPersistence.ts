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
import { PROTECTED_UNITS, protectionFor } from '../config.js';
import { ActionError } from './errors.js';
import { runsProtectedProgram } from './protectedSet.js';
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

/** Units of Vigil itself and of the tools it relies on, never stopped or moved. */
export { PROTECTED_UNITS };

/** /etc is protected from quarantine in general; its startup folders are the exception. */
function startupQuarantine(opts: QuarantineOptions): QuarantineOptions {
  const base = opts.protectedPrefixes ?? protectionFor('linux').prefixes;
  return {
    ...opts,
    platform: 'linux',
    protectedPrefixes: base.filter((p) => p !== '/etc/'),
  };
}

/** The programs a unit's ExecStart= lines or a desktop entry's Exec= line start. */
export function startCommands(text: string, isDesktop: boolean): string[] {
  const key = isDesktop ? /^Exec=(.*)$/ : /^ExecStart(?:Pre|Post)?=(.*)$/;
  const out: string[] = [];
  for (const line of text.split('\n')) {
    const m = key.exec(line.trim());
    if (!m) continue;
    // systemd prefixes like "-" (ignore failure) or "@" (argv0) come before the path.
    const cmd = m[1]!.trim().replace(/^[-@:+!|]+/, '');
    const first = cmd.startsWith('"') ? cmd.slice(1).split('"')[0] : cmd.split(/\s+/)[0];
    if (first) out.push(first);
  }
  return out;
}

/** Names and program paths from `systemctl show -p Id,Names,ExecStart`. */
export function parseShow(out: string): { names: string[]; programs: string[] } {
  const names: string[] = [];
  const programs: string[] = [];
  for (const line of out.split('\n')) {
    if (line.startsWith('Id=')) names.push(line.slice(3).trim());
    else if (line.startsWith('Names=')) names.push(...line.slice(6).trim().split(/\s+/));
    else if (line.startsWith('ExecStart=')) {
      for (const m of line.matchAll(/(?:^|[{;]\s*)(?:path|argv\[\])=(\S+)/g)) programs.push(m[1]!);
    }
  }
  return { names: names.filter(Boolean), programs };
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
  if (PROTECTED_UNITS.has(name))
    throw new ActionError('refused', `${name} belongs to Vigil or its sensors`);
  // Vet the file the way the quarantine will before stopping anything.
  resolveTarget(path, startupQuarantine(opts));
  let st;
  try {
    st = lstatSync(path);
  } catch {
    throw new ActionError('not_found', `${path} does not exist`);
  }
  if (!st.isFile()) throw new ActionError('refused', `${path} is not a regular file`);
  const text = readFileSync(path, 'utf8');

  const scope = unitScope(path, st.uid, passwd);
  // Whatever it is called, an item that is or runs Vigil or a sensor is theirs:
  // check the names systemd knows the unit by (aliases too) and what it runs.
  const names = new Set<string>();
  const programs = startCommands(text, isDesktop);
  if (scope.kind !== 'autostart') {
    const show = await sys.run('systemctl', [
      ...scopeArgs(scope),
      'show',
      '-p',
      'Id,Names,ExecStart',
      name,
    ]);
    if (show.code === 0) {
      const parsed = parseShow(show.stdout);
      parsed.names.forEach((n) => names.add(n));
      programs.push(...parsed.programs);
    }
  }
  for (const n of names) {
    if (PROTECTED_UNITS.has(n))
      throw new ActionError('refused', `${name} is ${n}, part of Vigil or its sensors`);
  }
  const linux = { ...opts, platform: 'linux' as const };
  for (const program of programs) {
    if (runsProtectedProgram(program, linux))
      throw new ActionError('refused', `${name} runs ${program}, part of Vigil or its sensors`);
  }
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
  const q = quarantine(path, actionId, startupQuarantine(opts));
  if (scope.kind !== 'autostart')
    await sys.run('systemctl', [...scopeArgs(scope), 'daemon-reload']);
  return { quarantine: q, label: name, domain: domainOf(scope), wasLoaded };
}

export async function restoreLinuxPersistence(
  sys: System,
  rec: PersistenceRecord,
  opts: QuarantineOptions,
): Promise<void> {
  restore(rec.quarantine, startupQuarantine(opts));
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
