// Parser for Santa's default "file" event log (/var/db/santa/santa.log).
//
// Each line looks like:
//   [2026-09-26T21:00:00.123Z] I santad: action=EXEC|decision=DENY|reason=BINARY|...|machineid=X
//
// Santa escapes "|" inside values as "<pipe>" and control characters as
// backslash sequences (see Santa's SanitizableString), so splitting on "|" is
// safe. The format is defined in Santa's
// Source/santad/Logs/EndpointSecurity/Serializers/BasicString.mm.

import type { EventOfKind, FileOp, SensorEvent } from '@vigil/core';
import { defined, nonEmpty, num, pidOf, type ProcessRef } from '../types.js';
import { santaSigning } from '../signing.js';
import { lineEventId } from '../eventId.js';

const LINE_RE = /^\[([^\]]+)\]\s+\S+\s+santad:\s+(action=.*)$/;

export type SantaLogFields = Record<string, string>;

export function unescapeSantaValue(value: string): string {
  // Most values have nothing escaped; skip the two scans.
  if (!value.includes('<') && !value.includes('\\')) return value;
  return value
    .replaceAll('<pipe>', '|')
    .replace(/\\([nrt\\])/g, (_m, c: string) =>
      c === 'n' ? '\n' : c === 'r' ? '\r' : c === 't' ? '\t' : '\\',
    );
}

/** The timestamp and the `action=...` part of a Santa line, or undefined if it isn't one. */
function splitSantaLine(line: string): { ts: number; body: string } | undefined {
  const trimmed = line.trimEnd();
  const m = LINE_RE.exec(trimmed);
  if (m) return { ts: Date.parse(m[1]!), body: m[2]! };
  // Lines without the timestamp prefix (e.g. forwarded from syslog).
  if (trimmed.startsWith('action=')) return { ts: Number.NaN, body: trimmed };
  return undefined;
}

function parseFields(body: string): SantaLogFields {
  const fields: SantaLogFields = {};
  for (const part of body.split('|')) {
    const eq = part.indexOf('=');
    if (eq <= 0) continue;
    const key = part.slice(0, eq);
    // First occurrence wins: Santa never repeats keys, and a repeated key
    // could only come from a crafted value trying to override a field.
    if (!(key in fields)) fields[key] = unescapeSantaValue(part.slice(eq + 1));
  }
  return fields;
}

/** Split the key=value part of a Santa log line. Returns undefined for lines that are not events. */
export function parseSantaLogLine(
  line: string,
): { ts: number; fields: SantaLogFields } | undefined {
  const split = splitSantaLine(line);
  if (!split) return undefined;
  const fields = parseFields(split.body);
  if (!fields.action) return undefined;
  return { ts: split.ts, fields };
}

/** The actions santaLogLineToEvent maps; every other line is dropped. */
const MAPPED_ACTIONS: ReadonlySet<string> = new Set([
  'EXEC',
  'EXIT',
  'WRITE',
  'DELETE',
  'RENAME',
  'FILE_ACCESS',
  'LAUNCH_ITEM_ADD',
  'LAUNCH_ITEM_REMOVE',
  'XPROTECT_DETECTED',
  'TCC_MODIFICATION',
  'GATEKEEPER_OVERRIDE',
]);

/**
 * The line's action, read without parsing the rest. The body always starts
 * with `action=`, which is its first field, so this is the value the full
 * parse gives `fields.action`.
 */
function actionOf(body: string): string {
  const end = body.indexOf('|');
  return unescapeSantaValue(body.slice('action='.length, end < 0 ? undefined : end));
}

type Mechanism = EventOfKind<'persistence'>['mechanism'];

function mechanismFor(itemType: string | undefined, itemPath: string): Mechanism {
  switch (itemType) {
    case 'AGENT':
      return 'launch_agent';
    case 'DAEMON':
      return 'launch_daemon';
    case 'LOGIN_ITEM':
    case 'USER_ITEM':
      return 'login_item';
    default:
      if (itemPath.includes('/LaunchDaemons/')) return 'launch_daemon';
      if (itemPath.includes('/LaunchAgents/')) return 'launch_agent';
      return 'other';
  }
}

/** The process that did something, from plain or "event_"-prefixed fields. */
function actor(f: SantaLogFields, prefix = ''): ProcessRef | undefined {
  const pid = pidOf(f[`${prefix}pid`]);
  if (pid === undefined) return undefined;
  return defined({
    pid,
    ppid: pidOf(f[`${prefix}ppid`]),
    path: f[`${prefix}processpath`] ?? '',
    uid: num(f[`${prefix}uid`]),
    user: nonEmpty(f[`${prefix}user`]),
  });
}

const UNKNOWN_PROCESS: ProcessRef = { pid: 0, path: '' };

/** Watch items whose name ends in this only report writes (AllowReadAccess is on). */
export const WRITE_WATCH_SUFFIX = 'Writes';

function fileAccessOp(accessType: string | undefined, policy: string | undefined): FileOp {
  switch (accessType) {
    case 'RENAME':
      return 'rename';
    case 'UNLINK':
      return 'delete';
    case 'CREATE':
      return 'create';
    case 'OPEN':
      // Santa logs a write-mode open as OPEN too; on a write-only item that's all it reports.
      return policy?.endsWith(WRITE_WATCH_SUFFIX) ? 'write' : 'open';
    default:
      // TRUNCATE, LINK, CLONE, COPYFILE, EXCHANGEDATA
      return 'write';
  }
}

/**
 * Turn one Santa log line into a SensorEvent. Returns undefined for lines we
 * don't map (FORK, login window events, junk).
 */
export function santaLogLineToEvent(
  line: string,
  now: () => number = Date.now,
): SensorEvent | undefined {
  const split = splitSantaLine(line);
  // Santa logs a FORK for about every EXIT; skip lines we drop anyway before
  // decoding every field and hashing the line.
  if (!split || !MAPPED_ACTIONS.has(actionOf(split.body))) return undefined;
  const f = parseFields(split.body);
  const ts = Number.isFinite(split.ts) ? split.ts : now();
  const base = {
    id: lineEventId('santa-log:', line, Number.isFinite(split.ts) ? ts : undefined),
    ts,
    source: 'santa' as const,
    raw: f,
  };

  switch (f.action) {
    case 'EXEC': {
      const process: ProcessRef = defined({
        pid: pidOf(f.pid) ?? 0,
        ppid: pidOf(f.ppid),
        path: f.path ?? '',
        args: f.args !== undefined ? f.args.split(' ') : undefined,
        sha256: nonEmpty(f.sha256),
        teamId: nonEmpty(f.teamid),
        signingId: nonEmpty(f.signingid),
        signing: santaSigning(f),
        uid: num(f.uid),
        user: nonEmpty(f.user),
        quarantine: nonEmpty(f.quarantine_url) ? { originUrl: f.quarantine_url! } : undefined,
      });
      if (f.decision === 'DENY') {
        return {
          ...base,
          kind: 'santa.decision',
          target: 'execution',
          decision: 'block',
          reason: `BLOCK_${f.reason ?? 'UNKNOWN'}`,
          process,
        };
      }
      return { ...base, kind: 'process.exec', process };
    }
    case 'EXIT':
      return {
        ...base,
        kind: 'process.exit',
        process: defined({
          pid: pidOf(f.pid) ?? 0,
          ppid: pidOf(f.ppid),
          path: '',
          uid: num(f.uid),
        }),
      };
    case 'WRITE':
    case 'DELETE':
    case 'RENAME':
      return {
        ...base,
        kind: 'file',
        ...defined({
          op:
            f.action === 'WRITE'
              ? ('write' as const)
              : f.action === 'DELETE'
                ? ('delete' as const)
                : ('rename' as const),
          path: f.path ?? '',
          newPath: nonEmpty(f.newpath),
          process: actor(f),
        }),
      };
    case 'FILE_ACCESS': {
      const decision = f.decision ?? '';
      const path = f.path ?? '';
      if (decision.startsWith('DENIED')) {
        return {
          ...base,
          kind: 'santa.decision',
          target: 'file_access',
          decision: 'block',
          reason: f.policy_name ? `${decision}:${f.policy_name}` : decision,
          path,
          process: actor(f) ?? UNKNOWN_PROCESS,
        };
      }
      // Audit-only watch items report the access without stopping it, so the
      // rules see it as the file activity it is.
      if (decision !== 'AUDIT_ONLY') return undefined;
      return {
        ...base,
        kind: 'file',
        op: fileAccessOp(f.access_type, f.policy_name),
        path,
        ...defined({ process: actor(f) }),
      };
    }
    case 'LAUNCH_ITEM_ADD':
    case 'LAUNCH_ITEM_REMOVE': {
      const path = nonEmpty(f.item_path) ?? nonEmpty(f.app_path) ?? '';
      return {
        ...base,
        kind: 'persistence',
        ...defined({
          change: f.action === 'LAUNCH_ITEM_ADD' ? ('added' as const) : ('removed' as const),
          mechanism: mechanismFor(f.item_type, path),
          path,
          program: nonEmpty(f.exec_path),
          // The process that installed the item is logged with an "event_" prefix.
          process: actor(f, 'event_') ?? actor(f),
        }),
      };
    }
    case 'XPROTECT_DETECTED':
      return {
        ...base,
        kind: 'system.alert',
        subtype: 'xprotect_detected',
        ...defined({ path: nonEmpty(f.detected_path), process: actor(f) }),
        details: details({
          malware: f.malware_identifier,
          signatureVersion: f.signature_version,
          incident: f.incident_identifier,
        }),
      };
    case 'TCC_MODIFICATION':
      return {
        ...base,
        kind: 'system.alert',
        subtype: 'tcc_modified',
        ...defined({ process: actor(f, 'event_') ?? actor(f) }),
        details: details({
          eventType: f.event_type,
          service: f.service,
          identity: f.identity,
          identityType: f.identity_type,
          authRight: f.auth_right,
          authReason: f.auth_reason,
        }),
      };
    case 'GATEKEEPER_OVERRIDE':
      return {
        ...base,
        kind: 'system.alert',
        subtype: 'gatekeeper_override',
        ...defined({ path: nonEmpty(f.target), sha256: nonEmpty(f.hash), process: actor(f) }),
        details: {},
      };
    default:
      return undefined;
  }
}

function details(o: Record<string, string | undefined>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(o)) if (v) out[k] = v;
  return out;
}
