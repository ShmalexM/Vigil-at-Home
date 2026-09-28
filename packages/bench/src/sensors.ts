import type { SensorEvent } from '@vigil/core';
import { globToRegExp } from '@vigil/detection';
import {
  QUERY_NAMES,
  fileAccessPolicy,
  osqueryLineToEvents,
  santaLogLineToEvent,
} from '@vigil/sensors';

/**
 * What Vigil's sensors would actually report for an activity.
 *
 * The attack corpus describes activity with every field a rule could want.
 * Real events come from Santa's log and osquery's results, through Vigil's
 * parsers, with Vigil's shipped Santa and osquery configuration. This renders
 * each activity as the log line the sensor writes, then runs Vigil's own
 * parser on it, so the benchmark shows what the rules get to see today.
 *
 * Modelled from the shipped configuration (packages/sensors):
 * - Santa logs every EXEC (with sha256, team ID, signing ID, quarantine URL).
 * - Santa's file-access policy watches only the paths in fileAccessPolicy(),
 *   reports only programs it doesn't allow, and starts in audit-only mode.
 *   No FileChangesRegex is set, so other file writes are not logged.
 * - Santa reports XProtect detections.
 * - osquery reports connections (no host names), listening ports, launchd
 *   items and Chromium extensions.
 */
export interface SensorOptions {
  /** Santa's file-access policy blocks instead of auditing (the user turned blocking on). */
  enforceFileAccess?: boolean;
}

interface WatchItem {
  name: string;
  paths: Array<{ re: RegExp; prefix: string | undefined }>;
  allowTeamIds: string[];
  allowPlatform: boolean;
}

let watchItems: WatchItem[] | undefined;

/** The watch items from the policy Vigil ships, read back from its plist. */
export function santaWatchItems(): WatchItem[] {
  if (watchItems) return watchItems;
  const xml = fileAccessPolicy();
  const items: WatchItem[] = [];
  const itemRe =
    /<key>([A-Za-z]+)<\/key>\s*<dict>\s*<key>Paths<\/key>\s*<array>([\s\S]*?)<\/array>[\s\S]*?<key>Processes<\/key>\s*<array>([\s\S]*?)<\/array>/g;
  for (const m of xml.matchAll(itemRe)) {
    const paths = [
      ...m[2]!.matchAll(
        /<key>Path<\/key>\s*<string>([^<]*)<\/string>\s*<key>IsPrefix<\/key>\s*<(true|false)\/>/g,
      ),
    ].map((p) => {
      const path = unxml(p[1]!);
      return p[2] === 'true'
        ? { re: globToRegExp(`${path}**`), prefix: path }
        : { re: globToRegExp(path), prefix: undefined };
    });
    items.push({
      name: m[1]!,
      paths,
      allowTeamIds: [...m[3]!.matchAll(/<key>TeamID<\/key>\s*<string>([^<]*)<\/string>/g)].map(
        (t) => t[1]!,
      ),
      allowPlatform: /<key>PlatformBinary<\/key>\s*<true\/>/.test(m[3]!),
    });
  }
  if (items.length === 0) throw new Error('Could not read the Santa file-access policy');
  return (watchItems = items);
}

function unxml(s: string): string {
  return s
    .replaceAll('&lt;', '<')
    .replaceAll('&gt;', '>')
    .replaceAll('&quot;', '"')
    .replaceAll('&apos;', "'")
    .replaceAll('&amp;', '&');
}

function santaValue(v: string | number | undefined): string {
  return String(v ?? '')
    .replaceAll('|', '<pipe>')
    .replace(/\n/g, '\\n');
}

function santaLine(ts: number, fields: Record<string, string | number | undefined>): string {
  const body = Object.entries(fields)
    .filter(([, v]) => v !== undefined && v !== '')
    .map(([k, v]) => `${k}=${santaValue(v)}`)
    .join('|');
  return `[${new Date(ts).toISOString()}] I santad: ${body}|machineid=bench`;
}

function osqueryLine(
  ts: number,
  name: string,
  columns: Record<string, string | undefined>,
): string {
  const cols: Record<string, string> = {};
  for (const [k, v] of Object.entries(columns)) if (v !== undefined) cols[k] = v;
  return JSON.stringify({
    name,
    unixTime: Math.floor(ts / 1000),
    action: 'added',
    counter: 7,
    columns: cols,
  });
}

type Proc = NonNullable<Extract<SensorEvent, { kind: 'process.exec' }>['process']>;

function santaProcessFields(p: Proc) {
  const platform = p.signing === 'apple';
  const name = p.path.split('/').pop() ?? '';
  return {
    sha256: p.sha256,
    pid: p.pid,
    ppid: p.ppid,
    uid: p.uid ?? 501,
    user: 'sam',
    path: p.path,
    args: (p.args ?? [name]).join(' '),
    teamid: p.teamId,
    signingid: platform ? `platform:com.apple.${name}` : p.signingId,
    quarantine_url: p.quarantine?.originUrl,
  };
}

function watchedBy(path: string): WatchItem | undefined {
  return santaWatchItems().find((w) =>
    w.paths.some((p) => p.re.test(path) || (p.prefix !== undefined && path.startsWith(p.prefix))),
  );
}

function allowed(w: WatchItem, p: Proc | undefined): boolean {
  if (!p) return false;
  if (w.allowPlatform && p.signing === 'apple') return true;
  return p.teamId !== undefined && w.allowTeamIds.includes(p.teamId);
}

/** The events Vigil would receive for this activity, or [] when no sensor sees it. */
export function throughSensors(e: SensorEvent, opts: SensorOptions = {}): SensorEvent[] {
  const lines: Array<['santa' | 'osquery', string]> = [];
  switch (e.kind) {
    case 'process.exec':
      lines.push([
        'santa',
        santaLine(e.ts, {
          action: 'EXEC',
          decision: 'ALLOW',
          reason: 'UNKNOWN',
          ...santaProcessFields(e.process),
        }),
      ]);
      break;
    case 'santa.decision':
      if (e.target === 'execution')
        lines.push([
          'santa',
          santaLine(e.ts, {
            action: 'EXEC',
            decision: 'DENY',
            reason: e.reason.replace(/^BLOCK_/, ''),
            ...santaProcessFields(e.process),
          }),
        ]);
      break;
    case 'file': {
      if (e.op !== 'open') break; // no FileChangesRegex: writes and renames are not logged
      const w = watchedBy(e.path);
      if (!w || allowed(w, e.process)) break;
      lines.push([
        'santa',
        santaLine(e.ts, {
          action: 'FILE_ACCESS',
          policy_version: 'vigil-1',
          policy_name: w.name,
          path: e.path,
          access_type: 'OPEN',
          decision: opts.enforceFileAccess ? 'DENIED' : 'AUDIT_ONLY',
          pid: e.process?.pid,
          ppid: e.process?.ppid,
          processpath: e.process?.path,
          uid: e.process?.uid ?? 501,
          user: 'sam',
        }),
      ]);
      break;
    }
    case 'system.alert':
      if (e.subtype === 'xprotect_detected')
        lines.push([
          'santa',
          santaLine(e.ts, {
            action: 'XPROTECT_DETECTED',
            detected_path: e.path,
            malware_identifier: e.details['malware'],
          }),
        ]);
      break;
    case 'network.connection':
      lines.push([
        'osquery',
        osqueryLine(e.ts, QUERY_NAMES.networkConnections, {
          pid: String(e.process?.pid ?? 0),
          path: e.process?.path,
          name: e.process?.path.split('/').pop(),
          uid: String(e.process?.uid ?? 501),
          remote_address: e.remoteAddress,
          remote_port: String(e.remotePort ?? 443),
          local_address: '192.168.1.20',
          local_port: '52000',
          protocol: e.protocol === 'udp' ? '17' : '6',
        }),
      ]);
      break;
    case 'network.listen':
      lines.push([
        'osquery',
        osqueryLine(e.ts, QUERY_NAMES.listeningPorts, {
          pid: String(e.process?.pid ?? 0),
          path: e.process?.path,
          name: e.process?.path.split('/').pop(),
          uid: '501',
          port: String(e.localPort),
          address: e.localAddress,
          protocol: e.protocol === 'udp' ? '17' : '6',
        }),
      ]);
      break;
    case 'persistence':
      lines.push([
        'osquery',
        osqueryLine(e.ts, QUERY_NAMES.launchd, {
          path: e.path,
          name: e.path.split('/').pop(),
          label: e.label,
          program: e.programArgs?.length ? '' : e.program,
          program_arguments: (e.programArgs ?? []).join(' '),
          run_at_load: '1',
          keep_alive: '0',
        }),
      ]);
      break;
    case 'browser.extension':
      lines.push([
        'osquery',
        osqueryLine(e.ts, QUERY_NAMES.browserExtensions, {
          browser_type: e.browser,
          identifier: e.extensionId,
          name: e.name,
          version: '1.0.0',
          permissions: (e.permissions ?? []).join(', '),
          path: '/Users/sam/Library/Application Support/Google/Chrome/Default/Extensions/x',
        }),
      ]);
      break;
    default:
      break;
  }
  const out: SensorEvent[] = [];
  for (const [sensor, line] of lines) {
    if (sensor === 'santa') {
      const ev = santaLogLineToEvent(line);
      if (ev) out.push(ev);
    } else out.push(...osqueryLineToEvents(line));
  }
  // Keep the corpus's timestamps so windows and learning periods line up.
  return out.map((ev) => ({ ...ev, ts: e.ts }));
}
