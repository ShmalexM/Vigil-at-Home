import type { SensorEvent } from '@vigil/core';
import { globToRegExp } from '@vigil/detection';
import {
  QUERY_NAMES,
  ProcessEnricher,
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

interface ProcMatch {
  teamId?: string;
  platform?: boolean;
  signingId?: RegExp;
}
interface WatchItem {
  name: string;
  paths: Array<{ re: RegExp; prefix: string | undefined }>;
  processes: ProcMatch[];
  denied: boolean;
  allowRead: boolean;
}
const enricher = new ProcessEnricher();

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
    const optsXml = xml.slice(m.index!, m.index! + m[0].length);
    const processes: ProcMatch[] = m[3]!
      .split('<dict>')
      .slice(1)
      .map((d) => {
        const pm: ProcMatch = {};
        const t = /<key>TeamID<\/key>\s*<string>([^<]*)<\/string>/.exec(d);
        if (t) pm.teamId = t[1]!;
        if (/<key>PlatformBinary<\/key>\s*<true\/>/.test(d)) pm.platform = true;
        const sid = /<key>SigningID<\/key>\s*<string>([^<]*)<\/string>/.exec(d);
        if (sid)
          pm.signingId = new RegExp(
            '^' + sid[1]!.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*') + '$',
          );
        return pm;
      });
    items.push({
      name: m[1]!,
      paths,
      processes,
      denied: /ProcessesWithDeniedPaths/.test(optsXml),
      allowRead: /<key>AllowReadAccess<\/key>\s*<true\/>/.test(optsXml),
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

function certCn(p: Proc): Record<string, string | undefined> {
  switch (p.signing) {
    case 'apple':
      return { cert_sha256: 'c', cert_cn: 'Software Signing' };
    case 'app_store':
      return { cert_sha256: 'c', cert_cn: 'Apple Mac OS Application Signing' };
    case 'developer_id':
      return { cert_sha256: 'c', cert_cn: `Developer ID Application: Vendor (${p.teamId ?? 'X'})` };
    default:
      return {};
  }
}

function santaProcessFields(p: Proc) {
  const name = p.path.split('/').pop() ?? '';
  return {
    sha256: p.sha256,
    ...certCn(p),
    pid: p.pid,
    ppid: p.ppid,
    uid: p.uid ?? 501,
    user: 'sam',
    path: p.path,
    args: (p.args ?? [name]).join(' '),
    teamid: p.teamId,
    quarantine_url: p.quarantine?.originUrl,
  };
}

function matchesPath(w: WatchItem, path: string): boolean {
  return w.paths.some(
    (p) => p.re.test(path) || (p.prefix !== undefined && path.startsWith(p.prefix)),
  );
}

function matchesProc(m: ProcMatch, p: Proc): boolean {
  const name = p.path.split('/').pop() ?? '';
  const sid = p.signing === 'apple' ? `com.apple.${name}` : p.signingId?.replace(/^[^:]*:/, '');
  if (m.platform && p.signing !== 'apple') return false;
  if (m.teamId && p.teamId !== m.teamId) return false;
  if (m.signingId && !(sid && m.signingId.test(sid))) return false;
  return m.platform === true || m.teamId !== undefined;
}

/** The watch item that reports this access, if any (Santa logs only what an item reports). */
function reportedBy(path: string, p: Proc | undefined, op: string): WatchItem | undefined {
  if (!p) return undefined;
  const items = santaWatchItems();
  for (const w of items) {
    if (!w.denied || !matchesPath(w, path)) continue;
    if (op === 'open' && w.allowRead) continue;
    if (w.processes.some((m) => matchesProc(m, p))) return w;
  }
  const w = items.find((i) => !i.denied && matchesPath(i, path));
  if (!w || (op === 'open' && w.allowRead)) return undefined;
  return w.processes.some((m) => matchesProc(m, p)) ? undefined : w;
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
      // Santa logged this program's launch earlier (the corpus leaves it out).
      if (e.process)
        enricher.enrich(
          santaLogLineToEvent(
            santaLine(e.ts, {
              action: 'EXEC',
              decision: 'ALLOW',
              reason: 'UNKNOWN',
              ...santaProcessFields(e.process),
            }),
          )!,
        );
      const w = reportedBy(e.path, e.process, e.op);
      if (!w) break;
      const access =
        e.op === 'rename'
          ? 'RENAME'
          : e.op === 'delete'
            ? 'UNLINK'
            : e.op === 'create'
              ? 'CREATE'
              : 'OPEN';
      lines.push([
        'santa',
        santaLine(e.ts, {
          action: 'FILE_ACCESS',
          policy_version: 'vigil-2',
          policy_name: w.name,
          path: e.path,
          access_type: access,
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
          signed:
            e.process?.signing === undefined
              ? undefined
              : ['unsigned', 'invalid'].includes(e.process.signing)
                ? '0'
                : '1',
          authority:
            e.process?.signing === 'apple'
              ? 'Software Signing'
              : e.process?.signing === 'developer_id'
                ? 'Developer ID Application: Vendor (X)'
                : '',
          team_identifier: e.process?.teamId,
          protocol: e.protocol === 'udp' ? '17' : '6',
        }),
      ]);
      break;
    case 'persistence':
      // Santa (macOS 13+) reports the launch item as it is added, with the
      // process that added it; osquery's launchd query sees the plist later.
      if (e.process && e.mechanism !== 'cron')
        lines.push([
          'santa',
          santaLine(e.ts, {
            action: e.change === 'removed' ? 'LAUNCH_ITEM_REMOVE' : 'LAUNCH_ITEM_ADD',
            item_type: e.mechanism === 'launch_daemon' ? 'DAEMON' : 'AGENT',
            item_path: e.path,
            exec_path: e.program,
            event_pid: e.process.pid,
            event_ppid: e.process.ppid,
            event_processpath: e.process.path,
            event_uid: e.process.uid ?? 501,
            event_user: 'sam',
          }),
        ]);
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
    case 'agent.tool_request':
      // No sensor involved: the agent's hook sends it to Vigil, so it arrives as it is.
      return [e];
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
  return out.map((ev) => enricher.enrich({ ...ev, ts: e.ts }));
}
