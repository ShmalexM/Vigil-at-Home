// Turns lines of osquery's filesystem results log into SensorEvents.

import { createHash } from 'node:crypto';
import type { EventOfKind, SensorEvent } from '@vigil/core';
import { defined, pidOf } from '../types.js';
import { QUERY_NAMES } from './config.js';
import { LINUX_QUERY_NAMES } from './linuxConfig.js';
import { osquerySigning } from '../signing.js';

interface OsqueryResultLine {
  name?: string;
  unixTime?: number | string;
  action?: 'added' | 'removed';
  /** 0 on the first run of a query, when every existing row is reported as "added". */
  counter?: number | string;
  columns?: Record<string, string>;
}

export interface OsqueryParseOptions {
  /**
   * First-run rows describe what was already there before Vigil started
   * watching, not new activity. They are dropped by default so installing
   * Vigil doesn't raise an alert for every existing launch agent; set this
   * for an explicit inventory scan.
   */
  includeBaseline?: boolean;
}

function id(line: string): string {
  return 'osquery:' + createHash('sha256').update(line).digest('hex').slice(0, 32);
}

function port(v: string | undefined): number | undefined {
  const n = pidOf(v);
  return n !== undefined && n <= 65535 ? n : undefined;
}

function protocolName(v: string | undefined): 'tcp' | 'udp' | 'other' {
  return v === '6' ? 'tcp' : v === '17' ? 'udp' : 'other';
}

function launchdMechanism(path: string): EventOfKind<'persistence'>['mechanism'] {
  if (path.includes('/LaunchDaemons/')) return 'launch_daemon';
  if (path.includes('/LaunchAgents/')) return 'launch_agent';
  return 'other';
}

export function osqueryLineToEvents(line: string, opts: OsqueryParseOptions = {}): SensorEvent[] {
  let parsed: OsqueryResultLine;
  try {
    parsed = JSON.parse(line) as OsqueryResultLine;
  } catch {
    return [];
  }
  const c = parsed.columns;
  if (!c || typeof c !== 'object') return [];
  // Event tables only ever hold new activity, so their first run is real too.
  const evented = parsed.name === LINUX_QUERY_NAMES.processEvents;
  if (Number(parsed.counter) === 0 && !opts.includeBaseline && !evented) return [];
  const unix = Number(parsed.unixTime);
  const base = {
    id: id(line),
    ts: Number.isFinite(unix) && unix > 0 ? unix * 1000 : Date.now(),
    source: 'osquery' as const,
    raw: parsed,
  };
  const added = parsed.action !== 'removed';

  switch (parsed.name) {
    case QUERY_NAMES.networkConnections: {
      if (!added) return [];
      return [
        {
          ...base,
          kind: 'network.connection',
          direction: 'outbound',
          protocol: protocolName(c.protocol),
          ...defined({
            remoteAddress: c.remote_address ?? '',
            remotePort: port(c.remote_port),
            localAddress: c.local_address || undefined,
            localPort: port(c.local_port),
          }),
          process: defined({ pid: pidOf(c.pid) ?? 0, path: c.path ?? '', uid: pidOf(c.uid) }),
        },
      ];
    }
    case QUERY_NAMES.listeningPorts: {
      if (!added) return [];
      const localPort = port(c.port);
      if (localPort === undefined) return [];
      return [
        {
          ...base,
          kind: 'network.listen',
          protocol: protocolName(c.protocol),
          localPort,
          ...defined({ localAddress: c.address || undefined }),
          process: defined({
            pid: pidOf(c.pid) ?? 0,
            path: c.path ?? '',
            uid: pidOf(c.uid),
            signing: osquerySigning(c),
            teamId: c.team_identifier || undefined,
            signingId: c.identifier || undefined,
          }),
        },
      ];
    }
    case QUERY_NAMES.browserExtensions: {
      if (!c.identifier) return [];
      const permissions = c.permissions
        ? c.permissions
            .split(',')
            .map((p) => p.trim())
            .filter(Boolean)
        : undefined;
      return [
        {
          ...base,
          kind: 'browser.extension',
          change: added ? 'added' : 'removed',
          browser: c.browser_type || 'chrome',
          extensionId: c.identifier,
          ...defined({ name: c.name || undefined, permissions }),
        },
      ];
    }
    case QUERY_NAMES.launchd: {
      const path = c.path ?? '';
      const args = c.program_arguments ? c.program_arguments.split(' ').filter(Boolean) : undefined;
      return [
        {
          ...base,
          kind: 'persistence',
          change: added ? 'added' : 'removed',
          mechanism: launchdMechanism(path),
          ...defined({
            path,
            label: c.label || undefined,
            program: c.program || args?.[0] || undefined,
            programArgs: args,
          }),
        },
      ];
    }
    case LINUX_QUERY_NAMES.processEvents: {
      const path = c.path ?? '';
      const pid = pidOf(c.pid);
      if (!added || !path.startsWith('/') || pid === undefined) return [];
      const t = Number(c.time);
      return [
        {
          ...base,
          ...(Number.isFinite(t) && t > 0 ? { ts: t * 1000 } : {}),
          kind: 'process.exec',
          process: defined({
            pid,
            ppid: pidOf(c.parent),
            path,
            args: commandLine(c.json_cmdline, c.cmdline),
            cwd: c.cwd || undefined,
            uid: pidOf(c.uid),
          }),
        },
      ];
    }
    case LINUX_QUERY_NAMES.startup: {
      const path = c.path ?? '';
      if (!path.startsWith('/')) return [];
      return [
        {
          ...base,
          kind: 'persistence',
          change: added ? 'added' : 'removed',
          mechanism: path.includes('/autostart/') ? 'autostart' : 'systemd_unit',
          path,
          ...defined({ label: path.slice(path.lastIndexOf('/') + 1) || undefined }),
        },
      ];
    }
    case LINUX_QUERY_NAMES.shellProfiles: {
      const path = c.path ?? '';
      if (!path.startsWith('/')) return [];
      return [
        {
          ...base,
          kind: 'persistence',
          change: added ? 'modified' : 'removed',
          mechanism: 'shell_profile',
          path,
        },
      ];
    }
    case QUERY_NAMES.crontab:
      return [
        {
          ...base,
          kind: 'persistence',
          change: added ? 'added' : 'removed',
          mechanism: 'cron',
          ...defined({ path: c.path ?? '', program: c.command || undefined }),
        },
      ];
    default:
      return [];
  }
}

/**
 * A launch's arguments. osquery gives them as a JSON array in json_cmdline;
 * the plain cmdline joins them with spaces and can't be split exactly, so
 * it is only the fallback.
 */
function commandLine(json: string | undefined, plain: string | undefined): string[] | undefined {
  if (json) {
    try {
      const parsed: unknown = JSON.parse(json);
      if (Array.isArray(parsed) && parsed.every((a) => typeof a === 'string'))
        return parsed.slice(0, 256);
    } catch {
      // fall back to cmdline
    }
  }
  const parts = plain?.split(' ').filter(Boolean);
  return parts?.length ? parts.slice(0, 256) : undefined;
}

/**
 * A row of the health query: undefined for any other line, otherwise the
 * query it names if osquery has denylisted it (empty when all is well). The
 * rows a run replaces come back as "removed" and say nothing new.
 */
export function osqueryHealth(line: string): { denylisted: string[] } | undefined {
  let parsed: OsqueryResultLine;
  try {
    parsed = JSON.parse(line) as OsqueryResultLine;
  } catch {
    return undefined;
  }
  if (parsed.name !== QUERY_NAMES.health) return undefined;
  const c = parsed.columns;
  const off = parsed.action !== 'removed' && c?.denylisted === '1' && c.name;
  return { denylisted: off ? [c.name!] : [] };
}
