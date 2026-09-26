// Turns lines of osquery's filesystem results log into SensorEvents.

import { createHash } from 'node:crypto';
import type { EventOfKind, SensorEvent } from '@vigil/core';
import { defined, pidOf } from '../types.js';
import { QUERY_NAMES } from './config.js';

interface OsqueryResultLine {
  name?: string;
  unixTime?: number | string;
  action?: 'added' | 'removed' | 'snapshot';
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
  if (Number(parsed.counter) === 0 && !opts.includeBaseline) return [];
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
    case QUERY_NAMES.launchd: {
      const path = c.path ?? '';
      const args = c.program_arguments ? c.program_arguments.split(' ').filter(Boolean) : undefined;
      return [
        {
          ...base,
          kind: 'persistence',
          change: added ? 'added' : 'removed',
          mechanism: launchdMechanism(path),
          ...defined({ path, program: c.program || args?.[0] || undefined, programArgs: args }),
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
