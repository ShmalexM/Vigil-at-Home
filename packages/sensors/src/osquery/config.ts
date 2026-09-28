// The osquery configuration Vigil installs. osquery only observes (it cannot
// block), so it covers what Santa's event log does not: which programs talk
// to which addresses, what opens a port to the network, which browser
// extensions are installed, and startup items as a periodic cross-check of
// Santa's real-time launch-item events.
//
// Queries are differential: osquery logs only rows that were added or
// removed since the previous run, one JSON object per line, to
// /var/log/osquery/osqueryd.results.log.

export const OSQUERY_RESULTS_LOG = '/var/log/osquery/osqueryd.results.log';
export const OSQUERY_CONFIG_PATH = '/var/osquery/osquery.conf';
/** osquery's launchd job reads startup flags from here. */
export const OSQUERY_FLAGS_PATH = '/var/osquery/osquery.flags';

/**
 * Startup-only flags. osquery ignores these when they appear in the config
 * file (verified on macOS 15 with osquery 5.23), so they go in the flagfile
 * that osquery's launchd job passes with --flagfile.
 */
export function osqueryFlags(): string {
  return (
    [
      '--logger_plugin=filesystem',
      // Keep osquery light on a laptop.
      '--watchdog_level=0',
      '--watchdog_memory_limit=200',
      '--watchdog_utilization_limit=10',
      '--disable_extensions=true',
    ].join('\n') + '\n'
  );
}

export const QUERY_NAMES = {
  networkConnections: 'vigil_network_connections',
  listeningPorts: 'vigil_listening_ports',
  browserExtensions: 'vigil_browser_extensions',
  launchd: 'vigil_launchd',
  crontab: 'vigil_crontab',
} as const;

export interface OsqueryConfigOptions {
  /** Seconds between connection snapshots. Short-lived connections between runs are missed. */
  networkIntervalSeconds?: number;
  persistenceIntervalSeconds?: number;
}

export function osqueryConfig(opts: OsqueryConfigOptions = {}): string {
  const net = opts.networkIntervalSeconds ?? 10;
  const persist = opts.persistenceIntervalSeconds ?? 60;
  const config = {
    options: {
      host_identifier: 'uuid',
      logger_path: '/var/log/osquery',
      // One JSON line per row change, which is what Vigil parses.
      logger_event_type: true,
      schedule_splay_percent: 10,
      disable_distributed: true,
    },
    schedule: {
      [QUERY_NAMES.networkConnections]: {
        query:
          'SELECT DISTINCT p.pid, p.path, p.name, p.uid, s.remote_address, s.remote_port, s.local_address, ' +
          's.local_port, s.protocol FROM process_open_sockets s JOIN processes p USING (pid) ' +
          'WHERE s.family IN (2, 30) AND s.remote_port != 0 AND s.remote_address NOT IN ' +
          "('127.0.0.1', '::1', '0.0.0.0', '::', '') AND s.remote_address NOT LIKE 'fe80:%';",
        interval: net,
        description: 'Outbound connections with the owning program',
      },
      [QUERY_NAMES.listeningPorts]: {
        query:
          'SELECT DISTINCT l.pid, p.path, p.name, p.uid, l.port, l.address, l.protocol FROM listening_ports l ' +
          "JOIN processes p USING (pid) WHERE l.port != 0 AND l.address NOT IN ('127.0.0.1', '::1');",
        interval: persist,
        description: 'Programs accepting connections from the network',
      },
      [QUERY_NAMES.browserExtensions]: {
        query:
          'SELECT e.browser_type, e.identifier, e.name, e.version, e.permissions, e.path FROM users ' +
          'CROSS JOIN chrome_extensions e USING (uid);',
        interval: persist * 5,
        description: 'Chrome, Brave, Edge and other Chromium extensions',
      },
      [QUERY_NAMES.launchd]: {
        query:
          'SELECT path, name, label, program, program_arguments, run_at_load, keep_alive FROM launchd ' +
          "WHERE path NOT LIKE '/System/%';",
        interval: persist,
        description: 'Launch agents and daemons outside the read-only system volume',
      },
      [QUERY_NAMES.crontab]: {
        query: 'SELECT command, path, minute, hour, day_of_month, month, day_of_week FROM crontab;',
        interval: persist * 5,
        description: 'Cron jobs',
      },
    },
  };
  return JSON.stringify(config, null, 2) + '\n';
}
