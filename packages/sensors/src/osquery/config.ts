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
/** Where osquery's macOS package installs the daemon. */
export const OSQUERYD_PATH = '/opt/osquery/lib/osquery.app/Contents/MacOS/osqueryd';
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
  health: 'vigil_health',
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
        // The signature join lets rules tell Apple's own listeners from others.
        // Skipping the resource and executable hashes keeps it to reading the
        // signature (the full check hashes every file in an app), and there are
        // only a handful of listening programs. GROUP BY folds the row osquery
        // returns for each architecture of a universal binary.
        query:
          'SELECT l.pid, p.path, p.name, p.uid, l.port, l.address, l.protocol, s.signed, s.authority, ' +
          's.team_identifier, s.identifier FROM listening_ports l JOIN processes p USING (pid) ' +
          'LEFT JOIN signature s ON s.path = p.path AND s.hash_resources = 0 AND s.hash_executable = 0 ' +
          "WHERE l.port != 0 AND l.address NOT IN ('127.0.0.1', '::1') " +
          'GROUP BY l.pid, l.port, l.address, l.protocol;',
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
      // Logs every row on every run, even when nothing else changed: proof
      // osquery is alive, and whether any of Vigil's queries is denylisted.
      // checked_at makes each run's rows differ from the last. Not a snapshot
      // query: the filesystem logger writes those to osqueryd.snapshots.log,
      // which Vigil does not read.
      [QUERY_NAMES.health]: {
        query:
          'SELECT name, denylisted, executions, (SELECT unix_time FROM time) AS checked_at ' +
          "FROM osquery_schedule WHERE name LIKE 'vigil_%';",
        interval: persist * 5,
        description: 'That osquery runs and none of the queries above is switched off',
      },
      [QUERY_NAMES.crontab]: {
        query: 'SELECT command, path, minute, hour, day_of_month, month, day_of_week FROM crontab;',
        interval: persist * 5,
        description: 'Cron jobs',
      },
    },
  };
  // When the watchdog kills osquery's worker (over its CPU or memory limit),
  // osquery denylists whichever query was running for 24 hours
  // (Config::recordQueryStart / denylistExpired in osquery's config.cpp). On a
  // busy Mac that would silently stop, say, connection reporting for a day.
  // The watchdog still keeps osquery within budget; the query just runs again
  // on its next interval.
  for (const q of Object.values(config.schedule)) Object.assign(q, { denylist: false });
  return JSON.stringify(config, null, 2) + '\n';
}
