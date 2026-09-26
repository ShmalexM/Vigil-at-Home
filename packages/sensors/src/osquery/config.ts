// The osquery configuration Vigil installs. osquery only observes (it cannot
// block), so it covers what Santa's event log does not: which programs talk
// to which addresses, and startup items as a periodic cross-check of Santa's
// real-time launch-item events. (Listening ports are waiting on an event kind
// in @vigil/core.)
//
// Queries are differential: osquery logs only rows that were added or
// removed since the previous run, one JSON object per line, to
// /var/log/osquery/osqueryd.results.log.

export const OSQUERY_RESULTS_LOG = '/var/log/osquery/osqueryd.results.log';
export const OSQUERY_CONFIG_PATH = '/var/osquery/osquery.conf';

export const QUERY_NAMES = {
  networkConnections: 'vigil_network_connections',
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
      logger_plugin: 'filesystem',
      logger_path: '/var/log/osquery',
      // One JSON line per row change, which is what Vigil parses.
      logger_event_type: true,
      schedule_splay_percent: 10,
      // Keep osquery light on a laptop.
      watchdog_level: 0,
      watchdog_memory_limit: 200,
      watchdog_utilization_limit: 10,
      disable_distributed: true,
      disable_extensions: true,
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
