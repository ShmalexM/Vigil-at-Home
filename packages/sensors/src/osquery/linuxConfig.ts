// osquery on Linux. With no Santa there, osquery is the whole sensor:
//
//   bpf_process_events  every launch, from eBPF probes on exec (5 s batches)
//   process_open_sockets connections with the owning program (30 s)
//   listening_ports      programs accepting connections
//   startup files        systemd units and autostart entries users and admins add
//   shell profiles       .bashrc, .profile, .zshrc and /etc/profile.d
//   crontab, chrome_extensions, and the health row, as on macOS
//
// Launches arrive with no signature; the helper's package index fills in
// whether the package manager installed the program (linux/packages.ts).
// osquery's Linux package runs osqueryd as the systemd service "osqueryd"
// with these two files.

import { QUERY_NAMES } from './config.js';

export const LINUX_OSQUERY_CONFIG_PATH = '/etc/osquery/osquery.conf';
export const LINUX_OSQUERY_FLAGS_PATH = '/etc/osquery/osquery.flags';
export const LINUX_OSQUERYD_PATH = '/opt/osquery/bin/osqueryd';
export const LINUX_OSQUERY_SERVICE = 'osqueryd.service';

export const LINUX_QUERY_NAMES = {
  processEvents: 'vigil_process_events',
  startup: 'vigil_linux_startup',
  shellProfiles: 'vigil_shell_profiles',
} as const;

/** Startup flags. eBPF events need the event framework, which is off by default. */
export function osqueryLinuxFlags(): string {
  return (
    [
      '--logger_plugin=filesystem',
      '--watchdog_level=0',
      '--watchdog_memory_limit=200',
      '--watchdog_utilization_limit=10',
      '--disable_extensions=true',
      '--disable_events=false',
      '--enable_bpf_events=true',
      // Events are read every few seconds; keep only a minute of them.
      '--events_expiry=60',
      '--events_max=20000',
      // The audit and inotify publishers stay off: eBPF covers launches.
      '--disable_audit=true',
      '--enable_file_events=false',
    ].join('\n') + '\n'
  );
}

const STARTUP_GLOBS = [
  '/etc/systemd/system/%',
  '/etc/systemd/user/%',
  '/etc/xdg/autostart/%',
  '/root/.config/systemd/user/%',
  '/root/.config/autostart/%',
  '/home/%/.config/systemd/user/%',
  '/home/%/.config/autostart/%',
];

const PROFILE_GLOBS = [
  '/etc/profile',
  '/etc/bash.bashrc',
  '/etc/profile.d/%',
  '/root/.bashrc',
  '/root/.profile',
  '/home/%/.bashrc',
  '/home/%/.bash_profile',
  '/home/%/.bash_login',
  '/home/%/.profile',
  '/home/%/.zshrc',
  '/home/%/.zprofile',
  '/home/%/.zshenv',
];

const like = (globs: string[]) => globs.map((g) => `f.path LIKE '${g}'`).join(' OR ');

export function osqueryLinuxConfig(
  opts: { networkIntervalSeconds?: number; persistenceIntervalSeconds?: number } = {},
): string {
  const net = opts.networkIntervalSeconds ?? 30;
  const persist = opts.persistenceIntervalSeconds ?? 60;
  const config = {
    options: {
      host_identifier: 'uuid',
      logger_path: '/var/log/osquery',
      logger_event_type: true,
      schedule_splay_percent: 10,
      disable_distributed: true,
    },
    schedule: {
      [LINUX_QUERY_NAMES.processEvents]: {
        // syscall is execve or execveat; failed launches (exit_code < 0) never ran.
        query:
          'SELECT pid, parent, uid, path, cwd, cmdline, json_cmdline, time FROM bpf_process_events ' +
          "WHERE syscall IN ('execve', 'execveat') AND exit_code >= 0;",
        interval: 5,
        description: 'Every program launch',
      },
      [QUERY_NAMES.networkConnections]: {
        query:
          'SELECT DISTINCT p.pid, p.path, p.name, p.uid, s.remote_address, s.remote_port, s.local_address, ' +
          's.local_port, s.protocol FROM process_open_sockets s JOIN processes p USING (pid) ' +
          'WHERE s.family IN (2, 10) AND s.remote_port != 0 AND s.remote_address NOT IN ' +
          "('127.0.0.1', '::1', '0.0.0.0', '::', '') AND s.remote_address NOT LIKE 'fe80:%' " +
          "AND s.remote_address NOT LIKE '127.%';",
        interval: net,
        description: 'Outbound connections with the owning program',
      },
      [QUERY_NAMES.listeningPorts]: {
        query:
          'SELECT l.pid, p.path, p.name, p.uid, l.port, l.address, l.protocol FROM listening_ports l ' +
          "JOIN processes p USING (pid) WHERE l.port != 0 AND l.address NOT IN ('127.0.0.1', '::1') " +
          "AND l.address NOT LIKE '127.%' GROUP BY l.pid, l.port, l.address, l.protocol;",
        interval: persist,
        description: 'Programs accepting connections from the network',
      },
      [QUERY_NAMES.browserExtensions]: {
        query:
          'SELECT e.browser_type, e.identifier, e.name, e.version, e.permissions, e.path FROM users ' +
          'CROSS JOIN chrome_extensions e USING (uid);',
        interval: persist * 5,
        description: 'Chrome, Chromium, Brave and other Chromium extensions',
      },
      [LINUX_QUERY_NAMES.startup]: {
        // The hash makes an edited file show up as a change, not only new ones.
        query:
          `SELECT f.path, h.sha256 FROM file f JOIN hash h USING (path) WHERE (${like(STARTUP_GLOBS)}) ` +
          "AND f.type = 'regular';",
        interval: persist,
        description: 'systemd units and autostart entries outside the package folders',
      },
      [LINUX_QUERY_NAMES.shellProfiles]: {
        query: `SELECT f.path, h.sha256 FROM file f JOIN hash h USING (path) WHERE (${like(PROFILE_GLOBS)}) AND f.type = 'regular';`,
        interval: persist * 5,
        description: 'Shell startup files',
      },
      [QUERY_NAMES.crontab]: {
        query: 'SELECT command, path, minute, hour, day_of_month, month, day_of_week FROM crontab;',
        interval: persist * 5,
        description: 'Cron jobs',
      },
      [QUERY_NAMES.health]: {
        query:
          'SELECT name, denylisted, executions, (SELECT unix_time FROM time) AS checked_at ' +
          "FROM osquery_schedule WHERE name LIKE 'vigil_%';",
        interval: persist * 5,
        description: 'That osquery runs and none of the queries above is switched off',
      },
    },
  };
  // See osqueryConfig: a watchdog kill must not switch a query off for a day.
  for (const q of Object.values(config.schedule)) Object.assign(q, { denylist: false });
  return JSON.stringify(config, null, 2) + '\n';
}
