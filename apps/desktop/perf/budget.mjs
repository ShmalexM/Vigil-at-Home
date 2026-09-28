// Vigil's resource budget, as checked by perf/measure.mjs. The reasoning and
// the budget for parts the app doesn't measure yet (sensors, the local model)
// are in docs/performance.md; change both together.
//
// `target` is what Vigil should cost on the oldest Macs it supports.
// `hard` is where the check fails: GitHub's Mac runners are shared VMs, so a
// measurement a little over target is reported but only a clear overrun fails.

const LIMITS = {
  startupMs: { target: 3000, hard: 10000, label: 'Start to menu-bar item', unit: 'ms' },
  'idle.cpuPct': { target: 0.5, hard: 3, label: 'Idle CPU (% of one core)', unit: '%' },
  'idle.wakeupsPerS': { target: 5, hard: 40, label: 'Idle wakeups', unit: '/s' },
  'idle.memMb': { target: 180, hard: 350, label: 'Idle memory, nothing open', unit: 'MB' },
  'popover.coldMs': { target: 800, hard: 3000, label: 'Popover, first open', unit: 'ms' },
  'popover.warmMs': { target: 150, hard: 600, label: 'Popover, reopen', unit: 'ms' },
  'window.memMb': { target: 400, hard: 700, label: 'Memory, main window open', unit: 'MB' },
  'closed.memMb': { target: 200, hard: 400, label: 'Memory after windows close', unit: 'MB' },
  'load.cpuPct': { target: 3, hard: 12, label: 'CPU storing 50 events/s', unit: '%' },
  'load.storedKbPerThousandEvents': {
    target: 700,
    hard: 2000,
    label: 'Disk used per 1,000 events',
    unit: 'KB',
  },
  'load.writtenKbPerThousandEvents': {
    target: 2000,
    hard: 10000,
    label: 'Disk writes per 1,000 events',
    unit: 'KB',
  },
};

const get = (obj, path) => path.split('.').reduce((o, k) => o?.[k], obj);

function checks(limits, results) {
  return Object.entries(limits).flatMap(([path, l]) => {
    const value = get(results, path);
    if (typeof value !== 'number') return [];
    const status = value > l.hard ? 'fail' : value > l.target ? 'over' : 'ok';
    return [
      {
        name: l.label,
        key: path,
        value: `${value} ${l.unit}`,
        budget: `${l.target} ${l.unit}`,
        status,
      },
    ];
  });
}

/** Sensors, measured by perf/sensors.mjs. osquery's own watchdog stops it at 10% CPU and 200 MB. */
const SENSOR_LIMITS = {
  'osquery.cpuPct': { target: 1.5, hard: 10, label: 'osquery CPU (% of one core)', unit: '%' },
  'osquery.memMb': { target: 80, hard: 200, label: 'osquery memory', unit: 'MB' },
  'osquery.wakeupsPerS': { target: 10, hard: 50, label: 'osquery wakeups', unit: '/s' },
  'tailing.current.cpuPct': { target: 0.1, hard: 1, label: 'Log tailing CPU', unit: '%' },
  'tailing.current.wakeupsPerS': { target: 2, hard: 30, label: 'Log tailing wakeups', unit: '/s' },
};

export const SENSOR_BUDGET = {
  /** Poll intervals to compare; the first is the sensors package's default. */
  tailIntervals: [200, 1000],
  limits: SENSOR_LIMITS,
  checks: (results) => checks(SENSOR_LIMITS, results),
};

export const BUDGET = {
  load: { eventsPerSecond: 50 },
  closed: { settleSeconds: 10 },
  limits: LIMITS,
  /** One row per measure: value, budget and ok / over (budget) / fail (hard limit). */
  checks: (results) => checks(LIMITS, results),
};
