// Resource check for the sensors: what osquery with Vigil's configuration and
// Vigil's log reading cost the Mac.
//   sudo node perf/sensors.mjs [outDir]
// macOS only, as root, with osquery installed (`brew install --cask osquery`).
// Skips cleanly until packages/sensors exists.
//
//   osquery   osqueryd running Vigil's schedule: CPU, memory, wakeups, and
//             how long each scheduled query takes (its cost is time ÷ interval)
//   tailing   following Santa's and osquery's logs with no new lines, at the
//             sensors package's poll interval and with alternatives
import { execFile, execFileSync, spawn } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { promisify } from 'node:util';
import { SENSOR_BUDGET } from './budget.mjs';

const appDir = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const repo = resolve(appDir, '../..');
const out = resolve(process.argv[2] ?? join(appDir, 'perf-results'));
mkdirSync(out, { recursive: true });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const round = (n, d = 0) => Math.round(n * 10 ** d) / 10 ** d;
const SECONDS = Number(process.env.VIGIL_PERF_SENSOR_S ?? 120);

const sensorsSrc = join(repo, 'packages/sensors/src');
if (!existsSync(join(sensorsSrc, 'osquery/config.ts'))) {
  console.log('packages/sensors not on this branch yet; skipping the sensor check.');
  process.exit(0);
}
if (process.platform !== 'darwin' || process.getuid?.() !== 0) {
  console.log('The sensor check needs macOS and root.');
  process.exit(1);
}

/** Bundle a TypeScript module from the sensors package so plain Node can run it. Returns its file URL. */
async function bundle(entry) {
  // esbuild comes with vite, which the app already depends on.
  const esbuild = createRequire(createRequire(join(appDir, 'package.json')).resolve('vite'))(
    'esbuild',
  );
  const file = join(mkdtempSync(join(tmpdir(), 'vigil-perf-')), 'mod.mjs');
  await esbuild.build({
    entryPoints: [entry],
    bundle: true,
    format: 'esm',
    platform: 'node',
    outfile: file,
    logLevel: 'error',
  });
  return pathToFileURL(file).href;
}

// ------------------------------------------------------------ measuring

function cpuSeconds(t) {
  const [days, rest] = t.includes('-') ? t.split('-') : ['0', t];
  const parts = rest.split(':').map(Number);
  while (parts.length < 3) parts.unshift(0);
  return Number(days) * 86400 + parts[0] * 3600 + parts[1] * 60 + parts[2];
}

/** pid and descendants → { cpuS, memMb } (memory is the physical footprint, as Activity Monitor shows). */
function snapshot(rootPids) {
  const rows = execFileSync('ps', ['-A', '-o', 'pid=,ppid=,time='], { encoding: 'utf8' })
    .trim()
    .split('\n')
    .map((l) => l.trim().split(/\s+/))
    .map(([pid, ppid, time]) => ({ pid: Number(pid), ppid: Number(ppid), cpuS: cpuSeconds(time) }));
  const keep = new Set(rootPids);
  for (let grew = true; grew;) {
    grew = false;
    for (const r of rows)
      if (!keep.has(r.pid) && keep.has(r.ppid)) {
        keep.add(r.pid);
        grew = true;
      }
  }
  const mem = new Map();
  const unit = { B: 1 / 1048576, K: 1 / 1024, M: 1, G: 1024 };
  for (const line of execFileSync('top', ['-l', '1', '-stats', 'pid,mem'], {
    encoding: 'utf8',
  }).split('\n')) {
    const m = /^\s*(\d+)\s+([\d.]+)([BKMG])/.exec(line);
    if (m) mem.set(Number(m[1]), Number(m[2]) * unit[m[3]]);
  }
  return new Map(
    rows
      .filter((r) => keep.has(r.pid))
      .map((r) => [r.pid, { cpuS: r.cpuS, memMb: mem.get(r.pid) ?? 0 }]),
  );
}

async function wakeups(pids, seconds) {
  const { stdout } = await promisify(execFile)(
    'powermetrics',
    [
      '-f',
      'plist',
      '-n',
      '1',
      '-i',
      String(seconds * 1000),
      '--samplers',
      'tasks',
      '--show-process-energy',
    ],
    { encoding: 'utf8', maxBuffer: 64 << 20 },
  );
  const plist = stdout
    .replace(/\0/g, '')
    .replace(/<(date|data)>([^<]*)<\/\1>/g, '<string>$2</string>');
  const json = JSON.parse(
    execFileSync('plutil', ['-convert', 'json', '-o', '-', '-'], {
      input: plist,
      encoding: 'utf8',
    }),
  );
  const tasks = (json.tasks ?? []).filter((t) => pids.has(t.pid));
  const num = (t, k) => (typeof t[k] === 'number' ? t[k] : 0);
  return {
    wakeupsPerS: round(
      tasks.reduce((a, t) => a + num(t, 'intr_wakeups_per_s') + num(t, 'idle_wakeups_per_s'), 0),
      1,
    ),
    energyImpact: round(
      tasks.reduce((a, t) => a + num(t, 'energy_impact'), 0),
      2,
    ),
  };
}

async function measure(rootPids, seconds) {
  const before = snapshot(rootPids);
  const t0 = Date.now();
  const pm = await wakeups(new Set(before.keys()), seconds).catch(() => null);
  if (!pm) await sleep(seconds * 1000);
  const after = snapshot(rootPids);
  const wall = (Date.now() - t0) / 1000;
  let cpu = 0;
  let mem = 0;
  for (const [pid, r] of after) {
    cpu += r.cpuS - (before.get(pid)?.cpuS ?? r.cpuS);
    mem += r.memMb;
  }
  return {
    seconds: Math.round(wall),
    cpuPct: round((cpu / wall) * 100, 2),
    memMb: round(mem),
    ...pm,
  };
}

const results = { platform: `${process.platform}-${process.arch}` };

// -------------------------------------------------------------- osquery

const bin = (name) =>
  [`/usr/local/bin/${name}`, `/opt/osquery/lib/osquery.app/Contents/MacOS/${name}`].find((p) =>
    existsSync(p),
  );
if (bin('osqueryd')) {
  const { osqueryConfig, osqueryFlags } = await import(
    await bundle(join(sensorsSrc, 'osquery/config.ts'))
  );
  const dir = mkdtempSync(join(tmpdir(), 'vigil-osq-'));
  const config = osqueryConfig();
  writeFileSync(join(dir, 'osquery.conf'), config);
  // Vigil's startup flags, with paths moved into the scratch folder.
  writeFileSync(
    join(dir, 'osquery.flags'),
    osqueryFlags() +
      [
        `--config_path=${dir}/osquery.conf`,
        `--database_path=${dir}/db`,
        `--logger_path=${dir}`,
        `--pidfile=${dir}/osqueryd.pid`,
        '--extensions_socket=' + `${dir}/em.sock`,
      ].join('\n') +
      '\n',
  );

  // Cost of each scheduled query, run once by itself.
  const schedule = JSON.parse(config).schedule;
  results.queries = {};
  for (const [name, { query, interval }] of Object.entries(schedule)) {
    const t0 = process.hrtime.bigint();
    let rows;
    try {
      rows = JSON.parse(
        execFileSync(bin('osqueryi'), ['--json', query], { encoding: 'utf8', maxBuffer: 64 << 20 }),
      ).length;
    } catch {
      rows = -1;
    }
    const ms = Number(process.hrtime.bigint() - t0) / 1e6;
    // osqueryi startup is included; it is the same for every query, so compare them to each other.
    results.queries[name] = {
      ms: round(ms),
      rows,
      interval,
      dutyPct: round((ms / 1000 / interval) * 100, 2),
    };
  }
  results.queries.baseline = (() => {
    const t0 = process.hrtime.bigint();
    execFileSync(bin('osqueryi'), ['--json', 'SELECT 1;']);
    return {
      ms: round(Number(process.hrtime.bigint() - t0) / 1e6),
      note: 'osqueryi start-up alone',
    };
  })();

  const daemon = spawn(bin('osqueryd'), [`--flagfile=${dir}/osquery.flags`], { stdio: 'ignore' });
  await sleep(30000); // first runs of every query, then steady state
  results.osquery = await measure([daemon.pid], SECONDS);
  daemon.kill('SIGTERM');
  await sleep(2000);
  rmSync(dir, { recursive: true, force: true });
} else {
  console.log('osquery is not installed; skipping it.');
}

// -------------------------------------------------------------- tailing

// A child process follows two idle logs (Santa's and osquery's) the way the
// sensors hub does, so its CPU and wakeups are the tailing cost alone.
const tailUrl = JSON.stringify(await bundle(join(sensorsSrc, 'tail.ts')));
const logs = mkdtempSync(join(tmpdir(), 'vigil-logs-'));
for (const f of ['santa.log', 'osqueryd.results.log']) writeFileSync(join(logs, f), 'start\n');

const variants = {
  idleNode: `setInterval(() => {}, 1e9);`,
  ...Object.fromEntries(
    SENSOR_BUDGET.tailIntervals.map((ms) => [
      `poll${ms}ms`,
      `const { FileTailer } = await import(${tailUrl});
       for (const f of ['santa.log', 'osqueryd.results.log'])
         await new FileTailer({ path: ${JSON.stringify(logs)} + '/' + f, onLine() {}, intervalMs: ${ms} }).start();
       setInterval(() => {}, 1e9);`,
    ]),
  ),
  // kqueue tells us when a log changes; a slow poll catches rotation.
  watchPlus2s: `const { FileTailer } = await import(${tailUrl});
     const { watch } = await import('node:fs');
     for (const f of ['santa.log', 'osqueryd.results.log']) {
       const path = ${JSON.stringify(logs)} + '/' + f;
       const t = new FileTailer({ path, onLine() {}, intervalMs: 2000 });
       await t.start();
       watch(path, { persistent: true }, () => void t.poll());
     }`,
};
results.tailing = {};
for (const [name, code] of Object.entries(variants)) {
  const child = spawn(process.execPath, ['--input-type=module', '-e', code], { stdio: 'ignore' });
  await sleep(3000);
  results.tailing[name] = await measure([child.pid], Math.min(SECONDS, 60));
  child.kill();
}
// What the sensors package does today: FileTailer watches the log folder and
// polls every 2 s only as a fallback (PR #19), which watchPlus2s reproduces.
results.tailing.current = results.tailing.watchPlus2s;
rmSync(logs, { recursive: true, force: true });

// -------------------------------------------------------------- report

const checks = SENSOR_BUDGET.checks(results);
writeFileSync(
  join(out, `sensors-${results.platform}.json`),
  JSON.stringify({ results, checks }, null, 2),
);
const lines = [
  `### Vigil sensor check: ${results.platform}`,
  '',
  '| Measure | Value | Budget | |',
  '|---|---|---|---|',
  ...checks.map(
    (c) =>
      `| ${c.name} | ${c.value} | ${c.budget} | ${c.status === 'ok' ? 'ok' : c.status === 'over' ? 'over budget' : 'FAIL'} |`,
  ),
  '',
  '| Query | Time once | Rows | Every | Share of time |',
  '|---|---|---|---|---|',
  ...Object.entries(results.queries ?? {}).map(
    ([n, q]) =>
      `| ${n} | ${q.ms} ms | ${q.rows ?? ''} | ${q.interval ? q.interval + ' s' : ''} | ${q.dutyPct ?? ''}${q.dutyPct !== undefined ? ' %' : ''} |`,
  ),
  '',
  '| Log tailing | CPU | Wakeups/s |',
  '|---|---|---|',
  ...Object.entries(results.tailing).map(
    ([n, t]) => `| ${n} | ${t.cpuPct} % | ${t.wakeupsPerS ?? '?'} |`,
  ),
].join('\n');
console.log(lines);
if (process.env.GITHUB_STEP_SUMMARY)
  writeFileSync(process.env.GITHUB_STEP_SUMMARY, lines + '\n', { flag: 'a' });
process.exit(checks.some((c) => c.status === 'fail') ? 1 : 0);
