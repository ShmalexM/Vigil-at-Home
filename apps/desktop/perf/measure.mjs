// Resource check: runs the real app and measures what it costs the Mac.
//   node perf/measure.mjs [outDir]
// Needs a built app (`pnpm build`). Runs in the macOS workflow's `perf` job on
// an Intel and an Apple-silicon runner; on Linux it runs under xvfb-run with
// fewer numbers (no wakeups or energy).
//
// Phases, each measured over the whole app (main process and its helpers):
//   startup   launch until the menu-bar item exists
//   idle      nothing open, nothing happening
//   popover   opening the menu-bar popover, cold then warm
//   window    the main window open and idle
//   closed    back to menu-bar only, after windows close
//   load      a steady stream of sensor events being stored
//
// The budget lives in docs/performance.md; the numbers it checks are in
// perf/budget.mjs. Hosted runners are shared VMs, so only a clear overrun
// fails the job (see `hard` there).
import { execFile, execFileSync } from 'node:child_process';
import { promisify } from 'node:util';
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { _electron as electron } from 'playwright-core';
import { BUDGET } from './budget.mjs';

const appDir = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const out = resolve(process.argv[2] ?? join(appDir, 'perf-results'));
mkdirSync(out, { recursive: true });
const mac = process.platform === 'darwin';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const env = (k, d) => Number(process.env[k] ?? d);
const IDLE_S = env('VIGIL_PERF_IDLE_S', 60);
const LOAD_S = env('VIGIL_PERF_LOAD_S', 60);
const LOAD_RATE = env('VIGIL_PERF_RATE', BUDGET.load.eventsPerSecond);

// ------------------------------------------------------------ process stats

/** CPU seconds from ps `time` ("1:02.03" or "1:02:03" or "1-02:03:04"). */
function cpuSeconds(t) {
  const [days, rest] = t.includes('-') ? t.split('-') : ['0', t];
  const parts = rest.split(':').map(Number);
  while (parts.length < 3) parts.unshift(0);
  const [h, m, s] = parts;
  return Number(days) * 86400 + h * 3600 + m * 60 + s;
}

/**
 * The app's process tree: pid → { memMb, cpuS, writtenMb, name }.
 * memMb is what Activity Monitor calls Memory (the physical footprint) on
 * macOS and the proportional set size on Linux, so pages that Electron's
 * processes share are not counted once per process.
 */
function tree(rootPid) {
  const rows = execFileSync('ps', ['-A', '-o', 'pid=,ppid=,rss=,time=,comm='], { encoding: 'utf8' })
    .trim()
    .split('\n')
    .map((l) => l.trim().split(/\s+/))
    .map(([pid, ppid, rss, time, ...comm]) => ({
      pid: Number(pid),
      ppid: Number(ppid),
      memMb: Number(rss) / 1024,
      cpuS: cpuSeconds(time),
      writtenMb: 0,
      name: comm.join(' ').split('/').pop(),
    }));
  const keep = new Set([rootPid]);
  for (let grew = true; grew;) {
    grew = false;
    for (const r of rows)
      if (!keep.has(r.pid) && keep.has(r.ppid)) {
        keep.add(r.pid);
        grew = true;
      }
  }
  const procs = new Map(rows.filter((r) => keep.has(r.pid)).map((r) => [r.pid, r]));
  if (mac) {
    const footprint = macFootprints();
    for (const r of procs.values()) r.memMb = footprint.get(r.pid) ?? r.memMb;
  } else {
    for (const r of procs.values()) Object.assign(r, linuxProc(r.pid) ?? {});
  }
  return procs;
}

/** pid → MB from top's MEM column (physical footprint). */
function macFootprints() {
  const out = new Map();
  const text = execFileSync('top', ['-l', '1', '-stats', 'pid,mem'], { encoding: 'utf8' });
  const unit = { B: 1 / 1048576, K: 1 / 1024, M: 1, G: 1024 };
  for (const line of text.split('\n')) {
    const m = /^\s*(\d+)\s+([\d.]+)([BKMG])/.exec(line);
    if (m) out.set(Number(m[1]), Number(m[2]) * unit[m[3]]);
  }
  return out;
}

/** CPU seconds (ps only has whole seconds on Linux), PSS and bytes written. */
function linuxProc(pid) {
  try {
    const stat = readFileSync(`/proc/${pid}/stat`, 'utf8');
    const f = stat.slice(stat.lastIndexOf(')') + 2).split(' ');
    const cpuS = (Number(f[11]) + Number(f[12])) / 100; // utime + stime, in USER_HZ
    const pss = /^Pss:\s+(\d+)/m.exec(readFileSync(`/proc/${pid}/smaps_rollup`, 'utf8'));
    const io = /^write_bytes:\s+(\d+)/m.exec(readFileSync(`/proc/${pid}/io`, 'utf8'));
    return {
      cpuS,
      ...(pss ? { memMb: Number(pss[1]) / 1024 } : {}),
      ...(io ? { writtenMb: Number(io[1]) / 1048576 } : {}),
    };
  } catch {
    return null;
  }
}

const sum = (m, k) => [...m.values()].reduce((a, r) => a + r[k], 0);

/**
 * Wakeups and energy per process from powermetrics (macOS, needs sudo without
 * a password, which GitHub's runners have). Returns null when unavailable.
 */
async function powermetrics(pids, seconds) {
  if (!mac) return null;
  try {
    execFileSync('sudo', ['-n', 'true'], { stdio: 'ignore' });
  } catch {
    return null;
  }
  try {
    const { stdout } = await promisify(execFile)(
      'sudo',
      [
        '-n',
        'powermetrics',
        '-f',
        'plist',
        '-n',
        '1',
        '-i',
        String(seconds * 1000),
        '--samplers',
        'tasks',
        '--show-process-energy',
        '--show-process-io',
      ],
      { encoding: 'utf8', maxBuffer: 64 << 20 },
    );
    // JSON has no date or data type, so plutil refuses them; keep them as strings.
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
    const pick = (t, re) =>
      Object.entries(t).reduce((a, [k, v]) => (re.test(k) && typeof v === 'number' ? a + v : a), 0);
    return {
      wakeupsPerS: tasks.reduce((a, t) => a + pick(t, /^(intr|idle)_wakeups_per_s$/), 0),
      energyImpact: tasks.reduce((a, t) => a + pick(t, /^energy_impact$/), 0),
      writtenMbPerS:
        tasks.reduce((a, t) => a + pick(t, /^diskio_byteswritten_per_s$/), 0) / 1048576,
      tasks: tasks.map((t) => ({ pid: t.pid, name: t.name, ...t })),
    };
  } catch (err) {
    console.log(`powermetrics failed: ${err.message.split('\n')[0]}`);
    return null;
  }
}

/** Measure the app over `seconds`: CPU as % of one core, RSS at the end, wakeups. */
async function measure(rootPid, seconds, during) {
  const before = tree(rootPid);
  const t0 = Date.now();
  const work = during?.();
  const pm = await powermetrics(new Set(before.keys()), seconds);
  if (!pm) await sleep(seconds * 1000);
  await work;
  const after = tree(rootPid);
  const wall = (Date.now() - t0) / 1000;
  let cpu = 0;
  let written = 0;
  for (const [pid, r] of after) {
    cpu += r.cpuS - (before.get(pid)?.cpuS ?? 0);
    written += r.writtenMb - (before.get(pid)?.writtenMb ?? 0);
  }
  if (pm) written = pm.writtenMbPerS * wall;
  return {
    seconds: Math.round(wall),
    cpuPct: round((cpu / wall) * 100, 2),
    memMb: round(sum(after, 'memMb')),
    writtenMb: round(written, 2),
    processes: [...after.values()].map((r) => ({ name: r.name, memMb: round(r.memMb) })),
    ...(pm
      ? { wakeupsPerS: round(pm.wakeupsPerS, 1), energyImpact: round(pm.energyImpact, 2) }
      : {}),
  };
}

const round = (n, d = 0) => Math.round(n * 10 ** d) / 10 ** d;

/** Size of the database and its WAL. */
function dbMb(dir) {
  let bytes = 0;
  for (const f of readdirSync(dir))
    if (f.startsWith('vigil.db')) bytes += statSync(join(dir, f)).size;
  return bytes / 1048576;
}

// ------------------------------------------------------------------- run it

const userData = mkdtempSync(join(tmpdir(), 'vigil-perf-'));
const t0 = Date.now();
const app = await electron.launch({
  executablePath: createRequire(join(appDir, 'package.json'))('electron'),
  args: [...(mac ? [] : ['--no-sandbox']), appDir],
  env: { ...process.env, VIGIL_PERF: '1', VIGIL_USER_DATA: userData },
});
const pid = app.process().pid;

const results = { platform: `${process.platform}-${process.arch}`, host: hostInfo() };
try {
  for (;;) {
    const ready = await app.evaluate(() => globalThis.vigil?.readyAt ?? null);
    if (ready) {
      results.startupMs = ready - t0;
      break;
    }
    if (Date.now() - t0 > 30000) throw new Error('App did not start in 30 s');
    await sleep(50);
  }
  // Let first-run work (migrations, the first scheduled jobs) settle.
  await sleep(5000);

  results.idle = await measure(pid, IDLE_S);

  // Popover: cold (creates the renderer) and warm (already loaded, hidden).
  const openPopover = () =>
    app.evaluate(async () => {
      const start = Date.now();
      const { windows } = globalThis.vigil;
      windows.togglePopover();
      // Loaded and painted: the renderer answers once React has rendered.
      const wc = windows.popover.webContents;
      while (wc.isLoading()) await new Promise((r) => setTimeout(r, 5));
      await wc.executeJavaScript('new Promise((r) => requestAnimationFrame(() => r(0)))');
      return Date.now() - start;
    });
  const hidePopover = () => app.evaluate(() => globalThis.vigil.windows.popover?.hide());
  const cold = await openPopover();
  await sleep(1500);
  await hidePopover();
  await sleep(500);
  const warm = await openPopover();
  results.popover = { coldMs: cold, warmMs: warm, ...(await measure(pid, 10)) };
  await hidePopover();

  // Main window open and idle.
  await app.evaluate(() => globalThis.vigil.windows.openMain());
  await sleep(3000);
  results.window = await measure(pid, 20);
  await app.evaluate(() => globalThis.vigil.windows.main?.close());

  // Back to menu-bar only, after hidden windows are released (the app does
  // this on a timer; here it is triggered so the check doesn't wait minutes).
  await app.evaluate(() => globalThis.vigil.windows.releaseHidden?.());
  await sleep(BUDGET.closed.settleSeconds * 1000);
  results.closed = await measure(pid, 20);

  // Steady event stream, as while compiling or running tests: every event
  // goes into the event history.
  const dbBefore = dbMb(userData);
  results.load = {
    eventsPerSecond: LOAD_RATE,
    ...(await measure(pid, LOAD_S, () =>
      app.evaluate(
        async (_e, { rate, seconds }) => {
          const { core } = globalThis.vigil;
          // Before the batched event log existed, every event was its own commit.
          const add = core.events ? (e) => core.events.add(e) : (e) => core.store.insertEvent(e);
          const end = Date.now() + seconds * 1000;
          let n = 0;
          while (Date.now() < end) {
            // Sensors deliver in small bursts; 10 ticks a second.
            for (let i = 0; i < rate / 10; i++) add(fakeExec(n++));
            await new Promise((r) => setTimeout(r, 100));
          }
          await core.events?.flush?.();
          function fakeExec(i) {
            const tool = ['clang', 'ld', 'git', 'node', 'swift-frontend', 'python3'][i % 6];
            return {
              id: `perf-${Date.now().toString(16)}-${i}`,
              ts: Date.now(),
              source: 'santa',
              kind: 'process.exec',
              process: {
                pid: 10000 + (i % 50000),
                ppid: 9000 + (i % 7),
                path: `/usr/bin/${tool}`,
                args: [
                  tool,
                  '-c',
                  `/Users/me/code/project/src/file${i % 900}.c`,
                  '-o',
                  `/tmp/obj${i}.o`,
                ],
                cwd: '/Users/me/code/project',
                uid: 501,
                sha256: (i % 64).toString(16).padStart(64, 'a'),
                signingId: `com.apple.${tool}`,
                teamId: '',
                signing: 'apple',
                parentPath: '/bin/zsh',
              },
              // Sensors attach their original record, as Santa's parser does.
              raw: {
                action: 'EXEC',
                decision: 'ALLOW',
                reason: 'BINARY',
                sha256: 'a'.repeat(64),
                cert_sha256: 'b'.repeat(64),
                cert_cn: 'Software Signing',
                pid: String(10000 + i),
                ppid: '9000',
                uid: '501',
                user: 'me',
                gid: '20',
                group: 'staff',
                mode: 'M',
                path: `/usr/bin/${tool}`,
                args: `${tool} -c file${i % 900}.c`,
              },
            };
          }
        },
        { rate: LOAD_RATE, seconds: LOAD_S },
      ),
    )),
  };
  // Stored size once the WAL is folded back into the database file.
  await app.evaluate(() => globalThis.vigil.core.store.db.exec('PRAGMA wal_checkpoint(TRUNCATE)'));
  const events = LOAD_RATE * LOAD_S;
  const perK = (mb) => round((mb * 1024 * 1000) / events, 1);
  results.load.storedKbPerThousandEvents = perK(dbMb(userData) - dbBefore);
  results.load.writtenKbPerThousandEvents = perK(results.load.writtenMb);
} finally {
  await app.close().catch(() => {});
  rmSync(userData, { recursive: true, force: true });
}

// ----------------------------------------------------------------- report

const checks = BUDGET.checks(results);
writeFileSync(
  join(out, `perf-${results.platform}.json`),
  JSON.stringify({ results, checks }, null, 2),
);
const md = report(results, checks);
console.log(md);
if (process.env.GITHUB_STEP_SUMMARY)
  writeFileSync(process.env.GITHUB_STEP_SUMMARY, md + '\n', { flag: 'a' });
const hardFails = checks.filter((c) => c.status === 'fail');
process.exit(hardFails.length ? 1 : 0);

function hostInfo() {
  if (!mac) return process.arch;
  const q = (k) => {
    try {
      return execFileSync('sysctl', ['-n', k], { encoding: 'utf8' }).trim();
    } catch {
      return '?';
    }
  };
  return `${q('machdep.cpu.brand_string')}, ${q('hw.ncpu')} cores, ${round(Number(q('hw.memsize')) / 2 ** 30)} GB`;
}

function report(r, checks) {
  const icon = { ok: 'ok', over: 'over budget', fail: 'FAIL' };
  const rows = checks.map((c) => `| ${c.name} | ${c.value} | ${c.budget} | ${icon[c.status]} |`);
  return [
    `### Vigil resource check: ${r.platform}`,
    '',
    `${r.host}`,
    '',
    '| Measure | Value | Budget | |',
    '|---|---|---|---|',
    ...rows,
  ].join('\n');
}
