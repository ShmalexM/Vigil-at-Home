/* global document */
// End-to-end check of Vigil's whole response path on a real Mac, with
// harmless stand-ins for the threats:
//   node e2e/flow.e2e.mjs [outDir]
//
// Needs: macOS, a built app (`pnpm build`), Vigil's helper installed and
// running as root (the bench workflow installs it the way the app does),
// osquery installed before the helper so the helper runs it, and sudo without
// a password (GitHub's Mac runners). Never run it on a Mac you care about: it
// installs a pf block on 1.1.1.1 for a few seconds and writes a launch agent.
//
// Scenarios:
//   1. Infostealer reads Chrome passwords: the event is simulated (Santa can't
//      be approved on a runner), the stand-in process is real. Vigil pauses it
//      through the helper, the popup shows, the user holds Resume app, and the
//      helper resumes it after the admin approval.
//   2. Fake password dialog: Vigil kills the stand-in; the user presses Keep blocked.
//   3. Beacon to a command server: a real connection, seen by the real osquery
//      through the helper. Vigil blocks the address with pf; the user undoes
//      it from the alert's page.
//   4. Launch agent named like Apple's: a real plist, seen by osquery. The
//      popup suggests disabling it; the user presses Turn off startup item; then undoes it.
//   5. Timing: the same pause-and-popup path repeated to get a spread.
//   6. Learning: answering "fine" three times demotes the rule from block to alert.
//   7. App closed: the helper runs the blocking rules the app handed it and
//      blocks the same beacon with no app running.
//
// The admin password dialog can't be answered on a runner, so the helper's
// approval step (which the dialog would run as root) runs through sudo
// instead; everything else is what a user's Mac does.
import { execFileSync, spawn } from 'node:child_process';
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { _electron as electron } from 'playwright-core';

const appDir = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const out = resolve(process.argv[2] ?? join(appDir, 'e2e-results'));
mkdirSync(out, { recursive: true });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const HELPER = '/Library/PrivilegedHelperTools/vigil-helper';
const HOME = homedir();
const STAND_IN_DIR = '/private/tmp/vigil-e2e';
const C2 = '1.1.1.1';
const AGENT_PLIST = join(HOME, 'Library/LaunchAgents/com.apple.vigil-e2e-lookalike.plist');
const OSQUERY_RESULTS = '/var/log/osquery/osqueryd.results.log';

if (process.platform !== 'darwin') {
  console.log('The flow check needs macOS.');
  process.exit(1);
}

const results = { checks: [], scenarios: {}, timings: [], images: [] };
function check(name, ok, detail) {
  results.checks.push({ name, ok: !!ok, ...(detail !== undefined ? { detail } : {}) });
  console.log(
    `${ok ? 'PASS' : 'FAIL'} ${name}${detail !== undefined ? `  ${JSON.stringify(detail)}` : ''}`,
  );
}

// ------------------------------------------------------------ stand-ins

mkdirSync(STAND_IN_DIR, { recursive: true });
const children = [];

/** A copy of /bin/sleep under a new name: harmless, and killable or pausable. */
function sleeper(name) {
  const path = join(STAND_IN_DIR, name);
  if (!existsSync(path)) copyFileSync('/bin/sleep', path);
  const child = spawn(path, ['900'], { stdio: 'ignore' });
  children.push(child);
  return child;
}

/** A copy of Node under a new name, running a tiny script. */
function nodeStandIn(name, script, extraArgs = []) {
  const path = join(STAND_IN_DIR, name);
  if (!existsSync(path)) copyFileSync(process.execPath, path);
  const child = spawn(path, ['-e', script, ...extraArgs], { stdio: 'ignore' });
  children.push(child);
  return child;
}

/** ps state letters: T = stopped (paused), S/R = running. Empty when gone. */
function procState(pid) {
  try {
    return execFileSync('ps', ['-o', 'stat=', '-p', String(pid)], { encoding: 'utf8' }).trim();
  } catch {
    return '';
  }
}

/** Start time the way the helper checks it (ps lstart, whole seconds). */
function startTime(pid) {
  const lstart = execFileSync('ps', ['-o', 'lstart=', '-p', String(pid)], { encoding: 'utf8' });
  return Date.parse(lstart.replace(/\s+/g, ' ').trim());
}

/**
 * Whether osquery has written any results for the named scheduled query yet.
 * Anchored to the start of the line: vigil_health rows carry every query's
 * name in their columns, and matching those let the launch agent be written
 * before the startup-item baseline run, which then swallowed it.
 */
function osqueryHasRun(query) {
  try {
    execFileSync('sudo', ['-n', 'grep', '-qE', `^\\{"name":"${query}"`, OSQUERY_RESULTS], {
      stdio: 'ignore',
    });
    return true;
  } catch {
    return false;
  }
}

/** osquery's own log lines about its watchdog, for when a real-osquery check misses. */
function osqueryWatchdogLog() {
  try {
    return execFileSync(
      'sudo',
      [
        '-n',
        'sh',
        '-c',
        // Skip JSON result lines: vigil_health rows have a denylisted column.
        'grep -hiE "watchdog|denylist|blacklist|sustainable|stopping worker" /var/log/osquery/osqueryd.* 2>/dev/null | grep -v "^{" | tail -n 15',
      ],
      { encoding: 'utf8' },
    )
      .trim()
      .split('\n')
      .filter(Boolean);
  } catch {
    return [];
  }
}

async function waitUntil(fn, timeout, step = 100) {
  const end = Date.now() + timeout;
  for (;;) {
    const v = await fn();
    if (v) return v;
    if (Date.now() > end) return v;
    await sleep(step);
  }
}

function pfBlocked(addr) {
  try {
    const table = execFileSync(
      'sudo',
      ['-n', 'pfctl', '-a', 'com.apple/vigil', '-t', 'vigil_blocked', '-T', 'show'],
      { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] },
    );
    return table.split('\n').some((l) => l.trim() === addr);
  } catch {
    return false;
  }
}

function reachable(addr) {
  try {
    execFileSync('curl', ['-s', '-o', '/dev/null', '-m', '5', `https://${addr}/`], {
      stdio: 'ignore',
    });
    return true;
  } catch {
    return false;
  }
}

/** A small JPEG of the popup, printed to the log (artifact downloads aren't always reachable). */
async function snap(page, name) {
  const png = join(out, `${name}.png`);
  try {
    await page.screenshot({ path: png });
    const jpg = join(out, `${name}.jpg`);
    execFileSync('sips', ['-s', 'format', 'jpeg', '-s', 'formatOptions', '70', png, '--out', jpg], {
      stdio: 'ignore',
    });
    const b64 = execFileSync('base64', ['-i', jpg], { encoding: 'utf8' }).replace(/\s+/g, '');
    console.log(`VIGIL_BENCH_IMG ${name} ${b64}`);
    results.images.push(name);
  } catch (err) {
    console.log(`screenshot ${name} failed: ${err.message}`);
  }
}

// ------------------------------------------------------------ the app

const userData = mkdtempSync(join(tmpdir(), 'vigil-flow-'));
const app = await electron.launch({
  executablePath: createRequire(join(appDir, 'package.json'))('electron'),
  args: [appDir],
  // VIGIL_PERF: a development build exposes its main-process objects to the
  // test and skips first-run setup; VIGIL_USER_DATA keeps a throwaway profile.
  env: { ...process.env, VIGIL_PERF: '1', VIGIL_USER_DATA: userData, ELECTRON_ENABLE_LOGGING: '1' },
});

const main = (fn, arg) => app.evaluate(fn, arg);

/** Push one simulated sensor event down the same path helper events take. */
async function inject(event) {
  return main(async (_e, ev) => {
    const at = Date.now();
    await globalThis.vigil.core.handleEvent({ ...ev, ts: at });
    return at;
  }, event);
}

async function alertFor(ruleId, since) {
  return main(
    (_e, { ruleId, since }) =>
      globalThis.vigil.core.store
        .listAlerts({})
        .find((a) => a.ruleId === ruleId && a.createdAt >= since) ?? null,
    { ruleId, since },
  );
}

async function detail(alertId) {
  return main((_e, id) => globalThis.vigil.core.alertDetail(id), alertId);
}

async function popupPage() {
  return waitUntil(async () => {
    for (const w of app.windows()) if ((await w.url()).includes('#popup')) return w;
    return null;
  }, 10000);
}

/** When the popup is on screen showing this alert, by the test's clock. */
async function popupShowing(title, timeout = 10000) {
  return waitUntil(
    async () => {
      const shown = await main(() => {
        const p = globalThis.vigil.windows.popup;
        return !!p && !p.isDestroyed() && p.isVisible();
      });
      if (!shown) return null;
      const page = await popupPage();
      if (!page) return null;
      const text = await page.evaluate(
        () => document.getElementById('popup-title')?.textContent ?? '',
      );
      return text === title ? Date.now() : null;
    },
    timeout,
    25,
  );
}

async function hold(page, name, ms = 1500) {
  const button = page.getByRole('button', { name });
  const box = await button.boundingBox();
  if (!box) throw new Error(`No ${name} button`);
  await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2);
  await page.mouse.down();
  await sleep(ms);
  await page.mouse.up();
}

try {
  const ready = await waitUntil(() => main(() => globalThis.vigil?.readyAt ?? null), 30000);
  check('app started', !!ready);

  // The helper connects on start; the app retries every 15 s.
  const connected = await waitUntil(
    () => main(() => globalThis.vigil.core.executor.state === 'connected'),
    40000,
    250,
  );
  check('app is connected to the real helper', connected);
  const status = await main(() => globalThis.vigil.core.status());
  check('actions are real, not simulated', status.dryRun === false, { dryRun: status.dryRun });

  // Answer the admin password dialog the way a user would, by running the
  // helper's approve step as root. Covers reconnects too.
  await main((_e, helper) => {
    const { execFile } = process.getBuiltinModule('node:child_process');
    const link = globalThis.vigil.core.executor;
    globalThis.__approvals = 0;
    const approver = (nonce) =>
      new Promise((res) => {
        globalThis.__approvals++;
        execFile('sudo', ['-n', helper, 'approve', nonce], (err) => res(!err));
      });
    const Client = link.client.constructor;
    link.client.approver = approver;
    link.connect = (s) => Client.connect(s, approver);
  }, HELPER);

  // Record when the popup is placed on screen, from the main process.
  await main(() => {
    const w = globalThis.vigil.windows;
    const place = w.placeAndShowPopup.bind(w);
    globalThis.__popupShownAt = [];
    w.placeAndShowPopup = () => {
      place();
      globalThis.__popupShownAt.push(Date.now());
    };
  });
  const lastPopupAt = () => main(() => globalThis.__popupShownAt.at(-1) ?? 0);

  // ---------------------------------------------------------------- 1
  {
    const s = {
      name: 'Infostealer reads Chrome passwords',
      sensor: 'simulated event, real process',
    };
    results.scenarios.stealer = s;
    const child = sleeper('Installer');
    await sleep(300);
    const pid = child.pid;
    const t0 = await inject({
      id: `e2e-stealer-${pid}`,
      source: 'santa',
      kind: 'file',
      op: 'open',
      path: `${HOME}/Library/Application Support/Google/Chrome/Default/Login Data`,
      process: {
        pid,
        ppid: process.pid,
        path: join(STAND_IN_DIR, 'Installer'),
        startTime: startTime(pid),
        args: ['Installer', '900'],
        signing: 'adhoc',
        sha256: 'e2e0'.repeat(16),
        parentPath: '/bin/zsh',
      },
    });
    const alert = await waitUntil(() => alertFor('credential-theft-untrusted', t0), 5000);
    check('stealer: alert raised', !!alert);
    const d = alert && (await detail(alert.id));
    const suspend = d?.actions.find((a) => a.action.kind === 'process.suspend');
    check('stealer: helper paused the process', suspend?.status === 'done', suspend?.result);
    check('stealer: process is really paused', procState(pid).startsWith('T'), procState(pid));
    const shownAt = alert && (await popupShowing(alert.title));
    check('stealer: popup shows the alert', !!shownAt);
    s.eventToBlockMs = suspend?.result?.at ? suspend.result.at - t0 : null;
    s.eventToPopupMs = shownAt ? (await lastPopupAt()) - t0 : null;
    s.eventToPopupPaintedMs = shownAt ? shownAt - t0 : null;
    const page = await popupPage();
    if (page) {
      await snap(page, 'popup-stealer');
      const t1 = Date.now();
      // The release button names its effect: "Resume app", or "Release both" with a network block too.
      await hold(page, /Resume app|Release both|Release all/);
      const resumed = await waitUntil(() => !procState(pid).startsWith('T'), 20000);
      s.allowToReleaseMs = Date.now() - t1;
      check('stealer: holding Resume app resumed the process', resumed, procState(pid));
      const after = await detail(alert.id);
      check('stealer: alert resolved as fine', after?.alert.decision?.verdict === 'benign');
      check(
        'stealer: resume ran through the helper',
        after?.actions.some((a) => a.action.kind === 'process.resume' && a.status === 'done'),
      );
    }
    child.kill('SIGKILL');
  }

  // ---------------------------------------------------------------- 2
  {
    const s = { name: 'Fake password dialog', sensor: 'simulated event, real process' };
    results.scenarios.fakePrompt = s;
    const args = ['display dialog "Enter your password" with hidden answer'];
    const child = nodeStandIn('osascript', 'setInterval(() => {}, 1e6)', args);
    await sleep(500);
    const pid = child.pid;
    const t0 = await inject({
      id: `e2e-prompt-${pid}`,
      source: 'santa',
      kind: 'process.exec',
      process: {
        pid,
        ppid: process.pid,
        path: join(STAND_IN_DIR, 'osascript'),
        startTime: startTime(pid),
        args: ['osascript', '-e', 'setInterval(() => {}, 1e6)', ...args],
        signing: 'adhoc',
        parentPath: join(STAND_IN_DIR, 'Installer'),
      },
    });
    const alert = await waitUntil(() => alertFor('fake-password-prompt', t0), 5000);
    check('fake prompt: alert raised', !!alert);
    const d = alert && (await detail(alert.id));
    const kill = d?.actions.find((a) => a.action.kind === 'process.kill');
    check('fake prompt: helper stopped the process', kill?.status === 'done', kill?.result);
    const gone = await waitUntil(
      () => procState(pid) === '' || procState(pid).startsWith('Z'),
      3000,
    );
    check('fake prompt: process is gone', gone, procState(pid));
    const shownAt = alert && (await popupShowing(alert.title));
    check('fake prompt: popup shows the alert', !!shownAt);
    s.eventToBlockMs = kill?.result?.at ? kill.result.at - t0 : null;
    s.eventToPopupMs = shownAt ? (await lastPopupAt()) - t0 : null;
    s.eventToPopupPaintedMs = shownAt ? shownAt - t0 : null;
    const page = await popupPage();
    if (page) {
      await snap(page, 'popup-fake-prompt');
      await page.getByRole('button', { name: 'Keep blocked' }).click();
      const decided = await waitUntil(
        async () => (await detail(alert.id))?.alert.decision?.verdict === 'malicious',
        5000,
      );
      check('fake prompt: Keep blocked recorded it as malicious', decided);
      const hidden = await waitUntil(
        () => main(() => !globalThis.vigil.windows.popup?.isVisible()),
        3000,
      );
      check('fake prompt: popup closed after the decision', hidden);
    }
  }

  // ---------------------------------------------------------------- 3
  {
    const s = { name: 'Beacon to a command server', sensor: 'real osquery' };
    results.scenarios.beacon = s;
    const osquery = (await main(() => globalThis.vigil.core.executor.query('helper.status')))
      ?.sensors?.osquery;
    s.osquery = osquery ?? null;
    check('osquery is installed and run by the helper', osquery?.installed);
    check('1.1.1.1 is reachable before the test', reachable(C2));
    // A fresh osquery on a runner can take a while before its first scheduled
    // results (the first run of every query lands at once). Start the beacon
    // only once connection snapshots are flowing, so the wait below measures
    // the 30 s snapshot interval rather than osquery's start-up.
    const g0 = Date.now();
    const flowing = await waitUntil(() => osqueryHasRun('vigil_network_connections'), 150000, 1000);
    s.osqueryReadyWaitedMs = Date.now() - g0;
    if (!flowing) console.log('osquery had written no connection results after 150 s');
    await main(
      (_e, ip) =>
        globalThis.vigil.core.detector.stores.lists.add('known_bad_ips', ip, {
          source: 'e2e',
          updatedAt: Date.now(),
        }),
      C2,
    );
    const t0 = Date.now();
    // Keep one HTTPS connection open and busy, so it is there when osquery
    // takes its next snapshot (an idle socket gets closed by the server).
    const beacon = nodeStandIn(
      'beacon',
      `const https=require('node:https');const agent=new https.Agent({keepAlive:true,maxSockets:1});` +
        `const go=()=>https.get({host:'${C2}',path:'/',agent,timeout:5000},(r)=>r.resume()).on('error',()=>{});` +
        `go();setInterval(go,2000)`,
    );
    let alert = await waitUntil(() => alertFor('known-bad-destination', t0), 90000, 500);
    if (!alert) {
      // osquery didn't report it in time; keep the rest of the path covered.
      s.sensor = 'simulated event (osquery did not report the connection in 90 s)';
      s.osqueryLog = osqueryWatchdogLog();
      const t1 = await inject({
        id: `e2e-beacon-${beacon.pid}`,
        source: 'osquery',
        kind: 'network.connection',
        direction: 'outbound',
        protocol: 'tcp',
        remoteAddress: C2,
        remotePort: 443,
        process: { pid: beacon.pid, path: join(STAND_IN_DIR, 'beacon') },
      });
      alert = await waitUntil(() => alertFor('known-bad-destination', t1), 5000);
    }
    check('beacon: seen by real osquery', s.sensor === 'real osquery');
    check('beacon: alert raised', !!alert);
    // The alert is saved before its block runs, so wait for the block's record to settle.
    const blockOf = (x) => x?.actions.find((a) => a.action.kind === 'network.block');
    const d =
      alert &&
      ((await waitUntil(async () => {
        const x = await detail(alert.id);
        return blockOf(x) && blockOf(x).status !== 'pending' ? x : null;
      }, 5000)) ??
        (await detail(alert.id)));
    const block = blockOf(d);
    const ev = d?.events[0];
    s.connectToEventMs = ev ? ev.ts - t0 : null;
    s.connectToBlockMs = block?.result?.at ? block.result.at - t0 : null;
    s.eventToBlockMs = block?.result?.at && ev ? block.result.at - ev.ts : null;
    check('beacon: helper blocked the address', block?.status === 'done', block?.result);
    check('beacon: address is in the pf table', pfBlocked(C2));
    check('beacon: address is really unreachable', !reachable(C2));
    const shownAt = alert && (await popupShowing(alert.title));
    check('beacon: popup shows the alert', !!shownAt);
    s.connectToPopupMs = shownAt ? shownAt - t0 : null;
    const popup = await popupPage();
    if (popup) await snap(popup, 'popup-beacon');
    // Undo from the alert's page in the main window, as a user would.
    await main((_e, id) => globalThis.vigil.windows.openMain(`alerts/${id}`), alert?.id);
    const win = await waitUntil(async () => {
      for (const w of app.windows()) if ((await w.url()).includes('#alerts')) return w;
      return null;
    }, 10000);
    if (win && block) {
      await win.getByRole('button', { name: 'Undo' }).first().click({ timeout: 10000 });
      const t1 = Date.now();
      const unblocked = await waitUntil(() => !pfBlocked(C2), 20000, 250);
      s.undoMs = Date.now() - t1;
      check('beacon: Undo removed the block', unblocked);
      check('beacon: address is reachable again', reachable(C2));
      await win.screenshot({ path: join(out, 'alert-beacon-undone.png') });
    }
    beacon.kill('SIGKILL');
  }

  // ---------------------------------------------------------------- 4
  {
    const s = { name: 'Launch agent named like Apple', sensor: 'real osquery' };
    const scenarioStart = Date.now();
    results.scenarios.persistence = s;
    await main(() => globalThis.vigil.windows.main?.close());
    // osquery reports every existing startup item on its first run of the
    // query, and Vigil treats that run as the baseline. Write the plist only
    // after that run, or it lands in the baseline and is never reported.
    const baselined = await waitUntil(() => osqueryHasRun('vigil_launchd'), 150000, 1000);
    s.osqueryBaselineWaitedMs = Date.now() - scenarioStart;
    if (!baselined) console.log('osquery had not run its startup-item query after 150 s');
    const t0 = Date.now();
    mkdirSync(dirname(AGENT_PLIST), { recursive: true });
    writeFileSync(
      AGENT_PLIST,
      `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>com.apple.vigil-e2e-lookalike</string>
<key>ProgramArguments</key><array><string>/usr/bin/true</string></array>
</dict></plist>
`,
    );
    // The startup-item query runs every 60 s (plus up to 10% splay); allow three runs.
    let alert = await waitUntil(() => alertFor('persistence-apple-lookalike', t0), 200000, 1000);
    if (!alert) {
      s.sensor = 'simulated event (osquery did not report the plist in 200 s)';
      s.osqueryLog = osqueryWatchdogLog();
      const t1 = await inject({
        id: `e2e-agent-${t0}`,
        source: 'osquery',
        kind: 'persistence',
        change: 'added',
        mechanism: 'launch_agent',
        path: AGENT_PLIST,
        label: 'com.apple.vigil-e2e-lookalike',
        program: '/usr/bin/true',
        programArgs: ['/usr/bin/true'],
      });
      alert = await waitUntil(() => alertFor('persistence-apple-lookalike', t1), 5000);
    }
    check('launch agent: seen by real osquery', s.sensor === 'real osquery');
    check('launch agent: alert raised', !!alert);
    const ev = alert && (await detail(alert.id))?.events[0];
    s.writeToEventMs = ev ? ev.ts - t0 : null;
    const shownAt = alert && (await popupShowing(alert.title));
    check('launch agent: popup shows the alert', !!shownAt);
    s.writeToPopupMs = shownAt ? shownAt - t0 : null;
    const page = await popupPage();
    if (page && alert) {
      await snap(page, 'popup-launch-agent');
      await page.getByRole('button', { name: 'Turn off startup item' }).click();
      const disabled = await waitUntil(() => !existsSync(AGENT_PLIST), 15000, 250);
      check('launch agent: Turn off startup item disabled the plist through the helper', disabled);
      const d = await detail(alert.id);
      const act = d?.actions.find((a) => a.action.kind === 'persistence.disable');
      check('launch agent: action recorded as done', act?.status === 'done', act?.result);
      if (act) {
        await main((_e, id) => globalThis.vigil.core.alerts.undo(id), act.id);
        const back = await waitUntil(() => existsSync(AGENT_PLIST), 20000, 250);
        check('launch agent: undo put the plist back', back);
      }
    }
    rmSync(AGENT_PLIST, { force: true });
  }

  // ---------------------------------------------------------------- 5
  {
    const runs = Number(process.env.VIGIL_FLOW_RUNS ?? 15);
    for (let i = 0; i < runs; i++) {
      await main(() => globalThis.vigil.windows.hidePopup());
      const child = sleeper(`Installer-${i}`);
      await sleep(200);
      const pid = child.pid;
      const t0 = await inject({
        id: `e2e-timing-${pid}`,
        source: 'santa',
        kind: 'file',
        op: 'open',
        path: `${HOME}/Library/Application Support/Google/Chrome/Default/Cookies`,
        process: {
          pid,
          path: join(STAND_IN_DIR, `Installer-${i}`),
          startTime: startTime(pid),
          signing: 'adhoc',
          // A new hash each time, so the rule's dedupe doesn't fold the alerts together.
          sha256: i.toString(16).padStart(64, 'e'),
        },
      });
      const alert = await waitUntil(() => alertFor('credential-theft-untrusted', t0), 5000);
      const d = alert && (await detail(alert.id));
      const act = d?.actions.find((a) => a.action.kind === 'process.suspend');
      const shownAt = alert && (await popupShowing(alert.title));
      const shown = shownAt ? await lastPopupAt() : null;
      const paused = procState(pid).startsWith('T');
      const t1 = Date.now();
      // Undo the pause rather than answering "fine": three "fine" answers in a
      // row teach Vigil to demote the rule, which scenario 6 checks on its own.
      if (act) await main((_e, id) => globalThis.vigil.core.alerts.undo(id), act.id);
      const resumed = await waitUntil(() => !procState(pid).startsWith('T'), 20000);
      results.timings.push({
        eventToBlockMs: act?.result?.at ? act.result.at - t0 : null,
        eventToPopupMs: shown ? shown - t0 : null,
        eventToPopupPaintedMs: shownAt ? shownAt - t0 : null,
        releaseMs: resumed ? Date.now() - t1 : null,
        paused,
        resumed: !!resumed,
      });
      child.kill('SIGKILL');
    }
    const ok = results.timings.filter((t) => t.paused && t.resumed && t.eventToPopupMs !== null);
    check(
      `timing: ${ok.length}/${runs} runs paused, showed the popup and resumed`,
      ok.length === runs,
    );
  }

  // ---------------------------------------------------------------- 6
  {
    // The user keeps saying "fine" to one rule: after three answers Vigil
    // should stop blocking with it (block -> alert), and never raise it itself.
    const modeOf = () =>
      main(
        () =>
          globalThis.vigil.core.rules().find((r) => r.rule.id === 'credential-theft-untrusted')
            ?.rule.mode,
      );
    const before = await modeOf();
    // Scenario 1 already answered "fine" once for this rule.
    let answers = 1;
    for (let i = 0; i < 4 && (await modeOf()) === 'block'; i++, answers++) {
      const child = sleeper(`Helper-${i}`);
      await sleep(200);
      const t0 = await inject({
        id: `e2e-learn-${child.pid}`,
        source: 'santa',
        kind: 'file',
        op: 'open',
        path: `${HOME}/Library/Application Support/Google/Chrome/Default/Web Data`,
        process: {
          pid: child.pid,
          path: join(STAND_IN_DIR, `Helper-${i}`),
          startTime: startTime(child.pid),
          signing: 'adhoc',
          sha256: i.toString(16).padStart(64, 'd'),
        },
      });
      const alert = await waitUntil(() => alertFor('credential-theft-untrusted', t0), 5000);
      if (alert)
        await main(
          (_e, id) => globalThis.vigil.core.decide(id, { verdict: 'benign', release: true }),
          alert.id,
        );
      child.kill('SIGKILL');
    }
    const after = await modeOf();
    results.scenarios.learning = {
      name: '"Fine" answers demote the rule',
      before,
      after,
      answers,
    };
    check('learning: rule was blocking before', before === 'block', before);
    check(
      'learning: three "fine" answers demoted it to alert',
      after === 'alert' && answers === 3,
      {
        after,
        answers,
      },
    );
  }
  results.approvals = await main(() => globalThis.__approvals);

  // ---------------------------------------------------------------- 7
  {
    const s = { name: 'App closed: the helper blocks on its own', sensor: 'real osquery' };
    results.scenarios.appClosed = s;
    // Scenario 3 undid its block; the address is still on the list.
    const synced = await main(async () => {
      await globalThis.vigil.syncHelperRules();
      return (await globalThis.vigil.core.executor.query('helper.status'))?.helperRules ?? null;
    });
    s.helperRules = synced;
    check('app closed: helper has the blocking rules', (synced?.rules ?? 0) > 0, synced);
    check('app closed: helper has the threat list', (synced?.lists?.known_bad_ips ?? 0) > 0);
    check('app closed: address unblocked before the test', !pfBlocked(C2));
    await app.close();
    const t0 = Date.now();
    const beacon = nodeStandIn(
      'beacon-2',
      `const https=require('node:https');const agent=new https.Agent({keepAlive:true,maxSockets:1});` +
        `const go=()=>https.get({host:'${C2}',path:'/',agent,timeout:5000},(r)=>r.resume()).on('error',()=>{});` +
        `go();setInterval(go,2000)`,
    );
    const blocked = await waitUntil(() => pfBlocked(C2), 90000, 250);
    s.connectToBlockMs = blocked ? Date.now() - t0 : null;
    check('app closed: helper blocked the address with the app closed', blocked);
    check('app closed: address is really unreachable', blocked && !reachable(C2));
    beacon.kill('SIGKILL');
    execFileSync(
      'sudo',
      ['-n', 'pfctl', '-a', 'com.apple/vigil', '-t', 'vigil_blocked', '-T', 'flush'],
      {
        stdio: 'ignore',
      },
    );
  }
} catch (err) {
  check('run completed', false, { error: String(err?.stack ?? err) });
} finally {
  for (const c of children) c.kill('SIGKILL');
  rmSync(AGENT_PLIST, { force: true });
  rmSync(STAND_IN_DIR, { recursive: true, force: true });
  await app.close().catch(() => {});
}

results.passed = results.checks.filter((c) => c.ok).length;
results.total = results.checks.length;
results.platform = `${process.platform}-${process.arch}`;
results.macos = execFileSync('sw_vers', ['-productVersion'], { encoding: 'utf8' }).trim();
writeFileSync(join(out, 'flow.json'), JSON.stringify(results, null, 2));
console.log(`VIGIL_BENCH flow ${JSON.stringify(results)}`);
console.log(`\n${results.passed}/${results.total} checks passed`);
process.exit(results.passed === results.total ? 0 : 1);
