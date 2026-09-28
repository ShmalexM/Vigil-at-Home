/* global window */
// End-to-end check of the detection popup in the real app.
//   node e2e/popup.e2e.mjs [outDir]
// Needs a built app (`pnpm build`) and a display. Runs in CI on GitHub's
// macOS runners (.github/workflows/macos.yml); on Linux, run it under xvfb-run.
//
// Checks that a detection popup:
//   1. appears in the top-right corner of the screen,
//   2. does not take keyboard focus from the window the user is working in,
//   3. stays above other windows, on every Space, and over a full-screen window.
import { execFileSync } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { _electron as electron } from 'playwright-core';

const appDir = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const out = resolve(process.argv[2] ?? join(appDir, 'e2e-results'));
mkdirSync(out, { recursive: true });
const mac = process.platform === 'darwin';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const results = [];
function check(name, ok, detail) {
  results.push({ name, ok: !!ok, detail });
  console.log(`${ok ? 'PASS' : 'FAIL'} ${name}${detail ? `  ${JSON.stringify(detail)}` : ''}`);
}

/** Whole-screen capture, which is the only way to see stacking over full screen. */
function screenshot(name) {
  if (!mac) return;
  try {
    execFileSync('screencapture', ['-x', join(out, `${name}.png`)]);
  } catch (err) {
    console.log(`screencapture failed: ${err.message}`);
  }
}

const app = await electron.launch({
  // The electron package exports the path of its downloaded binary.
  executablePath: createRequire(join(appDir, 'package.json'))('electron'),
  args: [...(mac ? [] : ['--no-sandbox']), appDir],
  env: { ...process.env, ELECTRON_ENABLE_LOGGING: '1' },
});

async function windowByHash(hash, timeout = 15000) {
  const end = Date.now() + timeout;
  while (Date.now() < end) {
    for (const w of app.windows()) if ((await w.url()).includes(`#${hash}`)) return w;
    await sleep(200);
  }
  throw new Error(`No window for #${hash}`);
}

/** Main-process view of the main and popup windows. */
const state = () =>
  app.evaluate(({ BrowserWindow, screen }) => {
    const all = BrowserWindow.getAllWindows();
    const find = (h) => all.find((w) => w.webContents.getURL().includes(`#${h}`));
    const main = find('home') ?? find('alerts') ?? find('settings');
    const popup = find('popup');
    const focused = BrowserWindow.getFocusedWindow();
    const display = popup
      ? screen.getDisplayMatching(popup.getBounds())
      : screen.getPrimaryDisplay();
    return {
      workArea: display.workArea,
      main: main && { id: main.id, fullScreen: main.isFullScreen(), focused: main.isFocused() },
      popup: popup && {
        id: popup.id,
        visible: popup.isVisible(),
        bounds: popup.getBounds(),
        alwaysOnTop: popup.isAlwaysOnTop(),
        allSpaces: process.platform === 'darwin' ? popup.isVisibleOnAllWorkspaces() : true,
        focused: popup.isFocused(),
      },
      focusedId: focused?.id ?? null,
    };
  });

async function waitFor(pred, timeout = 10000) {
  const end = Date.now() + timeout;
  let s;
  while (Date.now() < end) {
    s = await state();
    if (pred(s)) return s;
    await sleep(200);
  }
  return s;
}

async function raiseTestAlert(page) {
  await page.evaluate(() => window.vigil.sendTestAlert());
  return waitFor((s) => s.popup?.visible);
}

function checkPopup(label, s) {
  const p = s.popup;
  check(`${label}: popup is visible`, p?.visible);
  if (!p) return;
  const wa = s.workArea;
  const right = wa.x + wa.width - (p.bounds.x + p.bounds.width);
  const top = p.bounds.y - wa.y;
  check(
    `${label}: popup sits in the top-right corner`,
    right >= 0 && right <= 40 && top >= 0 && top <= 40,
    {
      fromRight: right,
      fromTop: top,
    },
  );
  check(`${label}: popup did not take focus`, !p.focused && s.focusedId !== p.id, {
    focusedId: s.focusedId,
    popupId: p.id,
    mainId: s.main?.id,
  });
  check(`${label}: popup stays on top`, p.alwaysOnTop);
  check(`${label}: popup shows on every Space`, p.allSpaces);
}

try {
  // A fresh profile opens first-run setup; finish it so the main window shows Home.
  const first = await Promise.any([windowByHash('setup'), windowByHash('home')]);
  if ((await first.url()).includes('#setup')) {
    await first.evaluate(async () => {
      await window.vigil.setSetupMode('local');
      await window.vigil.finishSetup();
    });
  }
  const main = await windowByHash('home');
  await sleep(1500);

  // 1. Normal window: the user is working in the main window.
  await app.evaluate(({ BrowserWindow }) => BrowserWindow.getAllWindows()[0]?.focus());
  const before = await waitFor((s) => s.focusedId !== null, 5000);
  check('main window has focus before the alert', before.focusedId === before.main?.id, before);
  const s1 = await raiseTestAlert(main);
  await sleep(800);
  checkPopup('windowed', s1);
  const popup = await windowByHash('popup');
  await popup.screenshot({ path: join(out, 'popup.png') });
  screenshot('screen-windowed');

  // 2. Full screen: the main window takes over its own Space.
  await popup.evaluate(() => window.vigil.closePopup());
  await app.evaluate(({ BrowserWindow }) => {
    const w = BrowserWindow.getAllWindows().find((x) => x.webContents.getURL().includes('#home'));
    w?.setFullScreen(true);
    w?.focus();
  });
  const fs = await waitFor((s) => s.main?.fullScreen, 15000);
  check('main window went full screen', fs.main?.fullScreen);
  await sleep(1500); // let the Space animation finish
  const s2 = await raiseTestAlert(main);
  await sleep(800);
  checkPopup('full screen', s2);
  screenshot('screen-fullscreen');
} catch (err) {
  check('run completed', false, { error: String(err?.stack ?? err) });
  screenshot('screen-error');
} finally {
  await app.close().catch(() => {});
}

writeFileSync(join(out, 'results.json'), JSON.stringify(results, null, 2));
const failed = results.filter((r) => !r.ok);
console.log(`\n${results.length - failed.length}/${results.length} checks passed`);
process.exit(failed.length ? 1 : 0);
