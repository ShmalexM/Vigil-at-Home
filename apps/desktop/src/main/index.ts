import { mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { app, powerMonitor } from 'electron';
import { Store } from './db/store.js';
import { seedDemo } from './demo.js';
import { DryRunExecutor } from './executor.js';
import { registerIpc } from './ipc.js';
import { PowerPolicy } from './power.js';
import { VigilCore } from './service.js';
import { Windows } from './windows.js';

app.setName('Vigil at Home');

// The resource check (perf/measure.mjs) runs the app against a throwaway
// profile and drives it from the main process.
const perf = !app.isPackaged && !!process.env['VIGIL_PERF'];
if (perf && process.env['VIGIL_USER_DATA']) app.setPath('userData', process.env['VIGIL_USER_DATA']);

if (!app.requestSingleInstanceLock()) {
  app.quit();
} else {
  void app.whenReady().then(start);
}

function start(): void {
  // Menu-bar app: no Dock icon until the main window opens.
  app.dock?.hide();

  const dataDir = app.getPath('userData');
  mkdirSync(dataDir, { recursive: true });
  const store = new Store(new DatabaseSync(join(dataDir, 'vigil.db')));

  // Until the privileged helper is installed, blocks are simulated and the UI says so.
  const core = new VigilCore(store, new DryRunExecutor(), true);
  const windows = new Windows();

  registerIpc(core, windows);
  windows.createTray();
  windows.applyTheme(core.theme());
  // After start-up settles, so the menu-bar item appears first.
  setTimeout(() => windows.prewarmPopover(), 2000);

  const refresh = () => {
    windows.setNeedsYou(core.status().needsYou);
    windows.broadcast('changed');
  };
  core.alerts.on('changed', refresh);
  core.sensors.on('changed', refresh);
  core.alerts.on('popup', (alert) => windows.showPopup(alert.id));
  refresh();

  // Routine work slows on battery and waits while the Mac is hot or asleep;
  // blocking never does. `power.isBusy()` is what optional AI work checks.
  const power = new PowerPolicy(powerMonitor);
  core.applyPower(power.mode);
  power.on('change', (mode) => core.applyPower(mode));
  core.start();

  app.on('second-instance', () => windows.openMain());
  app.on('activate', () => windows.openMain());
  // Keep running in the menu bar when windows close.
  app.on('window-all-closed', () => {});
  app.on('before-quit', () => {
    core.stop();
    store.close();
  });

  if (!app.isPackaged && process.env['VIGIL_DEMO']) void seedDemo(core);
  if (perf) Object.assign(globalThis, { vigil: { core, windows, power, readyAt: Date.now() } });
  else if (!app.isPackaged) windows.openMain();
}
