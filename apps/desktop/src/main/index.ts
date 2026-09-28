import { mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { app, powerMonitor, safeStorage } from 'electron';
import { Store } from './db/store.js';
import { seedDemo, startDemoFeed } from './demo.js';
import { DryRunExecutor } from './executor.js';
import { registerIpc } from './ipc.js';
import { systemProbe } from './onboarding/checks.js';
import { demoProbe } from './onboarding/demo.js';
import { KeyStore } from './onboarding/keys.js';
import { OnboardingService } from './onboarding/service.js';
import { VigilCore } from './service.js';
import { Windows } from './windows.js';

app.setName('Vigil at Home');

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
  const demo = !app.isPackaged && !!process.env['VIGIL_DEMO'];
  const setup = new OnboardingService({
    store,
    keys: new KeyStore(join(dataDir, 'api-keys.json'), {
      available: () => safeStorage.isEncryptionAvailable(),
      encrypt: (s) => safeStorage.encryptString(s),
      decrypt: (b) => safeStorage.decryptString(b),
    }),
    ...(demo ? { probe: demoProbe(), supported: true } : { probe: systemProbe() }),
  });

  registerIpc(core, windows, setup);
  windows.createTray();
  windows.applyTheme(core.theme());

  const refresh = () => {
    windows.setNeedsYou(core.status().needsYou);
    windows.broadcast('changed');
  };
  core.alerts.on('changed', refresh);
  core.sensors.on('changed', refresh);
  setup.on('changed', () => windows.broadcast('changed'));
  core.alerts.on('popup', (alert) => windows.showPopup(alert.id));
  core.feed.on('events', (n) => windows.broadcast('events', n));
  refresh();

  // Routine work waits while the Mac sleeps or saves battery; blocking never does.
  powerMonitor.on('suspend', () => core.scheduler.pause());
  powerMonitor.on('resume', () => core.scheduler.resume());
  core.start();

  app.on('second-instance', () => windows.openMain());
  app.on('activate', () => windows.openMain());
  // Keep running in the menu bar when windows close.
  app.on('window-all-closed', () => {});
  app.on('before-quit', () => {
    core.stop();
    store.close();
  });

  if (demo) {
    void seedDemo(core).then(() => {
      const stop = startDemoFeed(core);
      app.on('before-quit', stop);
    });
  }
  // First run opens setup; after that Vigil starts quietly in the menu bar.
  if (!setup.finished()) windows.openMain('setup');
  else if (!app.isPackaged) windows.openMain();
}
