import { mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { app, powerMonitor } from 'electron';
import { Store } from './db/store.js';
import { seedDemo, startDemoFeed } from './demo.js';
import { Detector } from './detection.js';
import { HelperLink } from './helper.js';
import { registerIpc } from './ipc.js';
import { HEALTH_CHECK_MS, macProbe, reportHealth, type HelperSensors } from './sensor-health.js';
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
  const db = new DatabaseSync(join(dataDir, 'vigil.db'));
  const store = new Store(db);

  // Actions go to the privileged helper. Until it is installed and answering,
  // they are simulated and the UI says so.
  const helper = new HelperLink();
  const core = new VigilCore(store, helper, true);
  core.detector = new Detector(db, store, core.alerts, (e, o) => core.ingest(e, o), {
    installedAt: core.installedAt(),
    // The .app bundle when packaged; the Electron binary in development.
    selfPaths: [app.isPackaged ? join(process.execPath, '../../..') : process.execPath],
  });
  const windows = new Windows();

  registerIpc(core, windows);
  windows.createTray();
  windows.applyTheme(core.theme());

  const refresh = () => {
    windows.setNeedsYou(core.status().needsYou);
    windows.broadcast('changed');
  };
  core.alerts.on('changed', refresh);
  core.sensors.on('changed', refresh);
  core.alerts.on('popup', (alert) => windows.showPopup(alert.id));
  core.feed.on('events', (n) => windows.broadcast('events', n));
  refresh();

  // Routine work waits while the Mac sleeps or saves battery; blocking never does.
  powerMonitor.on('suspend', () => core.scheduler.pause());
  powerMonitor.on('resume', () => core.scheduler.resume());
  core.start();

  // Sensor events arrive through the helper, which reads Santa's and osquery's logs as root.
  helper.on('event', (e) => void core.handleEvent(e));
  const probe = macProbe(
    (source) => store.lastEventAt(source),
    () => helper.state,
    async () => (await helper.query<{ sensors?: HelperSensors }>('helper.status'))?.sensors ?? null,
  );
  const checkHealth = () => reportHealth(core.sensors, probe);
  helper.on('state', () => void checkHealth());
  if (process.platform === 'darwin') {
    helper.start();
    core.scheduler.every(
      'sensor-health',
      HEALTH_CHECK_MS,
      async () => {
        await helper.ping();
        await checkHealth();
      },
      true,
    );
  }

  app.on('second-instance', () => windows.openMain());
  app.on('activate', () => windows.openMain());
  // Keep running in the menu bar when windows close.
  app.on('window-all-closed', () => {});
  app.on('before-quit', () => {
    helper.stop();
    core.stop();
    store.close();
  });

  if (!app.isPackaged && process.env['VIGIL_DEMO']) {
    void seedDemo(core).then(() => {
      const stop = startDemoFeed(core);
      app.on('before-quit', stop);
    });
  }
  if (!app.isPackaged) windows.openMain();
}
