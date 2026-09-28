import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { app, powerMonitor, safeStorage } from 'electron';
import type { HelperInstallResult } from '../shared/ipc.js';
import { Store } from './db/store.js';
import { seedDemo, startDemoFeed } from './demo.js';
import { Detector } from './detection.js';
import { helperBundleDir, helperInstallCommand, runHelperScript } from './helper-install.js';
import { HelperLink } from './helper.js';
import { registerIpc } from './ipc.js';
import { systemProbe } from './onboarding/checks.js';
import { demoProbe } from './onboarding/demo.js';
import { KeyStore } from './onboarding/keys.js';
import { OnboardingService } from './onboarding/service.js';
import { PowerPolicy } from './power.js';
import { HEALTH_CHECK_MS, macProbe, reportHealth, type HelperSensors } from './sensor-health.js';
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
  const probe = macProbe(
    (source) => store.lastEventAt(source),
    () => helper.state,
    async () => (await helper.query<{ sensors?: HelperSensors }>('helper.status'))?.sensors ?? null,
  );

  core.helperInstallable = process.platform === 'darwin' && helperBundleDir() !== null;
  // Santa's configuration profile comes from the helper, which holds the sync
  // server's certificate. Setup offers it once it has been written here.
  const santaProfilePath = join(dataDir, 'Vigil Santa.mobileconfig');
  const saveSantaProfile = async () => {
    try {
      const r = await helper.query<{ mobileconfig: string }>('santa.profile');
      if (r?.mobileconfig) writeFileSync(santaProfilePath, r.mobileconfig);
    } catch {
      // The next connection tries again.
    }
  };
  // Installing or removing the helper shows macOS's own password dialog.
  const afterHelperScript = async (r: HelperInstallResult) => {
    await helper.reconnect();
    await reportHealth(core.sensors, probe);
    return r;
  };

  const demo = !app.isPackaged && !!process.env['VIGIL_DEMO'];
  const setup = new OnboardingService({
    store,
    keys: new KeyStore(join(dataDir, 'api-keys.json'), {
      available: () => safeStorage.isEncryptionAvailable(),
      encrypt: (s) => safeStorage.encryptString(s),
      decrypt: (b) => safeStorage.decryptString(b),
    }),
    ...(demo ? { probe: demoProbe(), supported: true } : { probe: systemProbe() }),
    // The wizard's helper and Santa steps, once this build can install them.
    plan: () => {
      const command = helperInstallCommand();
      return {
        ...(command ? { helperInstallCommand: command } : {}),
        ...(existsSync(santaProfilePath) ? { santaProfilePath } : {}),
      };
    },
  });

  registerIpc(core, windows, setup, {
    install: async () => afterHelperScript(await runHelperScript('install')),
    uninstall: async () => afterHelperScript(await runHelperScript('uninstall')),
  });
  windows.createTray();
  windows.applyTheme(core.theme(), core.appearance());
  // After start-up settles, so the menu-bar item appears first.
  setTimeout(() => windows.prewarmPopover(), 2000);

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

  // Routine work slows on battery and waits while the Mac is hot or asleep;
  // blocking never does. `power.isBusy()` is what optional AI work checks.
  const power = new PowerPolicy(powerMonitor);
  core.applyPower(power.mode);
  power.on('change', (mode) => core.applyPower(mode));
  core.start();

  // Sensor events arrive through the helper, which reads Santa's and osquery's logs as root.
  helper.on('event', (e) => void core.handleEvent(e));
  const checkHealth = () => reportHealth(core.sensors, probe);
  helper.on('state', (state) => {
    void checkHealth();
    if (state === 'connected') void saveSantaProfile();
  });
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

  if (demo) {
    void seedDemo(core).then(() => {
      const stop = startDemoFeed(core);
      app.on('before-quit', stop);
    });
  }
  if (perf) Object.assign(globalThis, { vigil: { core, windows, power, readyAt: Date.now() } });
  // First run opens setup; after that Vigil starts quietly in the menu bar.
  else if (!setup.finished()) windows.openMain('setup');
  else if (!app.isPackaged) windows.openMain();
}
