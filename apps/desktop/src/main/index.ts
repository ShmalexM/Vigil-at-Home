import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { app, dialog, Notification, powerMonitor, safeStorage, shell } from 'electron';
import { listDigest } from '@vigil/detection/fastpath';
import { HelperCallError } from '@vigil/helper/client';
import { z } from 'zod';
import type { HelperInstallResult } from '../shared/ipc.js';
import { AiBridge } from './ai.js';
import { Store } from './db/store.js';
import { seedDemo, startDemoFeed } from './demo.js';
import { seedUsageDemo } from './usage-demo.js';
import {
  Detector,
  type HelperSync,
  type HelperSyncOptions,
  type HelperSyncOutcome,
} from './detection.js';
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
import { UpdateChecker } from './updates.js';
import { Windows } from './windows.js';

app.setName('Vigil at Home');

// Development builds keep their own data, so demo data and test setups never
// end up in the installed app's database.
if (!app.isPackaged) app.setPath('userData', join(app.getPath('appData'), 'Vigil at Home Dev'));

// The resource check (perf/measure.mjs) runs the app against a throwaway
// profile and drives it from the main process.
const perf = !app.isPackaged && !!process.env['VIGIL_PERF'];
if (perf && process.env['VIGIL_USER_DATA']) app.setPath('userData', process.env['VIGIL_USER_DATA']);

if (!app.requestSingleInstanceLock()) {
  app.quit();
} else {
  void app.whenReady().then(start).catch(failedToStart);
}

/** A menu-bar app that fails to start has no window or icon, so say so and quit. */
function failedToStart(err: unknown): void {
  console.error('Vigil could not start:', err);
  dialog.showErrorBox(
    'Vigil at Home could not start',
    `${err instanceof Error ? err.message : String(err)}\n\nPlease reinstall Vigil at Home or report this error.`,
  );
  app.exit(1);
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

  // A development build installs the helper that `pnpm build:helper` made.
  const helperDir = () =>
    helperBundleDir(
      process.resourcesPath,
      app.isPackaged ? undefined : join(app.getAppPath(), 'build', 'helper', `dev-${process.arch}`),
    );
  core.helperInstallable = process.platform === 'darwin' && helperDir() !== null;
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
  const keys = new KeyStore(join(dataDir, 'api-keys.json'), {
    available: () => safeStorage.isEncryptionAvailable(),
    encrypt: (s) => safeStorage.encryptString(s),
    decrypt: (b) => safeStorage.decryptString(b),
  });
  const setup: OnboardingService = new OnboardingService({
    store,
    keys,
    ...(demo
      ? { probe: demoProbe(), supported: true }
      : {
          probe: systemProbe(undefined, async () => {
            if (await helper.ping()) return true;
            // Just installed: connect now rather than on the next retry.
            await helper.tryConnect();
            return helper.ping();
          }),
        }),
    // Setup's Codex step can use the user's own Codex sign-in (set up below).
    ...(demo
      ? {}
      : { codex: { status: () => ai.codexStatus(), share: () => ai.shareCodexSignIn() } }),
    // The wizard's helper and Santa steps, once this build can install them.
    plan: () => {
      const command = helperInstallCommand(helperDir());
      return {
        ...(command ? { helperInstallCommand: command } : {}),
        ...(existsSync(santaProfilePath) ? { santaProfilePath } : {}),
      };
    },
  });

  // Routine work slows on battery and waits while the Mac is hot or asleep;
  // blocking never does. `power.isBusy()` is what optional AI work checks.
  const power = new PowerPolicy(powerMonitor);

  // The AI explains alerts after their response has run. It never blocks,
  // releases or allows anything.
  const ai: AiBridge = new AiBridge({
    store,
    usage: core.usage,
    keys,
    mode: () => setup.mode(),
    dataDir,
    isBusy: () => power.isBusy(),
    openExternal: (url) => shell.openExternal(url),
  });
  if (!demo) core.usage.setLimitsSource(() => ai.limits());
  ai.on('changed', () => windows.broadcast('changed'));
  ai.explainAlertsFrom(core);
  ai.labelEventsFrom(core);
  ai.reviewRulesFrom(core);

  // Tells the user when a newer release is out. Unsigned builds can't update
  // themselves, so it offers the DMG; nothing installs without the user.
  const updates = new UpdateChecker({
    current: app.getVersion(),
    arch: process.arch,
    load: () => store.getSetting('updates', z.unknown(), {}),
    save: (s) => store.setSetting('updates', s),
    openExternal: (url) => shell.openExternal(url),
    onFound: (version) => {
      if (!Notification.isSupported()) return;
      const n = new Notification({
        title: `Vigil at Home ${version} is available`,
        body: 'Open Vigil to download it.',
      });
      n.on('click', () => windows.openMain());
      n.show();
    },
  });
  updates.on('changed', () => windows.broadcast('changed'));
  if (app.isPackaged) updates.start();
  app.on('before-quit', () => updates.stop());

  registerIpc(core, windows, setup, ai, updates, {
    install: async () => afterHelperScript(await runHelperScript('install', helperDir())),
    uninstall: async () => afterHelperScript(await runHelperScript('uninstall', helperDir())),
  });
  windows.createTray();
  windows.applyTheme(core.theme(), core.appearance());
  // After start-up settles, so the menu-bar item appears first.
  setTimeout(() => windows.prewarmPopover(), 2000);

  const refresh = () => {
    windows.setNeedsYou(core.status().badge);
    windows.broadcast('changed');
  };
  core.alerts.on('changed', refresh);
  core.sensors.on('changed', refresh);
  setup.on('changed', () => windows.broadcast('changed'));
  core.alerts.on('popup', (alert) => windows.showPopup(alert.id));
  core.feed.on('events', (n) => windows.broadcast('events', n));
  refresh();

  core.applyPower(power.mode);
  power.on('change', (mode) => core.applyPower(mode));
  core.start();

  // Sensor events arrive through the helper, which reads Santa's and osquery's logs as root.
  helper.on('event', (e) => void core.handleEvent(e));
  const checkHealth = () => reportHealth(core.sensors, probe);
  // Re-sent on every connection and whenever the rules, exceptions or lists change.
  let helperRulesSent: string | undefined;
  // A set the user declined to approve (a loosening needs their password). Not
  // asked again until the rules change, so the health timer never re-prompts.
  let helperRulesDeclined: string | undefined;
  // The helper runs the blocking rules it can on its own, so blocks happen
  // even while the app is closed, and hands Santa the pre-launch ones.
  let helperRulesSync: Promise<unknown> = Promise.resolve();
  const syncHelperRules: HelperSync = (opts = {}) => {
    const next = helperRulesSync.then(() => sendHelperRules(opts));
    helperRulesSync = next;
    return next;
  };
  const sendHelperRules = async (opts: HelperSyncOptions): Promise<HelperSyncOutcome> => {
    if (!core.detector) return 'unavailable';
    const set = core.detector.helperRules();
    const lists = Object.entries(set.lists).map(([l, entries]) => [l, listDigest(entries)]);
    const key = JSON.stringify({ ...set, lists });
    if (key === helperRulesSent) return 'applied';
    if (key === helperRulesDeclined && !opts.byUser) return 'declined';
    try {
      const how = opts.hold ? { hold: true, ...(opts.onHeld ? { onHeld: opts.onHeld } : {}) } : {};
      if (!(await helper.syncRules(set, how))) return 'unavailable';
      helperRulesSent = key;
      return 'applied';
    } catch (err) {
      if (err instanceof HelperCallError && err.code === 'refused') {
        helperRulesDeclined = key;
        return 'declined';
      }
      console.warn('[helper rules] could not update the helper:', err);
      return 'unavailable';
    }
  };
  if (core.detector) core.detector.syncHelper = syncHelperRules;
  helper.on('state', (state) => {
    void checkHealth();
    if (state === 'connected') {
      void saveSantaProfile();
      helperRulesSent = undefined;
      helperRulesDeclined = undefined;
      void syncHelperRules();
    }
  });
  if (process.platform === 'darwin') {
    helper.start();
    core.scheduler.every(
      'sensor-health',
      HEALTH_CHECK_MS,
      async () => {
        await helper.ping();
        await checkHealth();
        await syncHelperRules();
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
    seedUsageDemo(core.usage);
    void seedDemo(core).then(() => {
      const stop = startDemoFeed(core);
      app.on('before-quit', stop);
    });
  }
  if (perf)
    Object.assign(globalThis, {
      vigil: { core, windows, power, syncHelperRules, readyAt: Date.now() },
    });
  // First run opens setup; after that Vigil starts quietly in the menu bar.
  else if (!setup.finished()) windows.openMain('setup');
  else if (!app.isPackaged) windows.openMain();
}
