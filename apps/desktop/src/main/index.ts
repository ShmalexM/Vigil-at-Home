import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { app, dialog, Notification, powerMonitor, safeStorage, shell } from 'electron';
import { z } from 'zod';
import type { HelperInstallResult } from '../shared/ipc.js';
import { AgentService } from './agents/service.js';
import { AiBridge } from './ai.js';
import { Store } from './db/store.js';
import { demoInstalled, seedAgentsDemo, seedDemo, startDemoFeed } from './demo.js';
import { seedUsageDemo } from './usage-demo.js';
import { Detector } from './detection.js';
import {
  helperBundleDir,
  helperInstallCommand,
  helperMatch,
  runHelperScript,
  unlessDemo,
} from './helper-install.js';
import { HelperLink } from './helper.js';
import { HelperSyncer } from './helper-sync.js';
import { registerIpc } from './ipc.js';
import { systemProbe } from './onboarding/checks.js';
import { demoProbe } from './onboarding/demo.js';
import { FeedKeyStore, KeyStore, type Cipher } from './onboarding/keys.js';
import { linuxDistro, type LinuxDistro } from './onboarding/plan.js';
import { OnboardingService } from './onboarding/service.js';
import { Connectors, ConnectorRecord } from './pack/connectors.js';
import { Notebook } from './pack/notebook.js';
import { PackMemory } from './pack/memory.js';
import { PackService } from './pack/service.js';
import { seedPackDemo } from './pack/demo.js';
import { PowerPolicy } from './power.js';
import { hashSelf, selfPaths } from './self-path.js';
import {
  AwakeClock,
  HEALTH_CHECK_MS,
  macProbe,
  reportHealth,
  type HelperSensors,
} from './sensor-health.js';
import { VigilCore } from './service.js';
import { UpdateChecker } from './updates.js';
import { wantsX11 } from './display.js';
import { restrictWebContents, Windows } from './windows.js';

app.setName('Vigil at Home');

// Development builds keep their own data, so demo data and test setups never
// end up in the installed app's database.
if (!app.isPackaged) app.setPath('userData', join(app.getPath('appData'), 'Vigil at Home Dev'));

/** Where the root helper runs: macOS (launchd) and Linux (systemd). */
const HELPER_PLATFORMS = new Set<NodeJS.Platform>(['darwin', 'linux']);

/** Linux: which package manager setup's install commands use. */
function thisDistro(): LinuxDistro | undefined {
  if (process.platform !== 'linux') return undefined;
  try {
    return linuxDistro(readFileSync('/etc/os-release', 'utf8'));
  } catch {
    return 'other';
  }
}
const distro = thisDistro();

// The resource check (perf/measure.mjs) runs the app against a throwaway
// profile and drives it from the main process.
const perf = !app.isPackaged && !!process.env['VIGIL_PERF'];
if (perf && process.env['VIGIL_USER_DATA']) app.setPath('userData', process.env['VIGIL_USER_DATA']);

if (wantsX11(process.platform, process.argv, process.env))
  app.commandLine.appendSwitch('ozone-platform', 'x11');

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
  restrictWebContents();

  const dataDir = app.getPath('userData');
  mkdirSync(dataDir, { recursive: true });
  const db = new DatabaseSync(join(dataDir, 'vigil.db'));
  const store = new Store(db);

  // Actions go to the privileged helper. Until it is installed and answering,
  // they are simulated and the UI says so.
  const helper = new HelperLink();
  const core = new VigilCore(store, helper, true);
  const demo = !app.isPackaged && !!process.env['VIGIL_DEMO'];
  // The .app bundle or install folder when packaged; the Electron binary in development.
  const self = selfPaths(process.execPath, process.platform, app.isPackaged, process.env);
  // API keys, feed keys and connector secrets: encrypted with a key held in the Keychain.
  const cipher: Cipher = {
    available: () => safeStorage.isEncryptionAvailable(),
    encrypt: (s) => safeStorage.encryptString(s),
    decrypt: (b) => safeStorage.decryptString(b),
  };
  // Accepted limit: on Linux (GNOME keyring and similar) safeStorage's key is open to any
  // app running as the same user, so this does not keep the abuse.ch key from them. That
  // is the platform's limit, and the key is for a free feed, so it is stored the same way.
  const feedKeys = new FeedKeyStore(join(dataDir, 'feed-keys.json'), cipher);
  const detector = new Detector(db, store, core.alerts, (e, o) => core.ingest(e, o), {
    installedAt: core.installedAt(),
    selfPaths: self.app,
    helperSelf: self.helper,
    // URLhaus and MalwareBazaar send the user's abuse.ch key once they add one.
    feeds: { keys: (name) => feedKeys.get(name) },
    // What Vigil itself starts (its AI helpers) is tagged vigil-self, never a watched agent.
    selfPid: process.pid,
    // The tracker reports to the agent service, created just below.
    agentHooks: {
      onSession: (s) => agents.onSession(s),
      onMiss: (ppid) => agents.onMiss(ppid),
      onCandidate: (c) => agents.onCandidate(c),
    },
  });
  core.detector = detector;
  const devHelperDir = app.isPackaged
    ? undefined
    : join(app.getAppPath(), 'build', 'helper', `dev-${process.arch}`);
  // Watched AI agents and the pre-flight socket their hooks ask. Rules answer;
  // the answer never goes through the AI or the scheduler.
  const agents: AgentService = new AgentService({
    detector: core.detector,
    store,
    alerts: core.alerts,
    scheduler: core.scheduler,
    resourcesPath: process.resourcesPath,
    userData: dataDir,
    // For the vigil_status tool (Vigil's read-only tools for the user's own agents).
    status: () => core.status(),
    // Why the explainer or labeller isn't reaching an AI, for the Agents page.
    heldBack: (id) => ai.heldBack(id),
    ...(devHelperDir ? { devHelperDir } : {}),
    // The demo shows a fixed set of agents rather than this Mac's.
    ...(demo ? { readPs: async () => [], statInstall: demoInstalled } : {}),
  });
  const windows = new Windows();
  // Sensors can't report while Vigil is closed or the computer sleeps, so a
  // gap from then is not a quiet sensor.
  const awake = new AwakeClock(Date.now());
  powerMonitor.on('suspend', () => awake.suspend());
  powerMonitor.on('resume', () => awake.resume());
  const probe = {
    ...macProbe(
      (source) => store.lastEventAt(source),
      () => helper.state,
      async () =>
        (await helper.query<{ sensors?: HelperSensors }>('helper.status'))?.sensors ?? null,
    ),
    awakeMs: (since: number) => awake.awakeMs(since),
  };

  // A development build installs the helper that `pnpm build:helper` made.
  const helperDir = () => helperBundleDir(process.resourcesPath, devHelperDir);
  // The demo offers no helper buttons (see unlessDemo).
  core.helperInstallable = !demo && HELPER_PLATFORMS.has(process.platform) && helperDir() !== null;
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
  // After an update that replaced the app, the helper it installed before keeps
  // running until install.sh runs again. Compared at start and after each script.
  const checkHelperMatch = () => {
    const dir = helperDir();
    try {
      const m = dir && core.helperInstallable && !demo ? helperMatch(dir) : null;
      core.helperOutdated = m?.installed === 'outdated';
      return m;
    } catch (err) {
      console.error('[helper] could not compare the installed helper:', err);
      core.helperOutdated = false;
      return null;
    }
  };
  const helperAtStart = checkHelperMatch();
  // Installing or removing the helper shows the system's own password dialog.
  const afterHelperScript = async (r: HelperInstallResult) => {
    checkHelperMatch();
    await helper.reconnect();
    await reportHealth(core.sensors, probe);
    return r;
  };

  const installHelper = unlessDemo(demo, async () =>
    afterHelperScript(
      await runHelperScript(core.helperOutdated ? 'update' : 'install', helperDir()),
    ),
  );

  const keys = new KeyStore(join(dataDir, 'api-keys.json'), cipher);
  const setup: OnboardingService = new OnboardingService({
    store,
    keys,
    ...(demo
      ? { probe: demoProbe(), supported: true }
      : {
          probe: systemProbe(
            undefined,
            async () => {
              if (await helper.ping()) return true;
              // Just installed: connect now rather than on the next retry.
              await helper.tryConnect();
              return helper.ping();
            },
            // The labelling model set in AI settings; `ai` is created below, and checks run later.
            () => {
              try {
                return ai.settings().classifier.model;
              } catch {
                return undefined;
              }
            },
          ),
        }),
    // Setup's Codex step can use the user's own Codex sign-in (set up below).
    ...(demo
      ? {}
      : { codex: { status: () => ai.codexStatus(), share: () => ai.shareCodexSignIn() } }),
    // The helper step's button: the same password dialog as Home's. None in the demo.
    ...(demo ? {} : { installHelper }),
    // The wizard's helper and Santa steps, once this build can install them.
    plan: () => {
      const command = helperInstallCommand(helperDir());
      const claudePreflight = agents.claudePreflightStep();
      return {
        ...(distro ? { distro } : {}),
        ...(command ? { helperInstallCommand: command } : {}),
        ...(existsSync(santaProfilePath) ? { santaProfilePath } : {}),
        ...(claudePreflight ? { claudePreflight } : {}),
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
    busyReason: () => power.busyReason(),
    openExternal: (url) => shell.openExternal(url),
  });
  if (!demo) core.usage.setLimitsSource(() => ai.limits());
  core.aiNotice = () => ai.offNotice();
  ai.on('changed', () => windows.broadcast('changed'));
  ai.explainAlertsFrom(core);
  ai.labelEventsFrom(core);
  ai.reviewRulesFrom(core);

  // Tells the user when a newer release is out. Unsigned builds can't update
  // themselves, so it offers the DMG; nothing installs without the user.
  const updates = new UpdateChecker({
    current: app.getVersion(),
    arch: process.arch,
    platform: process.platform,
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

  // The pack: Vigil's own AI agents as dogs. The Lead dog talks with the user
  // and manages the pack; every tool call goes through the pack's gate, and
  // no dog can block, allow or change a rule.
  let packPush: NodeJS.Timeout | undefined;
  const pushPack = () => {
    // Moods change often while dogs work; one push per 150 ms is plenty.
    packPush ??= setTimeout(() => {
      packPush = undefined;
      windows.broadcast('pack');
    }, 150);
  };
  const connectors = new Connectors({
    load: () => store.getSetting('pack.connectors', z.array(ConnectorRecord), []),
    save: (records) => store.setSetting('pack.connectors', records),
    secretsPath: join(dataDir, 'pack-secrets.json'),
    cipher,
    onChange: pushPack,
    // Connectors run the user's programs: watched as connectors, never as Vigil.
    selfPaths: self.app,
    spawned: (pid, running) =>
      running ? detector.tracker.connectorStarted(pid) : detector.tracker.connectorStopped(pid),
  });
  const pack = new PackService({
    load: (key, schema, fallback) => store.getSetting(key, schema, fallback),
    save: (key, value) => store.setSetting(key, value),
    ai: ai.packAi(),
    vigilTools: agents.packTools(),
    preflight: (req, opts) => agents.packPreflight(req, opts),
    connectors,
    scheduler: core.scheduler,
    isBusy: () => power.isBusy(),
    notebook: new Notebook(db, { onChange: pushPack }),
    memory: new PackMemory(db, { onChange: pushPack }),
    onChange: pushPack,
  });
  ai.on('busy', (helper, busy) => pack.helperBusy(helper, busy));
  ai.on('note', (helper, note) => pack.helperNote(helper, note));
  pack.start();
  if (demo)
    seedPackDemo(pack, connectors, join(app.getAppPath(), 'src/main/pack/fixtures/demo-mcp.mjs'));
  app.on('before-quit', () => void connectors.closeAll());

  registerIpc(core, windows, setup, ai, updates, agents, { service: pack, connectors }, feedKeys, {
    install: installHelper,
    uninstall: unlessDemo(demo, async () =>
      afterHelperScript(await runHelperScript('uninstall', helperDir())),
    ),
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
  agents.on('changed', () => windows.broadcast('changed'));
  agents.on('activity', () => windows.broadcast('agents'));
  core.alerts.on('popup', (alert) => windows.showPopup(alert.id));
  core.feed.on('events', (n) => windows.broadcast('events', n));
  refresh();

  // An app updated in place asks once, for each helper it ships, to replace the
  // older one still installed, with the dialog the first install used. If that
  // is declined, Home keeps an Update helper button.
  if (helperAtStart?.installed === 'outdated' && app.isPackaged) {
    const bundle = helperAtStart.bundle;
    if (store.getSetting('helper.updateAsked', z.string(), '') !== bundle) {
      setTimeout(() => {
        void runHelperScript('update', helperDir())
          .then(afterHelperScript)
          .then((r) => {
            store.setSetting('helper.updateAsked', bundle);
            if (!r.ok && r.error !== 'cancelled') console.error('[helper] update failed:', r.error);
            windows.broadcast('changed');
          });
      }, 3000).unref?.();
    }
  }

  core.applyPower(power.mode);
  power.on('change', (mode) => core.applyPower(mode));
  core.start();
  // Reads `ps` once, then opens the pre-flight socket if the user turned it on.
  void agents.start().catch((err) => console.error('[agents] start failed:', err));

  // Sensor events arrive through the helper, which reads Santa's and osquery's logs as root.
  helper.on('event', (e) => void core.handleEvent(e));
  const checkHealth = () => reportHealth(core.sensors, probe);
  // An AppImage's programs are hashed once, in the background. The helper
  // gets them with the image in its first self grant, so a new image asks for
  // the password once rather than twice.
  const selfHashed = self.mount
    ? hashSelf(self.mount)
        .then((hashes) => core.detector?.setSelfHashes(hashes))
        .catch((err: unknown) => console.warn('[self] could not hash Vigil’s programs:', err))
    : Promise.resolve();
  // The helper runs the blocking rules it can on its own, so blocks happen
  // even while the app is closed, and hands Santa the pre-launch ones. Re-sent
  // on every connection and whenever the rules, exceptions or lists change;
  // what is Vigil's own goes apart from them, so its password dialog never
  // holds them up.
  const helperSync = new HelperSyncer({
    link: helper,
    rules: () => core.detector?.helperRules(),
    ready: selfHashed,
    log: (msg, err) => console.warn(msg, err),
  });
  const syncHelperRules = helperSync.sync;
  if (core.detector) core.detector.syncHelper = syncHelperRules;
  helper.on('state', (state) => {
    void checkHealth();
    if (state === 'connected') {
      void saveSantaProfile();
      helperSync.connected();
    }
  });
  if (HELPER_PLATFORMS.has(process.platform)) {
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
    void agents.stop();
    core.stop();
    store.close();
  });

  if (demo) {
    seedUsageDemo(core.usage);
    void seedDemo(core)
      .then(() => seedAgentsDemo(core, agents))
      .then(() => {
        const stop = startDemoFeed(core);
        app.on('before-quit', stop);
      });
  }
  if (perf)
    Object.assign(globalThis, {
      vigil: { core, windows, power, agents, syncHelperRules, helperSync, readyAt: Date.now() },
    });
  // First run opens setup; after that Vigil starts quietly in the menu bar.
  else if (!setup.finished()) windows.openMain('setup');
  else if (!app.isPackaged) windows.openMain();
}
