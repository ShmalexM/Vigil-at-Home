import { app, ipcMain, type IpcMainInvokeEvent } from 'electron';
import type { z } from 'zod';
import { calls, type CallName, type CallResults } from '../shared/ipc.js';
import type { HelperInstallResult } from '../shared/ipc.js';
import type { AiBridge } from './ai.js';
import { agentsHandlers } from './agents/ipc.js';
import { packHandlers } from './pack/ipc.js';
import type { Connectors } from './pack/connectors.js';
import type { PackService } from './pack/service.js';
import type { AgentService } from './agents/service.js';
import type { UpdateChecker } from './updates.js';
import { onboardingHandlers } from './onboarding/ipc.js';
import type { OnboardingService } from './onboarding/service.js';
import type { VigilCore } from './service.js';
import { sendTestAlert } from './test-alert.js';
import { isAppFrame, type Windows } from './windows.js';
import { RuleSuggestions } from './rule-suggestions.js';

export type Handlers = {
  [K in CallName]: (
    ...args: z.output<(typeof calls)[K]>
  ) => CallResults[K] | Promise<CallResults[K]>;
};

export interface HelperControl {
  install(): Promise<HelperInstallResult>;
  uninstall(): Promise<HelperInstallResult>;
}

const noHelper: HelperControl = {
  install: async () => ({ ok: false, error: 'The helper only runs on macOS' }),
  uninstall: async () => ({ ok: false, error: 'The helper only runs on macOS' }),
};

/** Register one validated handler per call. Arguments are parsed with zod before use. */
export function registerIpc(
  core: VigilCore,
  windows: Windows,
  setup: OnboardingService,
  ai: AiBridge,
  updates: UpdateChecker,
  agents: AgentService,
  pack: { service: PackService; connectors: Connectors },
  helper: HelperControl = noHelper,
): void {
  let ruleSuggestions: RuleSuggestions | undefined;
  const suggestions = () => {
    if (!core.detector) throw new Error('Detection is not running');
    ruleSuggestions ??= new RuleSuggestions(
      core.detector,
      () => ai.ruleReviewRunner() !== undefined,
    );
    return ruleSuggestions;
  };
  const h: Handlers = {
    getStatus: () => core.status(),
    listAlerts: (status) => core.store.listAlerts(status ? { status } : {}),
    getAlertDetail: (id) => core.alertDetail(id),
    decide: (id, input) => core.decide(id, stripUndefined(input)),
    reopen: (id) => core.alerts.reopen(id),
    clearNoticed: (ids) => core.clearNoticed(ids),
    clearNoticedUpTo: (at) => core.clearNoticedUpTo(at),
    undoAction: (id) => core.alerts.undo(id),
    approveProposal: (id) => core.alerts.approveProposal(id),
    rejectProposal: (id) => core.alerts.rejectProposal(id),
    listRules: () => core.rules(),
    setRuleMode: async (id: string, mode) => {
      const result = await core.setRuleMode(id, mode);
      // A cancelled password put the rule back; show that, not the click.
      windows.broadcast('changed');
      return result;
    },
    getRuleEditor: (id) => core.ruleEditing()?.view(id) ?? null,
    previewRule: (json) => editing(core).preview(json),
    saveRule: (json) => editing(core).save(json),
    revertRule: (id) => editing(core).revert(id),
    deleteRule: (id) => editing(core).delete(id),
    addExclusion: (id, input) => editing(core).addExclusion(id, input),
    removeExclusion: (id, index) => editing(core).removeExclusion(id, index),
    removeException: (id) => editing(core).removeException(id),
    excludeFromAlert: (id, scope) => editing(core).excludeFromAlert(id, scope),
    listRuleSuggestions: () => suggestions().view(),
    acceptRuleSuggestion: async (id, mode) => {
      const helper = await suggestions().accept(id, mode);
      windows.broadcast('changed');
      return { helper };
    },
    dismissRuleSuggestion: (id, note) => suggestions().dismiss(id, note),
    reviewRulesNow: () => suggestions().reviewNow(),
    listActions: () => core.store.listActions({ limit: 300 }),
    listEvents: (q) => core.store.listEventViews(stripUndefined(q)),
    eventStats: () => core.eventStats(),
    getSettings: () => ({
      theme: core.theme(),
      appearance: core.appearance(),
      dataDir: app.getPath('userData'),
      version: app.getVersion(),
      commit: typeof __VIGIL_COMMIT__ === 'string' ? __VIGIL_COMMIT__ : '',
      showAdvanced: core.showAdvanced(),
      platform: process.platform,
      arch: process.arch,
    }),
    setTheme: (theme) => {
      core.setTheme(theme);
      windows.applyTheme(theme, core.appearance());
    },
    setAlertView: (view) => {
      core.setAlertView(view);
      windows.setNeedsYou(core.status().badge);
      windows.broadcast('changed');
    },
    setShowAdvanced: (show) => {
      core.setShowAdvanced(show);
      windows.broadcast('changed');
    },
    setAppearance: (appearance) => {
      core.setAppearance(appearance);
      windows.applyTheme(core.theme(), core.appearance());
    },
    sendTestAlert: () => sendTestAlert(core.alerts),
    openMain: (route) => windows.openMain(route),
    closePopup: () => windows.hidePopup(),
    fitPopup: (height) => windows.fitPopup(height),
    quit: () => app.quit(),
    ...onboardingHandlers(setup, () => windows.openMain('home')),
    installHelper: () => helper.install(),
    uninstallHelper: () => helper.uninstall(),
    getUsage: (days) => core.usage.report(days),
    getUsageLimits: (refresh) => core.usage.limits(refresh ?? false),
    getUpdates: () => updates.view(),
    checkUpdates: () => updates.check(),
    setUpdateAuto: (auto) => updates.setAuto(auto),
    dismissUpdate: () => updates.dismiss(),
    downloadUpdate: () => updates.download(),
    openUpdateNotes: () => updates.openNotes(),
    getAi: () => ai.view(),
    getAiPrefs: () => ai.prefs(),
    setAiPrefs: (patch) => ai.setPrefs(patch),
    explainAlert: (id) => ai.explainOnRequest(core, id),
    signInAi: (provider) => ai.signIn(provider),
    shareCodexSignIn: async () => {
      const r = await ai.shareCodexSignIn();
      return r.ok
        ? { ok: true }
        : {
            ok: false,
            error: 'Your Codex keeps its sign-in in the Keychain, so sign in from Vigil instead',
          };
    },
    stopSharingCodexSignIn: () => ai.stopSharingCodexSignIn(),
    ...agentsHandlers(agents),
    ...packHandlers(pack.service, pack.connectors),
  };

  for (const name of Object.keys(calls) as CallName[]) {
    ipcMain.handle(`vigil:${name}`, (event: IpcMainInvokeEvent, ...raw: unknown[]) => {
      // Only Vigil's own page, in its top frame, may call in.
      const frame = event.senderFrame;
      if (!frame || frame.parent || !isAppFrame(frame.url)) {
        throw new Error('Rejected IPC from an unknown frame');
      }
      const args = calls[name].parse(raw);
      return (h[name] as (...a: unknown[]) => unknown)(...args);
    });
  }
}

function editing(core: VigilCore) {
  const e = core.ruleEditing();
  if (!e) throw new Error('Detection is not running');
  return e;
}

/** zod output has `key: undefined` where our types want the key absent. */
function stripUndefined<T extends object>(o: T): { [K in keyof T]: Exclude<T[K], undefined> } {
  return Object.fromEntries(Object.entries(o).filter(([, v]) => v !== undefined)) as {
    [K in keyof T]: Exclude<T[K], undefined>;
  };
}
