import { app, ipcMain, type IpcMainInvokeEvent } from 'electron';
import type { z } from 'zod';
import { calls, type CallName, type CallResults } from '../shared/ipc.js';
import { onboardingHandlers } from './onboarding/ipc.js';
import type { OnboardingService } from './onboarding/service.js';
import type { VigilCore } from './service.js';
import { sendTestAlert } from './test-alert.js';
import { rendererOrigin, type Windows } from './windows.js';

export type Handlers = {
  [K in CallName]: (
    ...args: z.output<(typeof calls)[K]>
  ) => CallResults[K] | Promise<CallResults[K]>;
};

/** Register one validated handler per call. Arguments are parsed with zod before use. */
export function registerIpc(core: VigilCore, windows: Windows, setup: OnboardingService): void {
  const h: Handlers = {
    getStatus: () => core.status(),
    listAlerts: (status) => core.store.listAlerts(status ? { status } : {}),
    getAlertDetail: (id) => core.alertDetail(id),
    decide: (id, input) => core.decide(id, stripUndefined(input)),
    reopen: (id) => core.alerts.reopen(id),
    undoAction: (id) => core.alerts.undo(id),
    approveProposal: (id) => core.alerts.approveProposal(id),
    rejectProposal: (id) => core.alerts.rejectProposal(id),
    listRules: () => core.rules(),
    setRuleMode: (id: string, mode) => core.setRuleMode(id, mode),
    getRuleEditor: (id) => core.ruleEditing()?.view(id) ?? null,
    previewRule: (json) => editing(core).preview(json),
    saveRule: (json) => editing(core).save(json),
    revertRule: (id) => editing(core).revert(id),
    deleteRule: (id) => editing(core).delete(id),
    addExclusion: (id, input) => editing(core).addExclusion(id, input),
    removeExclusion: (id, index) => editing(core).removeExclusion(id, index),
    removeException: (id) => editing(core).removeException(id),
    excludeFromAlert: (id, scope) => editing(core).excludeFromAlert(id, scope),
    listActions: () => core.store.listActions({ limit: 300 }),
    listEvents: (q) => core.store.listEventViews(stripUndefined(q)),
    eventStats: () => core.eventStats(),
    getSettings: () => ({
      theme: core.theme(),
      dataDir: app.getPath('userData'),
      version: app.getVersion(),
    }),
    setTheme: (theme) => {
      core.setTheme(theme);
      windows.applyTheme(theme);
    },
    sendTestAlert: () => sendTestAlert(core.alerts),
    openMain: (route) => windows.openMain(route),
    closePopup: () => windows.hidePopup(),
    fitPopup: (height) => windows.fitPopup(height),
    quit: () => app.quit(),
    ...onboardingHandlers(setup, () => windows.openMain('home')),
  };

  for (const name of Object.keys(calls) as CallName[]) {
    ipcMain.handle(`vigil:${name}`, (event: IpcMainInvokeEvent, ...raw: unknown[]) => {
      if (!event.senderFrame?.url.startsWith(rendererOrigin())) {
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
