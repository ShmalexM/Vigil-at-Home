import { shell } from 'electron';
import type { SettingsPane } from '../../shared/setup.js';
import type { Handlers } from '../ipc.js';
import type { OnboardingService } from './service.js';

/** System Settings pages the setup steps link to. Fixed list: the renderer can't open arbitrary URLs. */
const PANES: Record<Exclude<SettingsPane, 'terminal'>, string> = {
  extensions: 'x-apple.systempreferences:com.apple.LoginItems-Settings.extension',
  fullDiskAccess: 'x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles',
  profiles: 'x-apple.systempreferences:com.apple.Profiles-Settings.extension',
};

type SetupCall =
  | 'getSetup'
  | 'checkSetup'
  | 'setSetupMode'
  | 'skipSetupStep'
  | 'finishSetup'
  | 'restartSetup'
  | 'saveApiKey'
  | 'clearApiKey'
  | 'openSettingsPane';

export function onboardingHandlers(
  setup: OnboardingService,
  onFinish: () => void,
): Pick<Handlers, SetupCall> {
  return {
    getSetup: () => setup.view(),
    checkSetup: () => setup.view(true),
    setSetupMode: (mode) => {
      setup.setMode(mode);
      return setup.view();
    },
    skipSetupStep: (id, skipped) => {
      setup.skip(id, skipped);
      return setup.view();
    },
    finishSetup: () => {
      setup.finish();
      onFinish();
    },
    restartSetup: () => setup.restart(),
    saveApiKey: (input) => {
      setup.setKey(input);
      return setup.view();
    },
    clearApiKey: (provider) => {
      setup.clearKey(provider);
      return setup.view();
    },
    openSettingsPane: async (pane) => {
      if (pane === 'terminal') {
        await shell.openPath('/System/Applications/Utilities/Terminal.app');
        return;
      }
      await shell.openExternal(PANES[pane]);
    },
  };
}
