// electron-builder afterPack hook: turns off the Electron features a packaged app
// does not need, so the app binary can't be reused as a plain Node.js runtime or
// debugger, and only runs the code in its own app.asar.
// The helper and agent hook run on their own bundled node (Resources/helper), not this binary.

import { join } from 'node:path';
import { flipFuses, FuseV1Options, FuseVersion } from '@electron/fuses';

export default async function afterPack(context) {
  const { appOutDir, electronPlatformName, packager } = context;
  const darwin = electronPlatformName === 'darwin';
  const electron = darwin
    ? join(appOutDir, `${packager.appInfo.productFilename}.app`)
    : join(appOutDir, packager.executableName);

  await flipFuses(electron, {
    version: FuseVersion.V1,
    // Flipping fuses breaks the ad hoc signature; electron-builder signs again afterwards.
    resetAdHocDarwinSignature: darwin,
    [FuseV1Options.RunAsNode]: false,
    [FuseV1Options.EnableNodeOptionsEnvironmentVariable]: false,
    [FuseV1Options.EnableNodeCliInspectArguments]: false,
    [FuseV1Options.OnlyLoadAppFromAsar]: true,
    // electron-builder writes the asar hash into Info.plist; Electron checks it on macOS only.
    ...(darwin ? { [FuseV1Options.EnableEmbeddedAsarIntegrityValidation]: true } : {}),
    [FuseV1Options.EnableCookieEncryption]: true,
  });
}
