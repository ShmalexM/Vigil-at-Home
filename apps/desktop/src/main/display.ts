/**
 * Linux: run the app under XWayland on a Wayland desktop. Wayland lets no
 * app place its own windows or keep one above the others, so the popover
 * couldn't sit under the tray and the detection popup couldn't stay on top.
 * Someone who chose a platform themselves keeps their choice.
 */
export function wantsX11(
  platform: NodeJS.Platform,
  argv: readonly string[],
  env: NodeJS.ProcessEnv,
): boolean {
  if (platform !== 'linux') return false;
  if (argv.some((a) => a.startsWith('--ozone-platform'))) return false;
  return !env['ELECTRON_OZONE_PLATFORM_HINT'];
}
