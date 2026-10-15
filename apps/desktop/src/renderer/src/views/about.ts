import type { SettingsView, StatusView } from '../../../shared/ipc';

const OS: Record<string, string> = { darwin: 'macOS', linux: 'Linux', win32: 'Windows' };
const CHIP: Record<string, string> = { arm64: 'Apple silicon or ARM', x64: 'Intel or AMD (x64)' };

/** "macOS, Apple silicon or ARM", from process.platform and process.arch. */
export function systemName(platform: string, arch: string): string {
  const chip = platform === 'darwin' && arch === 'arm64' ? 'Apple silicon' : (CHIP[arch] ?? arch);
  return `${OS[platform] ?? platform}, ${chip}`;
}

/**
 * What a bug report needs, without anything personal: no paths, alert
 * titles or program names, only versions and how protection is doing.
 */
export function aboutText(
  s: Pick<SettingsView, 'version' | 'commit' | 'platform' | 'arch'>,
  status?: Pick<StatusView, 'level' | 'dryRun'> & {
    sensors: readonly { id: string; state: string }[];
  },
): string {
  const lines = [
    `Vigil at Home ${s.version}${s.commit ? ` (${s.commit})` : ''}`,
    `System: ${systemName(s.platform, s.arch)} (${s.platform} ${s.arch})`,
  ];
  if (status) {
    lines.push(`Protection: ${status.level}${status.dryRun ? ', blocks simulated' : ''}`);
    lines.push(`Layers: ${status.sensors.map((x) => `${x.id} ${x.state}`).join(', ')}`);
  }
  return lines.join('\n');
}
