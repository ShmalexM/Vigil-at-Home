import { execFileSync, spawnSync } from 'node:child_process';
import { cpSync, existsSync, lstatSync, mkdtempSync, readdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { helperMatch } from './helper-install.js';

// Installs the real helper with the Linux install.sh, as root, under systemd,
// then removes it. Runs in CI's linux job (sudo, VIGIL_LINUX_INTEGRATION=1).
const enabled =
  process.platform === 'linux' &&
  process.env['VIGIL_LINUX_INTEGRATION'] === '1' &&
  process.getuid?.() === 0 &&
  spawnSync('systemctl', ['is-system-running']).stdout?.toString().trim() !== 'offline';

const app = join(import.meta.dirname, '..', '..');
const dev = join(app, 'build', 'helper', `dev-${process.arch}`);
const sh = (script: string) =>
  spawnSync('/bin/sh', [join(dev, 'linux', script)], { encoding: 'utf8' });

describe.skipIf(!enabled)('Linux helper install', () => {
  it(
    'installs a root systemd service with its polkit policy, then removes it all',
    () => {
      execFileSync(process.execPath, [join(app, 'scripts', 'build-helper.mjs'), '--dev'], {
        cwd: app,
        stdio: 'inherit',
      });

      const install = sh('install.sh');
      expect(install.status, install.stderr).toBe(0);
      expect(install.stdout).toContain('Vigil helper installed and running.');
      expect(existsSync('/run/vigil-helper.sock')).toBe(true);
      expect(spawnSync('systemctl', ['is-active', '--quiet', 'vigil-helper.service']).status).toBe(
        0,
      );
      expect(spawnSync('systemctl', ['is-enabled', '--quiet', 'vigil-helper.service']).status).toBe(
        0,
      );
      expect(existsSync('/usr/share/polkit-1/actions/com.vigilathome.helper.policy')).toBe(true);
      // The launcher runs the installed node and helper.
      const approve = spawnSync('/usr/libexec/vigil-helper', ['approve', 'a'.repeat(32)]);
      expect(approve.status).toBe(0);

      // The app sees that the installed helper is the one it ships.
      expect(helperMatch(dev, 'linux').installed).toBe('current');
      // An updated app carrying a different helper sees the installed one as outdated.
      const newer = mkdtempSync(join(tmpdir(), 'vigil-newer-'));
      cpSync(dev, newer, { recursive: true });
      writeFileSync(join(newer, 'helper.mjs'), '// a newer helper\n', { flag: 'a' });
      expect(helperMatch(newer, 'linux').installed).toBe('outdated');

      // The helper runs through `current`, a link to one complete version.
      const d = '/usr/libexec/vigil-helper.d';
      expect(lstatSync(`${d}/current`).isSymbolicLink()).toBe(true);
      expect(existsSync(`${d}/node`)).toBe(false);

      // Installing again replaces the running copy, keeping the one before it.
      expect(sh('install.sh').status).toBe(0);
      expect(readdirSync(`${d}/versions`)).toHaveLength(2);
      expect(sh('install.sh').status).toBe(0);
      expect(readdirSync(`${d}/versions`)).toHaveLength(2);
      expect(existsSync(`${d}.lock`)).toBe(false);
      expect(spawnSync('systemctl', ['is-active', '--quiet', 'vigil-helper.service']).status).toBe(
        0,
      );

      const remove = sh('uninstall.sh');
      expect(remove.status).toBe(0);
      expect(existsSync('/usr/libexec/vigil-helper')).toBe(false);
      expect(existsSync('/usr/libexec/vigil-helper.d')).toBe(false);
      expect(existsSync('/usr/libexec/vigil-helper.d.lock')).toBe(false);
      expect(existsSync('/etc/systemd/system/vigil-helper.service')).toBe(false);
      expect(existsSync('/usr/share/polkit-1/actions/com.vigilathome.helper.policy')).toBe(false);
      expect(
        spawnSync('systemctl', ['is-active', '--quiet', 'vigil-helper.service']).status,
      ).not.toBe(0);
    },
    5 * 60_000,
  );
});
