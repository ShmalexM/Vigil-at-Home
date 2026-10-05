import { spawnSync } from 'node:child_process';
import { copyFileSync, mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { CHECKS, systemProbe } from './checks.js';
import { linuxDistro, setupPlan } from './plan.js';

// Runs setup's own Linux commands, exactly as shown to the user, on a real
// Debian-family machine as root. Runs in CI's linux job (Ubuntu, sudo,
// VIGIL_LINUX_INTEGRATION=1).
const release = (() => {
  try {
    return readFileSync('/etc/os-release', 'utf8');
  } catch {
    return '';
  }
})();
const enabled =
  process.platform === 'linux' &&
  process.env['VIGIL_LINUX_INTEGRATION'] === '1' &&
  process.getuid?.() === 0 &&
  linuxDistro(release) === 'debian';

const steps = setupPlan({ platform: 'linux', distro: 'debian', helperInstallCommand: 'x' });
const run = (id: string) => {
  for (const c of steps.find((s) => s.id === id)!.commands) {
    const r = spawnSync('/bin/sh', ['-c', c.cmd], { encoding: 'utf8', timeout: 5 * 60_000 });
    expect(r.status, `${c.label}\n${c.cmd}\n${r.stderr}`).toBe(0);
  }
};

describe.skipIf(!enabled)('Linux setup commands', () => {
  it(
    'install osquery from its signed repository',
    async () => {
      run('osquery');
      expect(await CHECKS.osquery(systemProbe())).toEqual({ ok: true });
    },
    10 * 60_000,
  );

  it(
    'install fapolicyd so that it only blocks what Vigil blocks',
    async () => {
      run('fapolicyd');
      expect(await CHECKS.fapolicyd(systemProbe())).toEqual({ ok: true });
      // A program no package manager knows about still runs.
      const dir = mkdtempSync(join(tmpdir(), 'vigil-untrusted-'));
      const prog = join(dir, 'untrusted-true');
      copyFileSync('/usr/bin/true', prog);
      spawnSync('chmod', ['755', prog]);
      expect(spawnSync(prog).status).toBe(0);
      spawnSync('systemctl', ['disable', '--now', 'fapolicyd']);
    },
    10 * 60_000,
  );
});
