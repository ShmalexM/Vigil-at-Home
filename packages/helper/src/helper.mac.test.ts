// Real-Mac checks for the helper's actions: pf blocks real traffic, signals
// and pid guards hit real processes, quarantine moves real files, and
// launchd startup items are really unloaded and restored. Runs only on macOS
// with VIGIL_MAC_INTEGRATION=1, as root (`pnpm --filter @vigil/helper test:mac`).

import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { execFileSync, spawn, type ChildProcess } from 'node:child_process';
import {
  chmodSync,
  chownSync,
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  realpathSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { connect } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { RuleStore } from '@vigil/sensors';
import { Approvals } from './approval.js';
import { Executor, type ActionOutcome } from './executor.js';
import { Journal } from './journal.js';
import type { HelperAction } from './protocol.js';
import { PF_ANCHOR, PF_TABLE } from './commands/firewall.js';
import { realSystem } from './system.js';

const enabled =
  process.platform === 'darwin' &&
  process.env.VIGIL_MAC_INTEGRATION === '1' &&
  process.getuid?.() === 0;

const sys = realSystem();
let root: string;
let approvalsDir: string;
let executor: Executor;

/** Run an action; for releases, approve it the way the root CLI would after the password dialog. */
async function act(cmd: HelperAction): Promise<ActionOutcome> {
  let out = await executor.execute(cmd);
  if (out.kind === 'needs_approval') {
    Approvals.writeApproval(approvalsDir, out.nonce);
    out = await executor.execute(cmd, out.nonce);
  }
  if (out.kind !== 'done') throw new Error(`unexpected outcome ${out.kind}`);
  return out.result as ActionOutcome;
}

function canConnect(host: string, port: number, timeoutMs = 4000): Promise<boolean> {
  return new Promise((resolve) => {
    const s = connect({ host, port, timeout: timeoutMs });
    const done = (ok: boolean) => {
      s.destroy();
      resolve(ok);
    };
    s.once('connect', () => done(true));
    s.once('timeout', () => done(false));
    s.once('error', () => done(false));
  });
}

async function psStat(pid: number): Promise<string> {
  return (await sys.run('ps', ['-o', 'stat=', '-p', String(pid)])).stdout.trim();
}

function spawnSleeper(): { child: ChildProcess; path: string } {
  // A copy outside /bin, which the helper would treat as a system binary.
  const path = join(root, 'vigil-test-sleeper');
  if (!existsSync(path)) copyFileSync('/bin/sleep', path);
  const child = spawn(path, ['600'], { stdio: 'ignore' });
  return { child, path: realpathSync(path) };
}

async function exited(child: ChildProcess, ms = 5000): Promise<boolean> {
  if (child.exitCode !== null || child.signalCode !== null) return true;
  return new Promise((resolve) => {
    const t = setTimeout(() => resolve(false), ms);
    child.once('exit', () => {
      clearTimeout(t);
      resolve(true);
    });
  });
}

describe.skipIf(!enabled)('helper on a real Mac', () => {
  beforeAll(() => {
    root = realpathSync(mkdtempSync(join(tmpdir(), 'vigil-helper-mac-')));
    approvalsDir = join(root, 'approvals');
    executor = new Executor({
      sys,
      journal: new Journal(join(root, 'journal.json')),
      approvals: new Approvals({ dir: approvalsDir }),
      rules: new RuleStore(join(root, 'rules.json')),
      quarantine: { quarantineDir: join(root, 'Quarantine') },
      syncPort: 47821,
    });
  });

  afterAll(async () => {
    await sys.run('pfctl', ['-a', PF_ANCHOR, '-t', PF_TABLE, '-T', 'flush']);
    await sys.run('pfctl', ['-a', PF_ANCHOR, '-F', 'all']);
    rmSync(root, { recursive: true, force: true });
  });

  describe('firewall', () => {
    const target = '1.1.1.1';

    it('the stock pf.conf evaluates anchors under com.apple', async () => {
      const r = await sys.run('pfctl', ['-sr']);
      expect(r.stdout + r.stderr).toMatch(/anchor "com\.apple\/\*"/);
    });

    it('blocks and then releases real traffic to an address', async () => {
      expect(await canConnect(target, 443), 'no connectivity before blocking').toBe(true);

      await act({ kind: 'network.block', address: target });
      const rules = await sys.run('pfctl', ['-a', PF_ANCHOR, '-sr']);
      expect(rules.stdout).toContain(PF_TABLE);
      expect(
        (await sys.run('pfctl', ['-a', PF_ANCHOR, '-t', PF_TABLE, '-T', 'show'])).stdout,
      ).toContain(target);
      expect(await canConnect(target, 443), 'traffic still flows while blocked').toBe(false);

      await act({ kind: 'network.unblock', address: target });
      expect(await canConnect(target, 443), 'traffic did not come back after unblock').toBe(true);
    }, 30_000);

    it('re-applies journal blocks after pf forgets them (as after a reboot)', async () => {
      await act({ kind: 'network.block', address: target });
      await sys.run('pfctl', ['-a', PF_ANCHOR, '-t', PF_TABLE, '-T', 'flush']);
      expect(await canConnect(target, 443)).toBe(true);
      await executor.reapplyFirewallBlocks();
      expect(await canConnect(target, 443)).toBe(false);
      await act({ kind: 'network.unblock', address: target });
      expect(await canConnect(target, 443)).toBe(true);
    }, 30_000);
  });

  describe('processes', () => {
    it('pauses, resumes and kills a real process', async () => {
      const { child, path } = spawnSleeper();
      const pid = child.pid!;
      await new Promise((r) => setTimeout(r, 300));

      await act({ kind: 'process.suspend', pid, path });
      expect(await psStat(pid)).toContain('T');

      await act({ kind: 'process.resume', pid, path });
      expect(await psStat(pid)).not.toContain('T');

      await act({ kind: 'process.kill', pid, path });
      expect(await exited(child)).toBe(true);
    }, 20_000);

    it('refuses when the pid now runs a different program', async () => {
      const { child } = spawnSleeper();
      await new Promise((r) => setTimeout(r, 300));
      await expect(
        act({ kind: 'process.kill', pid: child.pid!, path: '/usr/local/bin/something-else' }),
      ).rejects.toThrow();
      expect(await psStat(child.pid!)).not.toBe('');
      child.kill('SIGKILL');
      await exited(child);
    }, 20_000);

    it('refuses to touch a system process', async () => {
      const r = await sys.run('ps', ['-axo', 'pid=,comm=']);
      const line = r.stdout.split('\n').find((l) => /\/usr\/libexec\/|\/usr\/sbin\//.test(l));
      expect(line).toBeDefined();
      const [pidStr, comm] = line!.trim().split(/\s+/, 2) as [string, string];
      await expect(
        act({ kind: 'process.suspend', pid: Number(pidStr), path: comm }),
      ).rejects.toThrow();
    });
  });

  describe('quarantine', () => {
    // The user who runs the tests under sudo: the owner of the temporary folder.
    const userUid = () => Number(process.env.SUDO_UID ?? statSync(tmpdir()).uid);

    it('quarantines a user’s file as that user and restores it', async () => {
      // A folder of the user's, as in their Downloads: the move runs as them.
      chmodSync(root, 0o755);
      const folder = join(root, 'Downloads');
      mkdirSync(folder);
      chownSync(folder, userUid(), 20);
      const file = join(folder, 'dropper.sh');
      writeFileSync(file, '#!/bin/sh\necho hi\n', { mode: 0o755 });
      chownSync(file, userUid(), 20);
      const out = await act({ kind: 'file.quarantine', path: file });
      expect(existsSync(file)).toBe(false);
      await act({ kind: 'file.restore', quarantineId: out.quarantineId! });
      expect(existsSync(file)).toBe(true);
      expect(statSync(file).mode & 0o777).toBe(0o755);
      expect(statSync(file).uid).toBe(userUid());
    });

    it('refuses a root-owned file in a folder others can change', async () => {
      chmodSync(root, 0o755);
      const shared = join(root, 'Shared');
      mkdirSync(shared);
      chmodSync(shared, 0o1777);
      const file = join(shared, 'installed.sh');
      writeFileSync(file, '#!/bin/sh\n', { mode: 0o755 });
      await expect(act({ kind: 'file.quarantine', path: file })).rejects.toMatchObject({
        code: 'installer-owned',
      });
      expect(existsSync(file)).toBe(true);
    });
  });

  describe('startup items', () => {
    const label = 'com.example.vigiltest.sleeper';
    const plist = `/Library/LaunchDaemons/${label}.plist`;

    afterAll(async () => {
      await sys.run('launchctl', ['bootout', `system/${label}`]);
      rmSync(plist, { force: true });
    });

    it('unloads a launch daemon and puts it back', async () => {
      const { path } = spawnSleeper();
      writeFileSync(
        plist,
        `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>${label}</string>
<key>ProgramArguments</key><array><string>${path}</string><string>600</string></array>
<key>RunAtLoad</key><true/>
</dict></plist>
`,
        { mode: 0o644 },
      );
      const boot = await sys.run('launchctl', ['bootstrap', 'system', plist]);
      expect(boot.code, boot.stderr).toBe(0);
      expect((await sys.run('launchctl', ['print', `system/${label}`])).code).toBe(0);

      await act({ kind: 'persistence.disable', path: plist });
      expect(existsSync(plist)).toBe(false);
      expect((await sys.run('launchctl', ['print', `system/${label}`])).code).not.toBe(0);

      await act({ kind: 'persistence.enable', path: plist });
      expect(existsSync(plist)).toBe(true);
      expect((await sys.run('launchctl', ['print', `system/${label}`])).code).toBe(0);
    }, 30_000);
  });
  describe('startup items for the logged-in user', () => {
    const uid = sys.consoleUid();
    const user =
      uid && uid !== 0
        ? execFileSync('/usr/bin/stat', ['-f', '%Su', '/dev/console'], { encoding: 'utf8' }).trim()
        : undefined;
    const label = 'com.example.vigiltest.agent';
    const dir = user ? `/Users/${user}/Library/LaunchAgents` : '';
    const plist = `${dir}/${label}.plist`;

    afterAll(async () => {
      if (!user) return;
      await sys.run('launchctl', ['bootout', `gui/${uid}/${label}`]);
      rmSync(plist, { force: true });
    });

    it.skipIf(!user)(
      'unloads a launch agent in the user session and puts it back',
      async () => {
        const { path } = spawnSleeper();
        mkdirSync(dir, { recursive: true });
        writeFileSync(
          plist,
          `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>${label}</string>
<key>ProgramArguments</key><array><string>${path}</string><string>600</string></array>
<key>RunAtLoad</key><true/>
</dict></plist>
`,
          { mode: 0o644 },
        );
        chownSync(plist, uid!, 20);
        const boot = await sys.run('launchctl', ['bootstrap', `gui/${uid}`, plist]);
        expect(boot.code, boot.stderr).toBe(0);
        expect((await sys.run('launchctl', ['print', `gui/${uid}/${label}`])).code).toBe(0);

        await act({ kind: 'persistence.disable', path: plist });
        expect(existsSync(plist)).toBe(false);
        expect((await sys.run('launchctl', ['print', `gui/${uid}/${label}`])).code).not.toBe(0);

        await act({ kind: 'persistence.enable', path: plist });
        expect(existsSync(plist)).toBe(true);
        expect((await sys.run('launchctl', ['print', `gui/${uid}/${label}`])).code).toBe(0);
      },
      30_000,
    );
  });
});
