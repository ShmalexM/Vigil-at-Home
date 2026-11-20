// The helper update on 2026-10-17, replayed on an isolated helper: the daemon
// started on pin files it couldn't verify, ignored them (rightly) and then
// logged so every time its 5-minute repair read them again, for days, while
// nothing ever asked for them to be replaced. Now it logs once, names the
// problem in the app's copy (so the app asks for a helper update), and the
// update's pin-app signs new files that the next start takes.

import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { randomBytes } from 'node:crypto';
import {
  mkdtempSync,
  readFileSync,
  realpathSync,
  renameSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { AppPin } from './appPin.js';
import { HelperClient } from './client.js';
import { pinApp } from './pinApp.js';
import { AppPinStore } from './pinStore.js';
import { FakeSystem } from './testing/fakeSystem.js';
import { isolatedPaths, startIsolatedHelper } from './testing/isolatedHelper.js';

const PIN: AppPin = {
  platform: 'darwin',
  path: '/Users/a/Downloads/Vigil at Home.app/Contents/MacOS/Vigil at Home',
  cdhash: 'a'.repeat(40),
  sha256: 'b'.repeat(64),
};
const APP = '/Applications/Vigil at Home.app/Contents/MacOS/Vigil at Home';

let root: string;
beforeEach(() => {
  root = realpathSync(mkdtempSync(join(tmpdir(), 'vigil-pin-update-')));
});
afterEach(() => rmSync(root, { recursive: true, force: true }));

/** Start a helper on `root`, ask it for its status, and stop it. */
async function startOnce(logs: string[]) {
  const helper = await startIsolatedHelper({ root, log: (m) => logs.push(m) });
  try {
    const c = await HelperClient.connect(helper.socket, helper.approver());
    try {
      const status = (await c.call({ kind: 'helper.status' })) as {
        appPin?: { pinned: boolean; problem?: string };
      };
      return status.appPin;
    } finally {
      c.close();
    }
  } finally {
    await helper.stop();
  }
}

describe('a helper update over pin files the helper ignores', () => {
  it('is asked for, and signs new files the next start takes', async () => {
    const paths = isolatedPaths(root);
    const sys = new FakeSystem();
    const uid = process.getuid!();
    // An earlier helper pinned an app; then the key beside its files changed.
    const before = new AppPinStore(sys, { dir: paths.appPinDir, ownerUid: uid });
    await before.load();
    await before.write(PIN);
    const keyFile = join(paths.appPinDir, 'app-pin.key');
    writeFileSync(`${keyFile}.new`, randomBytes(32).toString('hex') + '\n', { mode: 0o600 });
    renameSync(`${keyFile}.new`, keyFile);

    const logs: string[] = [];
    const status = await startOnce(logs);
    expect(status).toEqual({
      pinned: false,
      problem: expect.stringMatching(/^the pin file is not the one this helper signed/),
    });
    expect(logs.filter((l) => l.startsWith('app pin:'))).toEqual([`app pin: ${status?.problem}`]);
    // The app reads this copy (helper-install.ts appPinProblem) and asks for an update.
    expect(JSON.parse(readFileSync(paths.appPin, 'utf8'))).toEqual({ problem: status?.problem });

    // Update helper: install.sh has stopped the helper, and runs pin-app as root.
    expect(
      await pinApp({
        euid: 0,
        socket: paths.socket,
        dir: paths.appPinDir,
        publicFile: paths.appPin,
        sys,
        target: APP,
        installed: ['/Applications/Vigil at Home.app'],
        ownerUid: uid,
      }),
    ).toBe(0);
    expect(JSON.parse(readFileSync(paths.appPin, 'utf8'))).toEqual({});

    const after: string[] = [];
    expect(await startOnce(after)).toEqual({ pinned: false });
    expect(after.filter((l) => l.startsWith('app pin:'))).toEqual([]);
    expect(JSON.parse(readFileSync(paths.appPin, 'utf8'))).toEqual({});
  });

  it('starts a clean update with no problem to report', async () => {
    const paths = isolatedPaths(root);
    const sys = new FakeSystem();
    const uid = process.getuid!();
    const logs: string[] = [];
    expect(await startOnce(logs)).toEqual({ pinned: false });
    const update = () =>
      pinApp({
        euid: 0,
        socket: paths.socket,
        dir: paths.appPinDir,
        publicFile: paths.appPin,
        sys,
        target: APP,
        installed: ['/Applications/Vigil at Home.app'],
        ownerUid: uid,
      });
    // Two updates in a row, each followed by a start, as Home → Update helper does.
    for (let i = 0; i < 2; i++) {
      expect(await update()).toBe(0);
      expect(await startOnce(logs)).toEqual({ pinned: false });
    }
    expect(logs.filter((l) => l.startsWith('app pin:'))).toEqual([]);
  });
});
