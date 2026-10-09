import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  copyFileSync,
  existsSync,
  linkSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHmac } from 'node:crypto';
import type { AppPin } from './appPin.js';
import { quarantine, type QuarantineOptions } from './commands/quarantine.js';
import { AppPinStore } from './pinStore.js';
import type { BinaryName, RunResult, System } from './system.js';
import type { Platform } from './platform.js';
import { FakeLinuxSystem } from './testing/fakeLinuxSystem.js';

const PIN: AppPin = {
  platform: 'darwin',
  path: '/Users/a/Downloads/Vigil at Home.app/Contents/MacOS/Vigil at Home',
  cdhash: 'a'.repeat(40),
  sha256: 'b'.repeat(64),
};
const OTHER: AppPin = { ...PIN, path: '/Users/a/evil', cdhash: 'c'.repeat(40) };

/**
 * Only what the store uses: the immutable flag, run through chflags or
 * chattr, with each run logged next to what the file held at that moment.
 */
class Flags {
  runs: { bin: BinaryName; args: string[]; held: string | undefined }[] = [];
  immutable = new Set<string>();
  constructor(readonly platform: Platform) {}
  now = () => 1_000;
  /** Milliseconds each run takes, to hold a write in flight. */
  delay = 0;
  /** Called during each run, with its arguments. */
  during: ((args: string[]) => void) | undefined;
  async run(bin: BinaryName, args: string[]): Promise<RunResult> {
    if (this.delay) await new Promise((r) => setTimeout(r, this.delay));
    this.during?.(args);
    const path = args.at(-1)!;
    const on = args[0] === '+i' || args[0] === 'uchg';
    if (on) this.immutable.add(path);
    else this.immutable.delete(path);
    this.runs.push({ bin, args, held: existsSync(path) ? readFileSync(path, 'utf8') : undefined });
    return { code: 0, stdout: '', stderr: '' };
  }
}

let root: string;
let state: string;
let file: string;
let keyFile: string;
beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), 'vigil-pinstore-'));
  state = join(root, 'pin');
  file = join(state, 'app-pin.json');
  keyFile = join(state, 'app-pin.key');
});
afterEach(() => rmSync(root, { recursive: true, force: true }));

const open = async (sys: Flags | System = new Flags('linux')) => {
  const store = new AppPinStore(sys as System, { dir: state, ownerUid: process.getuid!() });
  await store.load();
  return store;
};

describe('the signed app pin', () => {
  it('makes a 0600 key on first use and signs the pin with it', async () => {
    const store = await open();
    expect(statSync(keyFile).mode & 0o777).toBe(0o600);
    await store.write(PIN);
    const body = JSON.parse(readFileSync(file, 'utf8')) as Record<string, unknown>;
    expect(body).toMatchObject({ ...PIN, mac: expect.stringMatching(/^[0-9a-f]{64}$/) });
    // A helper started later reads it back.
    expect((await open()).current()).toEqual(PIN);
  });

  it('ignores a pin file without a valid signature, and says so', async () => {
    const store = await open();
    await store.write(PIN);
    for (const planted of [
      { ...OTHER },
      { ...OTHER, mac: 'f'.repeat(64) },
      // Signed with another key.
      { ...OTHER, mac: createHmac('sha256', Buffer.alloc(32)).update('x').digest('hex') },
      // The real signature over the real pin, with one field changed.
      { ...(JSON.parse(readFileSync(file, 'utf8')) as object), cdhash: OTHER.cdhash },
    ]) {
      writeFileSync(file + '.new', JSON.stringify(planted));
      renameSync(file + '.new', file);
      expect(store.current()).toEqual(PIN);
      expect(store.status()).toMatchObject({ pinned: true, problem: expect.stringMatching(/not/) });
      // A helper starting with only that file has no pin.
      expect((await open()).current()).toBeUndefined();
    }
  });

  it('never takes a copy of its own file, or an older one put back', async () => {
    const store = await open();
    await store.write(OTHER);
    copyFileSync(file, join(root, 'old-copy'));
    linkSync(file, join(root, 'old-link'));
    await store.write(PIN);
    // Same bytes, other inode: not the file the helper signed.
    copyFileSync(join(root, 'old-copy'), file);
    expect(store.current()).toEqual(PIN);
    expect(store.status().problem).toMatch(/not the one/);
    // The very file it signed earlier, put back: older than the pin in force.
    renameSync(join(root, 'old-link'), file);
    expect(store.current()).toEqual(PIN);
    expect(store.status().problem).toMatch(/not the one/);
  });

  it('keeps the pin in memory when the file is deleted', async () => {
    const store = await open();
    await store.write(PIN);
    rmSync(file);
    expect(store.current()).toEqual(PIN);
    expect(store.status()).toMatchObject({
      pinned: true,
      problem: expect.stringMatching(/missing/),
    });
    // Nor does a deleted key change anything: the key is in memory too.
    rmSync(keyFile);
    expect(store.current()).toEqual(PIN);
  });

  it('signs "no pin" too, so an unsigned pin after it stays ignored', async () => {
    const store = await open();
    await store.write(undefined);
    expect(store.status()).toEqual({ pinned: false });
    writeFileSync(file + '.new', JSON.stringify(PIN));
    renameSync(file + '.new', file);
    expect(store.current()).toBeUndefined();
    expect(store.status().problem).toMatch(/not the one/);
    // A fresh install with nothing there yet is not a problem.
    rmSync(state, { recursive: true });
    expect((await open()).status()).toEqual({ pinned: false });
  });

  it('rejects a key that others can read', async () => {
    const store = await open();
    await store.write(PIN);
    writeFileSync(keyFile + '.new', readFileSync(keyFile), { mode: 0o644 });
    renameSync(keyFile + '.new', keyFile);
    expect((await open()).current()).toBeUndefined();
    expect(store.current()).toEqual(PIN);
  });

  for (const platform of ['linux', 'darwin'] as const) {
    it(`clears the immutable flag only around its own writes (${platform})`, async () => {
      const sys = new Flags(platform);
      const store = await open(sys);
      const [clear, set] = platform === 'linux' ? ['-i', '+i'] : ['nouchg', 'uchg'];
      const bin = platform === 'linux' ? 'chattr' : 'chflags';
      // The key is new: flagged once written, nothing to clear.
      expect(sys.runs.map((r) => [r.bin, ...r.args])).toEqual([[bin, set, keyFile]]);
      expect([...sys.immutable]).toEqual([keyFile]);
      sys.runs = [];
      await store.write(OTHER);
      await store.write(PIN);
      expect(sys.runs.map((r) => [r.args[0], r.args[1]])).toEqual([
        [set, file],
        [clear, file],
        [set, file],
      ]);
      // Cleared while the old pin was still there, set once the new one was.
      expect(sys.runs[1]!.held).toContain(OTHER.cdhash);
      expect(sys.runs[2]!.held).toContain(PIN.cdhash);
      expect(sys.immutable).toEqual(new Set([keyFile, file]));
      // Reading, checking and status never touch the flag.
      sys.runs = [];
      store.current();
      store.status();
      await store.intact();
      await open(sys);
      expect(sys.runs).toEqual([]);
    });
  }
});

describe('one queue for the pin', () => {
  it('ends with the new pin when a repair races a write', async () => {
    const sys = new Flags('linux');
    const store = await open(sys);
    await store.write(OTHER);
    // The file goes away, so the repair has something to do.
    rmSync(file);
    // The write is slowed in its flag step, where the old code let a repair read the old pin.
    sys.delay = 30;
    const writing = store.write(PIN);
    const repairing = store.repair();
    await Promise.all([writing, repairing]);
    expect(store.current()).toEqual(PIN);
    expect((await open()).current()).toEqual(PIN);
    // And a repair queued after a "no pin" writes no pin, not the one before it.
    rmSync(file);
    const none = store.write(undefined);
    const again = store.repair();
    await Promise.all([none, again]);
    expect(store.current()).toBeUndefined();
    expect((await open()).status()).toEqual({ pinned: false });
  });

  it('keeps the old pin in memory until a write is in place and flagged', async () => {
    const sys = new Flags('linux');
    const store = await open(sys);
    await store.write(OTHER);
    let seenDuring: AppPin | undefined;
    sys.during = (args) => {
      if (args[0] === '+i' && args[1] === file) seenDuring = store.current();
    };
    await store.write(PIN);
    expect(seenDuring).toEqual(OTHER);
    expect(store.current()).toEqual(PIN);
  });

  it('writes a readable copy for the app, never read back', async () => {
    const publicFile = join(root, 'app-pin.json');
    const store = new AppPinStore(new Flags('linux') as unknown as System, {
      dir: state,
      publicFile,
      ownerUid: process.getuid!(),
    });
    await store.load();
    await store.write(PIN);
    expect(JSON.parse(readFileSync(publicFile, 'utf8'))).toEqual(PIN);
    expect(statSync(publicFile).mode & 0o777).toBe(0o644);
    expect(statSync(state).mode & 0o777).toBe(0o700);
    writeFileSync(publicFile, JSON.stringify(OTHER));
    expect(store.current()).toEqual(PIN);
  });
});

describe('the tripwire on moves', () => {
  const qopts = (
    store: AppPinStore,
    extra: Partial<QuarantineOptions> = {},
  ): QuarantineOptions => ({
    quarantineDir: join(root, 'Quarantine'),
    platform: 'linux',
    protectedPrefixes: [],
    protectedExact: new Set(),
    guard: () => store.intact(),
    log: (m) => logs.push(m),
    ...extra,
  });
  let logs: string[];
  beforeEach(() => {
    logs = [];
  });

  it('waits for a pin write in flight instead of tripping on it', async () => {
    const sys = new Flags('linux');
    const store = await open(sys);
    await store.write(OTHER);
    const home = join(root, 'home');
    mkdirSync(home);
    writeFileSync(join(home, 'evil'), 'x');
    sys.delay = 30;
    const writing = store.write(PIN);
    const rec = await quarantine(new FakeLinuxSystem(), join(home, 'evil'), 'q1', qopts(store));
    await writing;
    expect(existsSync(join(home, 'evil'))).toBe(false);
    expect(existsSync(rec.storedPath)).toBe(true);
    expect(store.current()).toEqual(PIN);
    expect(logs).toEqual([]);
  });

  it('refuses and logs, and moves nothing back, when a kept file changed', async () => {
    const store = await open();
    await store.write(PIN);
    const home = join(root, 'home');
    mkdirSync(home);
    writeFileSync(join(home, 'evil'), 'x');
    // Before the move: nothing moves.
    rmSync(file);
    await expect(
      quarantine(new FakeLinuxSystem(), join(home, 'evil'), 'q1', qopts(store)),
    ).rejects.toMatchObject({ code: 'refused' });
    expect(readFileSync(join(home, 'evil'), 'utf8')).toBe('x');
    expect(existsSync(file)).toBe(false);
    // During the move: the item stays in quarantine, and nothing is put back or rewritten.
    await store.repair();
    let calls = 0;
    const guard = async () => ++calls === 1;
    await expect(
      quarantine(new FakeLinuxSystem(), join(home, 'evil'), 'q2', qopts(store, { guard })),
    ).rejects.toMatchObject({ code: 'failed', message: expect.stringMatching(/in quarantine/) });
    expect(existsSync(join(home, 'evil'))).toBe(false);
    expect(existsSync(join(root, 'Quarantine', 'q2', 'evil'))).toBe(true);
    expect(logs).toHaveLength(2);
  });
});
