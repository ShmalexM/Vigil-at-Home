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
import { RuleStore } from '@vigil/sensors';
import type { AppPin } from './appPin.js';
import { Approvals } from './approval.js';
import {
  GuardTripped,
  quarantine,
  restore,
  type QuarantineOptions,
} from './commands/quarantine.js';
import { Executor } from './executor.js';
import { Journal } from './journal.js';
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
  async run(bin: BinaryName, args: string[]): Promise<RunResult> {
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
  state = join(root, 'state');
  mkdirSync(state);
  file = join(state, 'app-pin.json');
  keyFile = join(state, 'app-pin.key');
});
afterEach(() => rmSync(root, { recursive: true, force: true }));

const open = async (sys: Flags | System = new Flags('linux')) => {
  const store = new AppPinStore(sys as System, { file, keyFile, ownerUid: process.getuid!() });
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
    mkdirSync(state);
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
      store.guarded();
      await open(sys);
      expect(sys.runs).toEqual([]);
    });
  }
});

describe('a move that takes a file the helper keeps', () => {
  const opts = (store: AppPinStore): QuarantineOptions => ({
    quarantineDir: join(root, 'Quarantine'),
    platform: 'linux',
    protectedPrefixes: [],
    protectedExact: new Set(),
    // The state folder is deliberately left out, as if reached by another path.
    guarded: () => store.guarded(),
  });

  it('is undone and refused when it moved the folder holding them', async () => {
    const store = await open();
    await store.write(PIN);
    expect(() => quarantine(state, 'q1', opts(store))).toThrow(GuardTripped);
    expect(store.current()).toEqual(PIN);
    expect(store.status().problem).toBeUndefined();
    expect(existsSync(join(root, 'Quarantine', 'q1'))).toBe(false);
  });

  it('is undone and refused when what moved is a link to one of them', async () => {
    const store = await open();
    await store.write(PIN);
    const home = join(root, 'home');
    mkdirSync(home);
    linkSync(keyFile, join(home, 'notes.txt'));
    expect(() => quarantine(join(home, 'notes.txt'), 'q2', opts(store))).toThrow(GuardTripped);
    expect(existsSync(join(home, 'notes.txt'))).toBe(true);
    // An ordinary file still goes.
    writeFileSync(join(home, 'evil'), 'x');
    expect(quarantine(join(home, 'evil'), 'q3', opts(store)).storedPath).toContain('q3');
  });

  it('is undone and refused on restore', async () => {
    const store = await open();
    await store.write(PIN);
    const slot = join(root, 'Quarantine', 'q4');
    mkdirSync(slot, { recursive: true });
    linkSync(file, join(slot, 'x'));
    const rec = {
      originalPath: join(root, 'x'),
      storedPath: join(slot, 'x'),
      mode: 0o644,
      uid: process.getuid!(),
      gid: process.getgid!(),
      isDirectory: false,
    };
    expect(() => restore(rec, store.guarded())).toThrow(GuardTripped);
    expect(existsSync(rec.originalPath)).toBe(false);
    expect(existsSync(rec.storedPath)).toBe(true);
  });

  it('is refused by the executor, which keeps its pin', async () => {
    const sys = new FakeLinuxSystem();
    const store = await open(new Flags('linux'));
    await store.write(PIN);
    const ex = new Executor({
      sys,
      journal: new Journal(join(root, 'journal.json')),
      approvals: new Approvals({
        dir: join(root, 'approvals'),
        requiredOwnerUid: process.getuid!(),
      }),
      rules: new RuleStore(join(root, 'rules.json')),
      quarantine: {
        quarantineDir: join(root, 'Quarantine'),
        protectedPrefixes: [],
        protectedExact: new Set(),
      },
      syncPort: 47821,
      appPin: store,
    });
    await expect(ex.execute({ kind: 'file.quarantine', path: state })).rejects.toMatchObject({
      code: 'refused',
    });
    expect(existsSync(file)).toBe(true);
    expect(store.current()).toEqual(PIN);
    expect(store.status().problem).toBeUndefined();
  });
});
