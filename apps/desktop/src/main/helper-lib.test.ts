import { spawn, spawnSync } from 'node:child_process';
import {
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  readlinkSync,
  statSync,
  symlinkSync,
  utimesSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

// The install scripts' shared lock, version switch and pruning (helper/lib.sh),
// run under /bin/sh against a temporary folder in place of the real one. The
// scripts themselves need root, launchd or systemd, so they run in CI's Linux
// integration test instead.

const helper = join(import.meta.dirname, '..', '..', 'helper');
const LIB = join(helper, 'lib.sh');
const root = process.getuid?.() === 0;
const group = spawnSync('id', ['-gn'], { encoding: 'utf8' }).stdout.trim();

/** The script prologue: lib.sh with this test's folder and settings. */
const prologue = `set -eu
. "${LIB}"
DEST=$1
VH_GROUP=${group}
VH_CHOWN=${root ? 1 : 0}
VH_LOCK_TIMEOUT=\${T:-20}
VH_LOCK_GRACE=\${G:-10}
`;

/** The steps install.sh takes, without the service manager. */
const INSTALL = `${prologue}
vh_lock_acquire
echo "start $TAG" >>"$LOG"
vh_prepare
vh_build "$SRC/node" "$SRC/helper.mjs"
[ -z "\${PAUSE:-}" ] || sleep "$PAUSE" </dev/null >/dev/null 2>&1
vh_current
PREVIOUS=$VH_CURRENT
[ -n "$PREVIOUS" ] || vh_switch "$VH_VERSION"
vh_lock_check
vh_put 755 "$SRC/vigil-helper" "$(dirname "$DEST")/vigil-helper"
vh_switch "$VH_VERSION"
[ -z "\${AFTER_SWITCH:-}" ] || eval "$AFTER_SWITCH"
vh_finish "$PREVIOUS"
echo "end $TAG" >>"$LOG"
`;

interface World {
  base: string;
  dest: string;
  log: string;
  /** A bundle whose node and helper.mjs both carry `tag`. */
  bundle: (tag: string) => string;
}

function world(): World {
  const base = mkdtempSync(join(tmpdir(), 'vigil-lib-'));
  const tools = join(base, 'tools');
  mkdirSync(tools);
  return {
    base,
    dest: join(tools, 'vigil-helper.d'),
    log: join(base, 'log'),
    bundle: (tag) => {
      const src = join(base, `src-${tag}`);
      mkdirSync(src, { recursive: true });
      writeFileSync(join(src, 'node'), `node ${tag}\n`);
      writeFileSync(join(src, 'helper.mjs'), `helper ${tag}\n`);
      writeFileSync(join(src, 'vigil-helper'), '#!/bin/sh\n');
      return src;
    },
  };
}

type Env = Record<string, string>;

const envFor = (w: World, tag: string, env: Env = {}) => ({
  ...process.env,
  SRC: w.bundle(tag),
  TAG: tag,
  LOG: w.log,
  ...env,
});

function install(w: World, tag: string, env: Env = {}) {
  return spawnSync('/bin/sh', ['-c', INSTALL, 'install', w.dest], {
    encoding: 'utf8',
    env: envFor(w, tag, env),
  });
}

function installAsync(w: World, tag: string, env: Env = {}) {
  // Its own process group, so a signal can reach it and the command it waits on.
  const child = spawn('/bin/sh', ['-c', INSTALL, 'install', w.dest], {
    env: envFor(w, tag, env),
    stdio: ['ignore', 'ignore', 'pipe'],
    detached: true,
  });
  let stderr = '';
  child.stderr.on('data', (d) => (stderr += String(d)));
  const done = new Promise<{ code: number | null; signal: string | null; stderr: string }>(
    (resolve) => child.on('close', (code, signal) => resolve({ code, signal, stderr })),
  );
  return { child, done };
}

/** Run lib.sh with a script body, as a real script would. */
function lib(w: World, body: string, env: Env = {}) {
  return spawnSync('/bin/sh', ['-c', `${prologue}${body}`, 'lib', w.dest], {
    encoding: 'utf8',
    env: { ...process.env, ...env },
  });
}

/** The tag of the version `current` points to, after checking it is complete and unmixed. */
function current(w: World): string {
  const link = readlinkSync(join(w.dest, 'current'));
  expect(link).toMatch(/^versions\/[^/]+$/);
  const node = readFileSync(join(w.dest, link, 'node'), 'utf8')
    .trim()
    .replace(/^node /, '');
  const mjs = readFileSync(join(w.dest, link, 'helper.mjs'), 'utf8')
    .trim()
    .replace(/^helper /, '');
  expect(node).toBe(mjs);
  return mjs;
}

const versions = (w: World) => readdirSync(join(w.dest, 'versions')).sort();
const lock = (w: World) => `${w.dest}.lock`;
const bootId = () => readFileSync('/proc/sys/kernel/random/boot_id', 'utf8').trim();
const startOf = (w: World, pid: number) => lib(w, `vh_proc_start ${pid}`).stdout.trim();

function plantLock(w: World, owner: string) {
  mkdirSync(lock(w));
  writeFileSync(join(lock(w), 'owner'), owner);
}

function deadPid(): number {
  const p = spawnSync('/bin/true');
  return p.pid!;
}

describe.skipIf(process.platform !== 'linux')('helper lib.sh (versioned install)', () => {
  it('passes sh -n, and shellcheck when it is installed', () => {
    const scripts = [
      'lib.sh',
      'install.sh',
      'uninstall.sh',
      'vigil-helper',
      'linux/install.sh',
      'linux/uninstall.sh',
      'linux/vigil-helper',
    ].map((f) => join(helper, f));
    for (const f of scripts) {
      const r = spawnSync('/bin/sh', ['-n', f], { encoding: 'utf8' });
      expect(r.status, `${f}: ${r.stderr}`).toBe(0);
    }
    const sc = spawnSync('shellcheck', ['--version']);
    if (sc.status === 0) {
      const r = spawnSync('shellcheck', ['-x', '-s', 'sh', ...scripts], {
        encoding: 'utf8',
        cwd: helper,
      });
      expect(r.status, r.stdout).toBe(0);
    }
  });

  it('installs fresh: one complete, root-owned version behind current', () => {
    const w = world();
    const r = install(w, 'a');
    expect(r.status, r.stderr).toBe(0);
    expect(current(w)).toBe('a');
    expect(lstatSync(join(w.dest, 'current')).isSymbolicLink()).toBe(true);
    const [v] = versions(w);
    expect(versions(w)).toHaveLength(1);
    const dir = join(w.dest, 'versions', v!);
    expect(statSync(dir).mode & 0o777).toBe(0o755);
    expect(statSync(join(dir, 'node')).mode & 0o777).toBe(0o755);
    expect(statSync(join(dir, 'helper.mjs')).mode & 0o777).toBe(0o644);
    expect(statSync(join(w.base, 'tools', 'vigil-helper')).mode & 0o777).toBe(0o755);
    if (root) expect(statSync(join(dir, 'node')).uid).toBe(0);
    expect(existsSync(lock(w))).toBe(false);
    expect(readdirSync(w.dest).sort()).toEqual(['current', 'versions']);
  });

  it('upgrades the layout from before versions, keeping it until after the switch', () => {
    const w = world();
    mkdirSync(w.dest);
    writeFileSync(join(w.dest, 'node'), 'old node\n');
    writeFileSync(join(w.dest, 'helper.mjs'), 'old helper\n');
    mkdirSync(`${w.dest}.new`);
    writeFileSync(join(`${w.dest}.new`, 'node'), 'half-copied\n');
    const r = install(w, 'b', {
      // The old helper keeps running from these files until the restart.
      AFTER_SWITCH: '[ -f "$DEST/node" ] && [ -f "$DEST/helper.mjs" ] && echo old-kept',
    });
    expect(r.status, r.stderr).toBe(0);
    expect(r.stdout).toContain('old-kept');
    expect(current(w)).toBe('b');
    expect(existsSync(join(w.dest, 'node'))).toBe(false);
    expect(existsSync(join(w.dest, 'helper.mjs'))).toBe(false);
    expect(existsSync(`${w.dest}.new`)).toBe(false);
    expect(readdirSync(w.dest).sort()).toEqual(['current', 'versions']);
  });

  it('serializes overlapping runs; current always names one complete version', async () => {
    const w = world();
    expect(install(w, 'first').status).toBe(0);
    const tags = ['p', 'q', 'r', 's'];
    const runs = tags.map((t) => installAsync(w, t, { PAUSE: '0.3' }));
    const seen = new Set<string>();
    let checks = 0;
    const watcher = setInterval(() => {
      // current is never missing and never points at a partial or mixed version.
      seen.add(current(w));
      checks++;
    }, 5);
    const results = await Promise.all(runs.map((r) => r.done));
    clearInterval(watcher);
    for (const r of results) expect(r.code, r.stderr).toBe(0);
    expect(checks).toBeGreaterThan(10);
    expect(tags).toContain(current(w));
    for (const t of seen) expect(['first', ...tags]).toContain(t);
    // Each run finished before the next started.
    const lines = readFileSync(w.log, 'utf8').trim().split('\n').slice(2);
    expect(lines).toHaveLength(8);
    for (let i = 0; i < lines.length; i += 2) {
      expect(lines[i]).toMatch(/^start /);
      expect(lines[i + 1]).toBe(lines[i]!.replace('start', 'end'));
    }
    expect(versions(w)).toHaveLength(2);
    expect(existsSync(lock(w))).toBe(false);
  });

  it('takes over a lock whose process is gone or from before the last boot', () => {
    const w = world();
    plantLock(w, `boot=${bootId()}\npid=${deadPid()}\nstart=12345\n`);
    let r = install(w, 'a', { T: '3' });
    expect(r.status, r.stderr).toBe(0);
    expect(existsSync(lock(w))).toBe(false);

    // A live pid, but the lock was written before a reboot.
    const old = `boot=00000000-0000-0000-0000-000000000000\npid=${process.pid}\nstart=${startOf(w, process.pid)}\n`;
    plantLock(w, old);
    r = install(w, 'b', { T: '3' });
    expect(r.status, r.stderr).toBe(0);
    // A live pid that was reused: its start time differs.
    plantLock(w, `boot=${bootId()}\npid=${process.pid}\nstart=1\n`);
    r = install(w, 'c', { T: '3' });
    expect(r.status, r.stderr).toBe(0);
    expect(current(w)).toBe('c');
    expect(readdirSync(join(w.base, 'tools')).filter((f) => f.includes('.lock'))).toEqual([]);
  });

  it('puts back a lock another run took between finding it stale and renaming it', () => {
    const w = world();
    plantLock(w, `boot=${bootId()}\npid=${deadPid()}\nstart=1\n`);
    // Another run removes the stale lock and takes its own right after this one
    // has judged the old one stale.
    const r = lib(
      w,
      `VH_LOCK=$DEST.lock
vh_owner_stale() {
  rm -rf "$VH_LOCK"; mkdir "$VH_LOCK"; printf 'theirs' >"$VH_LOCK/owner"
}
vh_lock_takeover
cat "$VH_LOCK/owner"
`,
    );
    expect(r.status, r.stderr).toBe(0);
    expect(r.stdout).toBe('theirs');
    expect(readdirSync(join(w.base, 'tools')).filter((f) => f.includes('.stale'))).toEqual([]);
  });

  it('leaves an empty owner file alone during the grace period, then takes over', () => {
    const w = world();
    plantLock(w, '');
    let r = install(w, 'a', { T: '1', G: '10' });
    expect(r.status).not.toBe(0);
    expect(r.stderr).toContain('is still running after 1s');
    expect(existsSync(join(lock(w), 'owner'))).toBe(true);
    expect(existsSync(join(w.dest, 'current'))).toBe(false);

    const past = new Date(Date.now() - 60_000);
    utimesSync(join(lock(w), 'owner'), past, past);
    utimesSync(lock(w), past, past);
    r = install(w, 'a', { T: '3', G: '10' });
    expect(r.status, r.stderr).toBe(0);
    expect(current(w)).toBe('a');

    // No owner file at all counts the same, by the lock's own age.
    mkdirSync(lock(w));
    utimesSync(lock(w), past, past);
    expect(install(w, 'b', { T: '3' }).status).toBe(0);
  });

  it("waits for a live owner, then gives up with a clear error and doesn't touch its lock", () => {
    const w = world();
    expect(install(w, 'a').status).toBe(0);
    const sleeper = spawn('sleep', ['30']);
    try {
      const owner = `boot=${bootId()}\npid=${sleeper.pid}\nstart=${startOf(w, sleeper.pid!)}\n`;
      expect(owner).toMatch(/start=\d+/);
      plantLock(w, owner);
      const t0 = Date.now();
      // date +%s counts whole seconds, so a 3 s timeout waits more than 2 s.
      const r = install(w, 'b', { T: '3' });
      expect(Date.now() - t0).toBeGreaterThanOrEqual(1900);
      expect(r.status).not.toBe(0);
      expect(r.stderr).toContain(`Vigil helper (process ${sleeper.pid}) is still running after 3s`);
      expect(readFileSync(join(lock(w), 'owner'), 'utf8')).toBe(owner);
      expect(current(w)).toBe('a');
      expect(versions(w)).toHaveLength(1);
    } finally {
      sleeper.kill();
    }
  });

  it('recovers from a run killed mid-build; current stays on the old version', async () => {
    const w = world();
    expect(install(w, 'a').status).toBe(0);
    const killed = installAsync(w, 'b', { PAUSE: '30' });
    // Wait until it holds the lock and has written its version.
    for (let i = 0; i < 200 && versions(w).length < 2; i++)
      await new Promise((r) => setTimeout(r, 25));
    expect(versions(w)).toHaveLength(2);
    killed.child.kill('SIGKILL');
    expect((await killed.done).signal).toBe('SIGKILL');
    expect(existsSync(lock(w))).toBe(true);
    expect(current(w)).toBe('a');

    const r = install(w, 'c', { T: '3' });
    expect(r.status, r.stderr).toBe(0);
    expect(current(w)).toBe('c');
    // The half-done version is gone; the one before is kept.
    expect(versions(w)).toHaveLength(2);
    const kept = versions(w).map((v) =>
      readFileSync(join(w.dest, 'versions', v, 'helper.mjs'), 'utf8'),
    );
    expect(kept.sort()).toEqual(['helper a\n', 'helper c\n']);
    expect(existsSync(lock(w))).toBe(false);
  });

  it('releases its lock when stopped with a signal', async () => {
    const w = world();
    const run = installAsync(w, 'a', { PAUSE: '30' });
    for (let i = 0; i < 200 && !existsSync(join(lock(w), 'owner')); i++)
      await new Promise((r) => setTimeout(r, 25));
    expect(existsSync(join(lock(w), 'owner'))).toBe(true);
    // Let it reach the pause, then stop it the way Ctrl-C or the app would.
    await new Promise((r) => setTimeout(r, 300));
    process.kill(-run.child.pid!, 'SIGTERM');
    const done = await run.done;
    expect(done.code).toBe(143);
    expect(existsSync(lock(w))).toBe(false);
  });

  it('releases only its own lock', () => {
    const w = world();
    const r = lib(
      w,
      `vh_lock_acquire
printf 'boot=x\\npid=1\\nstart=1\\n' >"$DEST.lock/owner"
`,
    );
    expect(r.status, r.stderr).toBe(0);
    expect(readFileSync(join(lock(w), 'owner'), 'utf8')).toBe('boot=x\npid=1\nstart=1\n');
  });

  it('keeps current and the version before it, and never follows symlinks while pruning', () => {
    const w = world();
    for (const t of ['a', 'b', 'c']) expect(install(w, t).status).toBe(0);
    const tags = () =>
      versions(w).map((v) => readFileSync(join(w.dest, 'versions', v, 'helper.mjs'), 'utf8'));
    expect(tags().sort()).toEqual(['helper b\n', 'helper c\n']);

    const outside = join(w.base, 'outside');
    mkdirSync(outside);
    writeFileSync(join(outside, 'keep'), 'precious');
    writeFileSync(join(outside, 'helper.mjs'), 'not a version');
    symlinkSync(outside, join(w.dest, 'versions', 'planted'));
    symlinkSync(outside, join(w.dest, 'versions', '.hidden'));
    writeFileSync(join(w.dest, 'versions', 'stray-file'), 'x');

    expect(install(w, 'd').status).toBe(0);
    expect(current(w)).toBe('d');
    expect(readFileSync(join(outside, 'keep'), 'utf8')).toBe('precious');
    // c, the one before d, stays; b is gone, and so are the links and the stray file.
    expect(tags().sort()).toEqual(['helper c\n', 'helper d\n']);
  });

  it('never removes the version current points to, even when told to keep another', () => {
    const w = world();
    expect(install(w, 'a').status).toBe(0);
    const r = lib(w, 'vh_lock_acquire\nvh_finish does-not-exist\n');
    expect(r.status, r.stderr).toBe(0);
    expect(current(w)).toBe('a');
  });

  it('refuses to switch to a version that is incomplete or a symlink', () => {
    const w = world();
    expect(install(w, 'a').status).toBe(0);
    mkdirSync(join(w.dest, 'versions', 'partial'));
    writeFileSync(join(w.dest, 'versions', 'partial', 'node'), 'node x');
    symlinkSync(join(w.dest, 'versions', versions(w)[0]!), join(w.dest, 'versions', 'link'));
    for (const v of ['partial', 'link', '../x', '']) {
      const r = lib(w, `vh_lock_acquire\nvh_switch '${v}'\n`);
      expect(r.status, v).not.toBe(0);
    }
    expect(current(w)).toBe('a');
  });

  it('removes everything on uninstall without following symlinks', () => {
    const w = world();
    expect(install(w, 'a').status).toBe(0);
    expect(install(w, 'b').status).toBe(0);
    const outside = join(w.base, 'outside');
    mkdirSync(outside);
    writeFileSync(join(outside, 'keep'), 'precious');
    symlinkSync(outside, join(w.dest, 'versions', 'planted'));
    mkdirSync(`${w.dest}.new`);
    mkdirSync(`${w.dest}.old`);
    const r = lib(w, 'vh_lock_acquire\nvh_remove_dest\n');
    expect(r.status, r.stderr).toBe(0);
    expect(existsSync(w.dest)).toBe(false);
    expect(existsSync(`${w.dest}.new`)).toBe(false);
    expect(existsSync(`${w.dest}.old`)).toBe(false);
    expect(existsSync(lock(w))).toBe(false);
    expect(readFileSync(join(outside, 'keep'), 'utf8')).toBe('precious');
  });

  it('makes uninstall wait for an install that is still running', async () => {
    const w = world();
    const run = installAsync(w, 'a', { PAUSE: '1' });
    for (let i = 0; i < 200 && !existsSync(join(lock(w), 'owner')); i++)
      await new Promise((r) => setTimeout(r, 25));
    const r = lib(w, 'vh_lock_acquire\nvh_remove_dest\n');
    expect(r.status, r.stderr).toBe(0);
    expect((await run.done).code).toBe(0);
    // The install finished first, then the removal took everything it wrote.
    expect(existsSync(w.dest)).toBe(false);
  });
});
