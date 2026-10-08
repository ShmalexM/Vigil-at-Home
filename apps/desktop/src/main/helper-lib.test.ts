import { spawn, spawnSync } from 'node:child_process';
import {
  existsSync,
  lstatSync,
  lutimesSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  readlinkSync,
  rmSync,
  statSync,
  symlinkSync,
  utimesSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

// The install scripts' version switch and pruning (helper/lib.sh), run under
// /bin/sh against a temporary folder in place of the real one. The scripts
// themselves need root, launchd or systemd, so they run in CI's Linux
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
`;

/** The steps install.sh takes, without the service manager. */
const INSTALL = `${prologue}
echo "start $TAG" >>"$LOG"
vh_prepare
# Wait for the go-ahead, so runs can be started at the same moment.
while [ -n "\${GO:-}" ] && [ ! -e "$GO" ]; do sleep 0.01; done
vh_build "$SRC/node" "$SRC/helper.mjs"
[ -z "\${PAUSE:-}" ] || sleep "$PAUSE" </dev/null >/dev/null 2>&1
vh_current
[ -n "$VH_CURRENT" ] || vh_switch "$VH_VERSION"
vh_put 755 "$SRC/vigil-helper" "$(dirname "$DEST")/vigil-helper"
vh_switch "$VH_VERSION"
[ -z "\${AFTER_SWITCH:-}" ] || eval "$AFTER_SWITCH"
vh_finish
echo "end $TAG $VH_VERSION" >>"$LOG"
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
const versionDir = (w: World, v: string) => join(w.dest, 'versions', v);
/** The tag a complete version was built from. */
const tagOf = (w: World, v: string) =>
  readFileSync(join(versionDir(w, v), 'helper.mjs'), 'utf8')
    .trim()
    .replace(/^helper /, '');
/** The version each tag's run built, from the log. */
function built(w: World): Record<string, string> {
  const out: Record<string, string> = {};
  for (const line of readFileSync(w.log, 'utf8').trim().split('\n')) {
    const [what, tag, v] = line.split(' ');
    if (what === 'end') out[tag!] = v!;
  }
  return out;
}

const twoHoursAgo = () => new Date(Date.now() - 2 * 3600_000);
/** Make paths look last changed two hours ago (a symlink's own time, not its target's). */
function age(...paths: string[]) {
  const past = twoHoursAgo();
  for (const p of paths) {
    if (lstatSync(p).isSymbolicLink()) lutimesSync(p, past, past);
    else utimesSync(p, past, past);
  }
}

const switchTo = (w: World, v: string) => {
  const r = lib(w, `vh_switch '${v}'\n`);
  expect(r.status, r.stderr).toBe(0);
};

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
    // The time (UTC), this run's pid and random letters.
    expect(v).toMatch(/^\d{14}\.\d+\.[A-Za-z0-9]{6}$/);
    const dir = versionDir(w, v!);
    expect(statSync(dir).mode & 0o777).toBe(0o755);
    expect(statSync(join(dir, 'node')).mode & 0o777).toBe(0o755);
    expect(statSync(join(dir, 'helper.mjs')).mode & 0o777).toBe(0o644);
    expect(readdirSync(dir).sort()).toEqual(['helper.mjs', 'node']);
    expect(statSync(join(w.base, 'tools', 'vigil-helper')).mode & 0o777).toBe(0o755);
    if (root) expect(statSync(join(dir, 'node')).uid).toBe(0);
    expect(readdirSync(w.dest).sort()).toEqual(['current', 'versions']);
    expect(readdirSync(join(w.base, 'tools')).sort()).toEqual(['vigil-helper', 'vigil-helper.d']);
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

  it('gives each run its own version, even two in the same second', () => {
    const w = world();
    const src = w.bundle('x');
    const r = lib(
      w,
      `vh_prepare
vh_build "${src}/node" "${src}/helper.mjs"; a=$VH_VERSION
vh_build "${src}/node" "${src}/helper.mjs"; b=$VH_VERSION
echo "$a $b"
`,
    );
    expect(r.status, r.stderr).toBe(0);
    const [a, b] = r.stdout.trim().split(' ');
    expect(a).not.toBe(b);
    expect(versions(w)).toEqual([a, b].sort());
  });

  it('lets overlapping runs all finish; current always names one complete version', async () => {
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
    // They did overlap: every run started before the first one ended.
    const lines = readFileSync(w.log, 'utf8').trim().split('\n').slice(2);
    expect(lines.slice(0, 4).every((l) => l.startsWith('start '))).toBe(true);
    // Every version is under an hour old, so all are kept, each complete.
    expect(versions(w)).toHaveLength(5);
    expect(
      versions(w)
        .map((v) => tagOf(w, v))
        .sort(),
    ).toEqual(['first', ...tags].sort());
  });

  it('two installs at the same moment both succeed, and current names a complete version', async () => {
    const w = world();
    for (let round = 0; round < 5; round++) {
      const go = join(w.base, `go-${round}`);
      const pair = [`x${round}`, `y${round}`];
      const runs = pair.map((t) => installAsync(w, t, { GO: go }));
      // Both are waiting at the go-ahead; release them together.
      await new Promise((r) => setTimeout(r, 100));
      writeFileSync(go, '');
      const results = await Promise.all(runs.map((r) => r.done));
      for (const r of results) expect(r.code, r.stderr).toBe(0);
      expect(pair).toContain(current(w));
      const target = readlinkSync(join(w.dest, 'current')).replace(/^versions\//, '');
      expect(versions(w)).toContain(target);
      // Each run built and kept its own complete version.
      const ids = built(w);
      expect(ids[pair[0]!]).not.toBe(ids[pair[1]!]);
      for (const t of pair) expect(tagOf(w, ids[t]!)).toBe(t);
    }
    expect(versions(w)).toHaveLength(10);
    expect(readdirSync(w.dest).sort()).toEqual(['current', 'versions']);
  });

  it('recovers from a run killed mid-install; current stays on the old version', async () => {
    const w = world();
    expect(install(w, 'a').status).toBe(0);
    const killed = installAsync(w, 'b', { PAUSE: '30' });
    // Wait until it has written its version in full, then kill it before the switch.
    const complete = () =>
      versions(w).filter((v) => existsSync(join(versionDir(w, v), 'helper.mjs'))).length;
    for (let i = 0; i < 200 && complete() < 2; i++) await new Promise((r) => setTimeout(r, 25));
    expect(complete()).toBe(2);
    process.kill(-killed.child.pid!, 'SIGKILL');
    expect((await killed.done).signal).toBe('SIGKILL');
    expect(current(w)).toBe('a');

    // Nothing is left to wait for or clear up: the next run just goes ahead.
    let r = install(w, 'c');
    expect(r.status, r.stderr).toBe(0);
    expect(current(w)).toBe('c');
    // The killed run's version is under an hour old, so it is kept for now.
    expect(
      versions(w)
        .map((v) => tagOf(w, v))
        .sort(),
    ).toEqual(['a', 'b', 'c']);

    // An hour on, the next run keeps only the two newest complete versions
    // (by name, which starts with the time; the order within one second is
    // arbitrary) and current, which is d.
    for (const v of versions(w)) age(versionDir(w, v));
    const before = versions(w);
    r = install(w, 'd');
    expect(r.status, r.stderr).toBe(0);
    expect(current(w)).toBe('d');
    const d = built(w)['d']!;
    const kept = new Set([...[...before, d].sort().slice(-2), d]);
    expect(versions(w)).toEqual([...kept].sort());
  });

  it('prunes only versions that are old, not among the newest two, and not current', () => {
    const w = world();
    for (const t of ['a', 'b', 'c', 'd', 'e']) expect(install(w, t).status).toBe(0);
    // By name, which starts with the time: v0 is the oldest, v4 the newest.
    const [v0, v1, v2, v3, v4] = versions(w);
    // current points at the oldest, as after going back to it.
    switchTo(w, v0!);
    // Incomplete folders: one old, left by a run that was stopped, and one
    // young that sorts newest, as another run still writing would.
    const oldPartial = '20200101000000.1.oldold';
    const youngPartial = '29990101000000.1.young';
    for (const p of [oldPartial, youngPartial]) {
      mkdirSync(versionDir(w, p));
      writeFileSync(join(versionDir(w, p), 'node'), 'node partial\n');
    }
    // Everything is old except v2 and the young partial one.
    for (const v of versions(w)) if (v !== v2 && v !== youngPartial) age(versionDir(w, v));

    const r = lib(w, 'vh_finish\n');
    expect(r.status, r.stderr).toBe(0);
    // v0 is current, v2 is young, v3 and v4 are the newest two complete ones
    // (the young partial one doesn't count, being incomplete, and is kept as
    // it may still be being written). v1 and the old partial one go.
    expect(versions(w)).toEqual([v0, v2, v3, v4, youngPartial].sort());
    expect(existsSync(versionDir(w, v1!))).toBe(false);
    const target = readlinkSync(join(w.dest, 'current'));
    expect(target).toBe(`versions/${v0}`);
    expect(tagOf(w, v0!)).toBe(current(w));
  });

  it('keeps the version current named just before this run switched away from it', () => {
    const w = world();
    for (const t of ['v0', 'v1']) expect(install(w, t).status).toBe(0);
    const ids = built(w);
    // V0 is current and old (as after going back to it), V1 a complete leftover.
    switchTo(w, ids['v0']!);
    for (const v of versions(w)) age(versionDir(w, v));
    // V2 installs: V1 and V2 are the newest two, and V0 is neither young nor
    // current any more, but a launcher may have read current=V0 just before
    // the switch and be about to run it.
    const r = install(w, 'v2');
    expect(r.status, r.stderr).toBe(0);
    expect(current(w)).toBe('v2');
    expect(versions(w)).toEqual([ids['v0'], ids['v1'], built(w)['v2']].sort());
    // The next run, which switched away from V2 instead, lets V0 go.
    for (const v of versions(w)) age(versionDir(w, v));
    expect(install(w, 'v3').status).toBe(0);
    expect(versions(w)).not.toContain(ids['v0']);
  });

  it('reads current again right before each removal', () => {
    const w = world();
    for (const t of ['a', 'b', 'c', 'd', 'e']) expect(install(w, t).status).toBe(0);
    for (const v of versions(w)) age(versionDir(w, v));
    const all = versions(w);
    // All old; the three oldest by name are not among the newest two.
    const candidates = all.slice(0, 3);
    // Another run switches current to another of them just as the first of
    // them is being removed, whichever that is.
    const r = lib(
      w,
      `vh_remove() {
  _n=\${1##*/}
  case " ${candidates.join(' ')} " in *" $_n "*)
    if [ ! -e "$DEST/.switched" ]; then
      for _o in ${candidates.join(' ')}; do [ "$_o" = "$_n" ] || break; done
      echo "$_o" >"$DEST/.switched"
      ln -s "versions/$_o" "$DEST/.switch"; mv -fT "$DEST/.switch" "$DEST/current"
    fi ;;
  esac
  if [ -L "$1" ]; then rm -f "$1"; elif [ -e "$1" ]; then rm -rf "$1"; fi
}
vh_finish
`,
    );
    expect(r.status, r.stderr).toBe(0);
    const switched = readFileSync(join(w.dest, '.switched'), 'utf8').trim();
    expect(candidates).toContain(switched);
    expect(readlinkSync(join(w.dest, 'current'))).toBe(`versions/${switched}`);
    current(w);
    expect(versions(w)).toEqual([switched, ...all.slice(-2)].sort());
  });

  it('removes nothing more when current is missing', () => {
    const w = world();
    for (const t of ['a', 'b', 'c']) expect(install(w, t).status).toBe(0);
    for (const v of versions(w)) age(versionDir(w, v));
    rmSync(join(w.dest, 'current'));
    const r = lib(w, 'vh_finish\n');
    expect(r.status).not.toBe(0);
    expect(r.stderr).toContain('current is missing');
    expect(versions(w)).toHaveLength(3);
  });

  it('never follows symlinks while pruning, and keeps another run’s fresh temporary link', () => {
    const w = world();
    for (const t of ['a', 'b', 'c']) expect(install(w, t).status).toBe(0);
    const outside = join(w.base, 'outside');
    mkdirSync(outside);
    writeFileSync(join(outside, 'keep'), 'precious');
    writeFileSync(join(outside, 'node'), 'not a version');
    writeFileSync(join(outside, 'helper.mjs'), 'not a version');
    symlinkSync(outside, versionDir(w, 'planted'));
    symlinkSync(outside, versionDir(w, '.hidden'));
    symlinkSync(outside, versionDir(w, '99990101000000.1.link'));
    writeFileSync(versionDir(w, 'stray-file'), 'x');
    // A switch that was stopped long ago, and one another run is making now.
    // Their age is the link's own, never its target's.
    symlinkSync(outside, join(w.dest, '.current.tmp.11111'));
    age(join(w.dest, '.current.tmp.11111'));
    const oldTarget = join(w.base, 'old-target');
    mkdirSync(oldTarget);
    age(oldTarget);
    symlinkSync(oldTarget, join(w.dest, '.current.tmp.22222'));

    expect(install(w, 'd').status).toBe(0);
    expect(current(w)).toBe('d');
    expect(readFileSync(join(outside, 'keep'), 'utf8')).toBe('precious');
    // The links and the stray file go; every version is young, so all stay.
    expect(
      versions(w)
        .map((v) => tagOf(w, v))
        .sort(),
    ).toEqual(['a', 'b', 'c', 'd']);
    expect(readdirSync(w.dest).sort()).toEqual(['.current.tmp.22222', 'current', 'versions']);
    expect(readdirSync(outside).sort()).toEqual(['helper.mjs', 'keep', 'node']);
  });

  it('refuses to switch to a version that is incomplete or a symlink', () => {
    const w = world();
    expect(install(w, 'a').status).toBe(0);
    mkdirSync(versionDir(w, 'partial'));
    writeFileSync(join(versionDir(w, 'partial'), 'node'), 'node x');
    symlinkSync(versionDir(w, versions(w)[0]!), versionDir(w, 'link'));
    for (const v of ['partial', 'link', '../x', '']) {
      const r = lib(w, `vh_switch '${v}'\n`);
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
    symlinkSync(outside, versionDir(w, 'planted'));
    mkdirSync(`${w.dest}.new`);
    mkdirSync(`${w.dest}.old`);
    const r = lib(w, 'vh_remove_dest\n');
    expect(r.status, r.stderr).toBe(0);
    expect(existsSync(w.dest)).toBe(false);
    expect(existsSync(`${w.dest}.new`)).toBe(false);
    expect(existsSync(`${w.dest}.old`)).toBe(false);
    expect(readFileSync(join(outside, 'keep'), 'utf8')).toBe('precious');
  });
});
