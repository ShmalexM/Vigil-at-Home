// Builds what the app ships to install the Vigil helper:
//   build/helper/common/        helper.mjs (the helper, bundled), the launchd job,
//                               the install/uninstall scripts and the vigil-helper launcher,
//                               and vigil-hook.mjs (the Claude Code pre-flight hook, bundled)
//                               and linux/ (the systemd unit, polkit policy and Linux scripts)
//   build/helper/<os>-<arch>/   node, Node.js's own binary for that OS and chip
//                               (signed and notarized on macOS), and NODE-LICENSE
//   build/helper/dev-<arch>/    both together, which a development build installs from
// electron-builder copies common and <os>-<arch> into the app's resources/helper.
//
// Usage: node scripts/build-helper.mjs [--os darwin|linux] [--arch arm64,x64] [--skip-node] [--dev]
//   --os defaults to this machine's. --dev builds for this machine only.

import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';
import { execFileSync } from 'node:child_process';
import {
  chmodSync,
  copyFileSync,
  cpSync,
  existsSync,
  mkdirSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';
import { BUNDLE_OPTIONS } from './bundle-options.mjs';
import { writeLicenses } from './third-party-licenses.mjs';

/** The Node.js release the helper runs on. Bump with the repo's Node version. */
export const HELPER_NODE_VERSION = 'v22.22.2';

/**
 * SHA-256 of each Node.js tarball for HELPER_NODE_VERSION, from that release's
 * SHASUMS256.txt (check its signature against a key listed in the nodejs/node
 * README). Pinned here so a tampered download can't pass by bringing its own
 * checksum file. Update these whenever HELPER_NODE_VERSION changes.
 */
const HELPER_NODE_SHA256 = {
  'node-v22.22.2-darwin-arm64.tar.gz':
    'db4b275b83736df67533529a18cc55de2549a8329ace6c7bcc68f8d22d3c9000',
  'node-v22.22.2-darwin-x64.tar.gz':
    '12a6abb9c2902cf48a21120da13f87fde1ed1b71a13330712949e8db818708ba',
  'node-v22.22.2-linux-arm64.tar.gz':
    'b2f3a96f31486bfc365192ad65ced14833ad2a3c2e1bcefec4846902f264fa28',
  'node-v22.22.2-linux-x64.tar.gz':
    '978978a635eef872fa68beae09f0aad0bbbae6757e444da80b570964a97e62a3',
};

const app = join(dirname(fileURLToPath(import.meta.url)), '..');
const repo = join(app, '..', '..');
const out = join(app, 'build', 'helper');

const args = process.argv.slice(2);
const dev = args.includes('--dev');
const archArg = args.includes('--arch') ? args[args.indexOf('--arch') + 1] : 'arm64,x64';
const arches = dev ? [process.arch] : archArg.split(',').filter(Boolean);
const os = args.includes('--os')
  ? args[args.indexOf('--os') + 1]
  : process.platform === 'linux'
    ? 'linux'
    : 'darwin';
if (os !== 'darwin' && os !== 'linux') throw new Error(`--os must be darwin or linux, not ${os}`);
const skipNode =
  args.includes('--skip-node') ||
  (dev && process.platform !== 'darwin' && process.platform !== 'linux');

async function bundle() {
  const common = join(out, 'common');
  rmSync(common, { recursive: true, force: true });
  mkdirSync(common, { recursive: true });
  const options = BUNDLE_OPTIONS;
  const helper = await build({
    ...options,
    metafile: true,
    entryPoints: [join(repo, 'packages/helper/src/cli.ts')],
    outfile: join(common, 'helper.mjs'),
  });
  // The pre-flight hook runs as the user, from the app bundle, on the same
  // signed node. install.sh doesn't copy it: nothing about it runs as root.
  const hook = await build({
    ...options,
    metafile: true,
    entryPoints: [join(repo, 'packages/agent-hook/src/cli.ts')],
    outfile: join(common, 'vigil-hook.mjs'),
  });
  writeLicenses(
    'helper',
    [helper, hook].flatMap((r) =>
      Object.keys(r.metafile.inputs).map((f) => join(process.cwd(), f)),
    ),
  );
  for (const f of ['install.sh', 'uninstall.sh', 'vigil-helper']) {
    copyFileSync(join(app, 'helper', f), join(common, f));
    chmodSync(join(common, f), 0o755);
  }
  copyFileSync(
    join(repo, 'packages/helper/launchd/com.vigilathome.helper.plist'),
    join(common, 'com.vigilathome.helper.plist'),
  );
  mkdirSync(join(common, 'linux'));
  for (const f of LINUX_FILES) {
    copyFileSync(join(app, 'helper', 'linux', f), join(common, 'linux', f));
    chmodSync(join(common, 'linux', f), f.includes('.') && !f.endsWith('.sh') ? 0o644 : 0o755);
  }
  console.log(`helper and pre-flight hook bundled to ${common}`);
}

const LINUX_FILES = [
  'install.sh',
  'uninstall.sh',
  'vigil-helper',
  'vigil-helper.service',
  'com.vigilathome.helper.policy',
];

function sha256(data) {
  return createHash('sha256').update(data).digest('hex');
}

async function fetchOk(url) {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`${url}: HTTP ${res.status}`);
  return Buffer.from(await res.arrayBuffer());
}

async function node(arch) {
  const dir = join(out, `${os}-${arch}`);
  const target = join(dir, 'node');
  const name = `node-${HELPER_NODE_VERSION}-${os}-${arch}`;
  const stamp = join(dir, 'VERSION');
  const license = join(dir, 'NODE-LICENSE');
  const base = `https://nodejs.org/dist/${HELPER_NODE_VERSION}`;
  const file = `${name}.tar.gz`;
  const expected = HELPER_NODE_SHA256[file];
  if (!expected) {
    throw new Error(
      `No pinned SHA-256 for ${file}. After changing HELPER_NODE_VERSION, update ` +
        `HELPER_NODE_SHA256 in scripts/build-helper.mjs from ${base}/SHASUMS256.txt ` +
        `(after checking its signature).`,
    );
  }
  // Locally, reuse a runtime unpacked earlier if it came from the pinned
  // tarball and hasn't changed since. CI, and so every release, always
  // downloads and checks the tarball again, trusting nothing on disk.
  if (
    !process.env.CI &&
    existsSync(target) &&
    existsSync(license) &&
    existsSync(stamp) &&
    readFileSync(stamp, 'utf8') === `${name} ${expected} ${sha256(readFileSync(target))}`
  ) {
    console.log(`${name} already present`);
    return;
  }
  rmSync(dir, { recursive: true, force: true });
  mkdirSync(dir, { recursive: true });
  const tarball = await fetchOk(`${base}/${file}`);
  const actual = sha256(tarball);
  if (actual !== expected)
    throw new Error(`${file}: checksum ${actual}, expected the pinned ${expected}`);

  const tmp = join(dir, file);
  writeFileSync(tmp, tarball);
  execFileSync('tar', ['-xzf', tmp, '-C', dir, '--strip-components=2', `${name}/bin/node`]);
  // Node's LICENSE covers the libraries inside the binary (OpenSSL, V8, ICU...).
  execFileSync('tar', ['-xzf', tmp, '-C', dir, '--strip-components=1', `${name}/LICENSE`]);
  renameSync(join(dir, 'LICENSE'), license);
  rmSync(tmp);
  chmodSync(target, 0o755);
  writeFileSync(stamp, `${name} ${expected} ${sha256(readFileSync(target))}`);
  console.log(`${name} verified and unpacked to ${dir}`);
}

/** The bundle and node side by side, as the app ships them, for development builds. */
function devDir(arch) {
  const dir = join(out, `dev-${arch}`);
  rmSync(dir, { recursive: true, force: true });
  cpSync(join(out, 'common'), dir, { recursive: true });
  copyFileSync(join(out, `${os}-${arch}`, 'node'), join(dir, 'node'));
  chmodSync(join(dir, 'node'), 0o755);
  console.log(`development helper ready in ${dir}`);
}

/**
 * electron-builder drops Electron's and Chromium's licenses from Mac builds and
 * only warns when an extraResources source is missing, so copy them here and
 * fail loudly instead. electron-builder.yml ships build/electron-licenses.
 */
function electronLicenses() {
  const electron = dirname(
    createRequire(join(app, 'package.json')).resolve('electron/package.json'),
  );
  const dist = join(electron, 'dist');
  // CI installs can skip Electron's own download (electron-builder fetches its
  // own copy), so fetch it the way Electron's postinstall does.
  if (!existsSync(join(dist, 'LICENSES.chromium.html'))) {
    execFileSync(process.execPath, [join(electron, 'install.js')], { stdio: 'inherit' });
  }
  const dir = join(app, 'build', 'electron-licenses');
  rmSync(dir, { recursive: true, force: true });
  mkdirSync(dir, { recursive: true });
  for (const [from, to] of [
    ['LICENSE', 'LICENSE.electron.txt'],
    ['LICENSES.chromium.html', 'LICENSES.chromium.html'],
  ]) {
    if (!existsSync(join(dist, from))) throw new Error(`${join(dist, from)} is missing`);
    copyFileSync(join(dist, from), join(dir, to));
  }
}

await bundle();
if (os === 'darwin' && !dev) electronLicenses();
if (!skipNode) {
  for (const arch of arches) {
    await node(arch);
    devDir(arch);
  }
}
