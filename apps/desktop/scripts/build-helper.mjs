// Builds what the app ships to install the Vigil helper:
//   build/helper/common/        helper.mjs (the helper, bundled), the launchd job,
//                               the install/uninstall scripts and the vigil-helper launcher
//   build/helper/darwin-<arch>/ node, Node.js's own signed and notarized macOS binary
// electron-builder copies both into Contents/Resources/helper.
//
// Usage: node scripts/build-helper.mjs [--arch arm64,x64] [--skip-node]

import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import {
  chmodSync,
  copyFileSync,
  existsSync,
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';

/** The Node.js release the helper runs on. Bump with the repo's Node version. */
export const HELPER_NODE_VERSION = 'v22.22.2';

const app = join(dirname(fileURLToPath(import.meta.url)), '..');
const repo = join(app, '..', '..');
const out = join(app, 'build', 'helper');

const args = process.argv.slice(2);
const archArg = args.includes('--arch') ? args[args.indexOf('--arch') + 1] : 'arm64,x64';
const arches = archArg.split(',').filter(Boolean);
const skipNode = args.includes('--skip-node');

async function bundle() {
  const common = join(out, 'common');
  rmSync(common, { recursive: true, force: true });
  mkdirSync(common, { recursive: true });
  await build({
    entryPoints: [join(repo, 'packages/helper/src/cli.ts')],
    outfile: join(common, 'helper.mjs'),
    bundle: true,
    platform: 'node',
    format: 'esm',
    target: 'node22',
    // Bundled CommonJS dependencies still call require().
    banner: {
      js: "import { createRequire as __vigilRequire } from 'node:module'; const require = __vigilRequire(import.meta.url);",
    },
    legalComments: 'inline',
    logLevel: 'warning',
  });
  for (const f of ['install.sh', 'uninstall.sh', 'vigil-helper']) {
    copyFileSync(join(app, 'helper', f), join(common, f));
    chmodSync(join(common, f), 0o755);
  }
  copyFileSync(
    join(repo, 'packages/helper/launchd/com.vigilathome.helper.plist'),
    join(common, 'com.vigilathome.helper.plist'),
  );
  console.log(`helper bundled to ${common}`);
}

async function fetchOk(url) {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`${url}: HTTP ${res.status}`);
  return Buffer.from(await res.arrayBuffer());
}

async function node(arch) {
  const dir = join(out, `darwin-${arch}`);
  const target = join(dir, 'node');
  const name = `node-${HELPER_NODE_VERSION}-darwin-${arch}`;
  const stamp = join(dir, 'VERSION');
  if (existsSync(target) && existsSync(stamp) && readFileSync(stamp, 'utf8') === name) {
    console.log(`${name} already present`);
    return;
  }
  rmSync(dir, { recursive: true, force: true });
  mkdirSync(dir, { recursive: true });

  const base = `https://nodejs.org/dist/${HELPER_NODE_VERSION}`;
  const sums = (await fetchOk(`${base}/SHASUMS256.txt`)).toString('utf8');
  const file = `${name}.tar.gz`;
  const expected = sums
    .split('\n')
    .map((l) => l.trim().split(/\s+/))
    .find(([, f]) => f === file)?.[0];
  if (!expected) throw new Error(`${file} is not listed in SHASUMS256.txt`);
  const tarball = await fetchOk(`${base}/${file}`);
  const actual = createHash('sha256').update(tarball).digest('hex');
  if (actual !== expected) throw new Error(`${file}: checksum ${actual}, expected ${expected}`);

  const tmp = join(dir, file);
  writeFileSync(tmp, tarball);
  execFileSync('tar', ['-xzf', tmp, '-C', dir, '--strip-components=2', `${name}/bin/node`]);
  rmSync(tmp);
  chmodSync(target, 0o755);
  writeFileSync(stamp, name);
  console.log(`${name} verified and unpacked to ${dir}`);
}

await bundle();
if (!skipNode) for (const arch of arches) await node(arch);
