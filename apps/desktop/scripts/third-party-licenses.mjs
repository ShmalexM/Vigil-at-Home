// Writes the license texts of the npm packages bundled into the app. Bundling
// strips most license comments, and MIT, ISC and BSD ask for the notice to
// travel with every copy, so the packaged app ships these files instead
// (electron-builder.yml copies build/licenses into Resources/licenses).
import { existsSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

export const LICENSES_DIR = join(
  dirname(fileURLToPath(import.meta.url)),
  '..',
  'build',
  'licenses',
);

/** The package folder a bundled file came from, or undefined for our own code. */
function packageDir(file) {
  const path = file.replace(/^\0/, '').split('?')[0];
  const at = path.lastIndexOf(`${sep}node_modules${sep}`);
  if (at < 0) return undefined;
  const rest = path.slice(at + 14).split(sep);
  const parts = rest[0].startsWith('@') ? 2 : 1;
  return path.slice(0, at + 14) + rest.slice(0, parts).join(sep);
}

function licenseText(dir) {
  const file = readdirSync(dir).find((f) => /^(licen[cs]e|copying)(\.|-|$)/i.test(f));
  return file ? readFileSync(join(dir, file), 'utf8').trim() : undefined;
}

/**
 * Writes build/licenses/<name>.txt (none when nothing is bundled) for the bundled files given (absolute
 * paths, as rollup module ids or esbuild metafile inputs). Throws when a
 * bundled package has no license, so a new dependency can't ship without one.
 */
export function writeLicenses(name, files) {
  const dirs = new Set();
  for (const f of files) {
    const dir = packageDir(f);
    if (dir && existsSync(join(dir, 'package.json'))) dirs.add(dir);
  }
  const entries = new Map();
  for (const dir of dirs) {
    const pkg = JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8'));
    if (pkg.name?.startsWith('@vigil/')) continue;
    const id = `${pkg.name}@${pkg.version}`;
    const license = typeof pkg.license === 'string' ? pkg.license : pkg.license?.type;
    const text = licenseText(dir);
    if (!license && !text) throw new Error(`${id} is bundled but has no license`);
    entries.set(id, `${id}\nLicense: ${license ?? 'see below'}\n\n${text ?? ''}`.trim());
  }
  const out = join(LICENSES_DIR, `${name}.txt`);
  if (entries.size === 0) {
    rmSync(out, { force: true });
    return 0;
  }
  const body = [...entries.keys()]
    .sort()
    .map((id) => entries.get(id))
    .join(`\n\n${'-'.repeat(72)}\n\n`);
  mkdirSync(LICENSES_DIR, { recursive: true });
  writeFileSync(
    out,
    `Third-party software bundled into Vigil at Home (${name}), with the license\n` +
      `text each package ships. See THIRD_PARTY_NOTICES.md for the rest.\n\n${'='.repeat(72)}\n\n${body}\n`,
  );
  return entries.size;
}

/** A Vite plugin that writes the licenses for one electron-vite build (main, preload, renderer). */
export function thirdPartyLicenses(name) {
  return {
    name: 'vigil-third-party-licenses',
    apply: 'build',
    generateBundle() {
      writeLicenses(name, [...this.getModuleIds()]);
    },
  };
}
