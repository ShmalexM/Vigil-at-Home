import { execFileSync } from 'node:child_process';
import { resolve } from 'node:path';
import react from '@vitejs/plugin-react';
import { defineConfig } from 'electron-vite';
import { thirdPartyLicenses } from './scripts/third-party-licenses.mjs';

// Everything the app imports is a devDependency and gets bundled, so the packaged
// app ships only `out/` and no node_modules. A package that must stay external
// (for example one that spawns its own binary) goes in `dependencies` and needs
// externalizeDepsPlugin here. thirdPartyLicenses writes the license texts of
// what gets bundled to build/licenses, which the packages ship.

/** The commit being built, shown in Settings › About so a report names the exact build. */
function buildCommit(): string {
  const sha = process.env['GITHUB_SHA'];
  if (sha) return sha.slice(0, 7);
  try {
    return execFileSync('git', ['rev-parse', '--short', 'HEAD'], { encoding: 'utf8' }).trim();
  } catch {
    return '';
  }
}

export default defineConfig({
  main: {
    define: { __VIGIL_COMMIT__: JSON.stringify(buildCommit()) },
    plugins: [thirdPartyLicenses('main')],
  },
  preload: {
    plugins: [thirdPartyLicenses('preload')],
    build: {
      rollupOptions: {
        // electron-vite 5 does not externalize electron for a CommonJS preload under
        // vite 8, which bundles the npm stub and leaves window.vigil undefined.
        external: ['electron'],
        output: { format: 'cjs', entryFileNames: '[name].cjs' },
      },
    },
  },
  renderer: {
    root: resolve(import.meta.dirname, 'src/renderer'),
    plugins: [react(), thirdPartyLicenses('renderer')],
    build: { rollupOptions: { input: resolve(import.meta.dirname, 'src/renderer/index.html') } },
  },
});
