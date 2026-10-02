// The esbuild options for what the app ships to run on the helper's node
// (helper.mjs and vigil-hook.mjs). Shared with the test that runs the
// bundled hook, so it covers the shipping config.

/** @type {import('esbuild').BuildOptions} */
export const BUNDLE_OPTIONS = {
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
};
