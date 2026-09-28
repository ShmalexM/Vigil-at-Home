import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['{apps,packages}/*/src/**/*.test.ts', 'scripts/**/*.test.mjs'],
    // Real-Mac integration tests (root, pf, osquery) run in the macOS workflow's
    // sensors job through each package's test:mac script.
    exclude: ['**/node_modules/**', '**/*.mac.test.ts'],
  },
});
