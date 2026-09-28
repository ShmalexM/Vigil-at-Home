import { defineConfig } from 'vitest/config';

// Real-Mac integration tests only. The root config leaves them out of the
// default run; the macOS workflow's sensors job runs them as root.
export default defineConfig({
  test: {
    include: ['src/**/*.mac.test.ts'],
    testTimeout: 60_000,
  },
});
