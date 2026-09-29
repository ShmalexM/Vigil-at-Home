import { defineConfig } from 'vitest/config';

// The benchmark runs (*.run.ts) are not part of `pnpm test`: they take longer
// and write result files. The bench workflow runs them.
export default defineConfig({
  test: {
    include: ['src/**/*.run.ts'],
    testTimeout: 30 * 60_000,
  },
});
