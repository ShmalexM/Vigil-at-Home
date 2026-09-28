import { describe, expect, it } from 'vitest';
import { DEFAULT_FEEDS, FeedImporter, MemoryFeedStateStore } from '../feeds/index.js';
import { memoryStores } from '../state/stores.js';

/**
 * Downloads the real default feeds. Off by default (tests stay offline); the
 * live-feeds workflow runs it with VIGIL_LIVE_FEEDS=1 on GitHub's runners.
 */
describe.skipIf(!process.env.VIGIL_LIVE_FEEDS)('default threat feeds (live)', () => {
  for (const source of DEFAULT_FEEDS) {
    it(`${source.id} downloads and parses`, { timeout: 120_000 }, async () => {
      const stores = memoryStores();
      const importer = new FeedImporter([source], stores.lists, new MemoryFeedStateStore());
      const [r] = await importer.run({ force: true });
      console.log(`${source.id}: ${JSON.stringify(r)}`);
      if (r!.error && /HTTP 40[13]/.test(r!.error)) {
        throw new Error(
          `${source.id} needs an Auth-Key (${r!.error}); set it in the source's headers`,
        );
      }
      expect(r!.status).toBe('updated');
      expect(r!.entries).toBeGreaterThan(0);
      // Validation should drop only a small share of a curated feed.
      const dropped = Object.values(r!.dropped ?? {}).reduce((a, b) => a + (b ?? 0), 0);
      expect(dropped).toBeLessThan(r!.entries);
      expect(stores.lists.size(source.list)).toBe(r!.entries);
    });
  }
});
