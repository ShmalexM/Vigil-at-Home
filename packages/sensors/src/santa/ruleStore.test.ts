import { describe, expect, it } from 'vitest';
import { mkdtempSync, statSync, utimesSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { RuleStore } from './ruleStore.js';

describe('RuleStore.markSynced', () => {
  it('saves only when the synced state changes', () => {
    const file = join(mkdtempSync(join(tmpdir(), 'vigil-rules-')), 'rules.json');
    const store = new RuleStore(file);
    store.upsert({ ruleType: 'BINARY', identifier: 'a'.repeat(64), policy: 'BLOCKLIST' });
    const mtime = () => statSync(file).mtimeMs;
    const age = () => utimesSync(file, new Date(1000), new Date(1000));

    store.markSynced(store.rev, true);
    expect(store.syncedRev).toBe(store.rev);
    expect(store.cleanSyncPending).toBe(false);

    age();
    store.markSynced(store.rev, true);
    store.markSynced(store.rev, false);
    expect(mtime()).toBe(1000);

    store.requestCleanSync();
    age();
    store.markSynced(store.rev, false);
    expect(mtime()).toBe(1000);
    expect(store.cleanSyncPending).toBe(true);
    store.markSynced(store.rev, true);
    expect(mtime()).not.toBe(1000);
    expect(new RuleStore(file).cleanSyncPending).toBe(false);
  });
});
