import { describe, expect, it } from 'vitest';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, utimesSync } from 'node:fs';
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

  it('retries a save that failed, though memory already matches', () => {
    const file = join(mkdtempSync(join(tmpdir(), 'vigil-rules-')), 'rules.json');
    const store = new RuleStore(file);
    store.upsert({ ruleType: 'BINARY', identifier: 'a'.repeat(64), policy: 'BLOCKLIST' });
    const tmp = `${file}.tmp-${process.pid}`;
    mkdirSync(tmp); // the save's temp file can't be written
    expect(() => store.markSynced(store.rev, true)).toThrow();
    rmSync(tmp, { recursive: true });
    store.markSynced(store.rev, true);
    const disk = JSON.parse(readFileSync(file, 'utf8')) as {
      syncedRev: number;
      cleanSyncPending: boolean;
    };
    expect(disk.syncedRev).toBe(store.rev);
    expect(disk.cleanSyncPending).toBe(false);
  });
});
