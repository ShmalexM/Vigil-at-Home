import { DatabaseSync } from 'node:sqlite';
import { HelperCallError } from '@vigil/helper/client';
import { describe, expect, it } from 'vitest';
import { Store } from './db/store.js';
import { Detector } from './detection.js';
import { DryRunExecutor } from './executor.js';
import { helperRulesSync } from './helper-sync.js';
import { VigilCore } from './service.js';

function setup(
  syncRules: () => Promise<unknown>,
  rulesState: (lastSyncId?: string) => { syncId: string | null } | null = () => ({
    syncId: null,
  }),
) {
  const db = new DatabaseSync(':memory:');
  const store = new Store(db);
  const core = new VigilCore(store, new DryRunExecutor(), true);
  const detector = new Detector(db, store, core.alerts, (e, o) => core.ingest(e, o), {
    installedAt: 1,
    selfPaths: ['/Applications/Vigil at Home.app'],
    feeds: { fetch: async () => Promise.reject(new Error('offline in tests')) },
  });
  let answer = async (): Promise<unknown> => ({ applied: true, needLists: [], preexec: null });
  let lastSyncId: string | undefined;
  const link = {
    syncRules: (_set: unknown, how: { syncId?: string }) => {
      lastSyncId = how.syncId;
      return answer();
    },
    rulesState: async () => rulesState(lastSyncId),
  };
  detector.syncHelper = helperRulesSync(link, () => detector.helperRules()).sync;
  const mode = () => detector.rules().find((r) => r.rule.id === 'exec-from-shared-temp')!.mode;
  return {
    detector,
    mode,
    answerWith: (f: () => Promise<unknown>) => (answer = f),
    then: () => (answer = syncRules),
  };
}

describe('sending the helper a rule change', () => {
  it('after a timeout, goes by what the helper has in force: there, the change is made', async () => {
    const t = setup(
      async () => {
        throw new Error('The Vigil helper did not answer');
      },
      // The helper took the sync after the app stopped waiting (Santa was slow).
      (last) => ({ syncId: last ?? null }),
    );
    expect(await t.detector.setMode('exec-from-shared-temp', 'block')).toBe('applied');
    t.then();
    expect(await t.detector.setMode('exec-from-shared-temp', 'shadow')).toBe('applied');
    expect(t.mode()).toBe('shadow');
  });

  it('counts a password dialog left open past the timeout as a cancel', async () => {
    const t = setup(async () => {
      throw new Error('The Vigil helper did not answer');
    });
    expect(await t.detector.setMode('exec-from-shared-temp', 'block')).toBe('applied');
    t.then();
    expect(await t.detector.changeMode('exec-from-shared-temp', 'shadow')).toMatchObject({
      helper: 'declined',
    });
    expect(t.mode()).toBe('block');
  });

  it('makes nothing when the connection drops mid-ask, and says so', async () => {
    const t = setup(async () => {
      throw new HelperCallError('helper connection closed', 'failed');
    });
    expect(await t.detector.setMode('exec-from-shared-temp', 'block')).toBe('applied');
    t.then();
    expect(await t.detector.changeMode('exec-from-shared-temp', 'shadow')).toEqual({
      value: undefined,
      helper: 'failed',
      reason: 'the background helper stopped answering',
    });
    expect(t.mode()).toBe('block');
  });

  it('makes nothing when the helper refuses a list after taking the rules', async () => {
    const t = setup(async () => {
      // What helper.syncRules throws when detection.list.set is refused.
      throw new HelperCallError(
        'list known_bad_sha256 would drop 9000 entries; at most 5000',
        'refused',
      );
    });
    expect(await t.detector.setMode('exec-from-shared-temp', 'block')).toBe('applied');
    t.then();
    expect(await t.detector.changeMode('exec-from-shared-temp', 'alert')).toMatchObject({
      helper: 'failed',
      reason: 'list known_bad_sha256 would drop 9000 entries; at most 5000',
    });
    expect(t.mode()).toBe('block');
  });

  it('makes the change when no helper is connected, known before asking', async () => {
    const t = setup(async () => null);
    expect(await t.detector.setMode('exec-from-shared-temp', 'block')).toBe('applied');
    t.then();
    expect(await t.detector.setMode('exec-from-shared-temp', 'shadow')).toBe('unavailable');
    expect(t.mode()).toBe('shadow');
  });
});
