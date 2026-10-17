import { describe, expect, it } from 'vitest';
import type { Action, ActionRecord, ActionResult } from '@vigil/core';
import { RETIRE_MS, type JournalEntry } from '@vigil/helper';
import type { Detector } from './detection.js';
import type { ActionExecutor } from './executor.js';
import type { HelperInForce } from './helper.js';
import {
  InForce,
  LONG_IN_FORCE_MS,
  buildInForce,
  checkInForce,
  isSystemPath,
  isTestPath,
  type InForceHelper,
  type InForceInput,
  type KnownProgram,
} from './in-force.js';
import { VigilCore } from './service.js';
import { memoryStore } from './testing.js';

const NOW = 1_800_000_000_000;
const DAY = 24 * 60 * 60 * 1000;
const SH = 'a'.repeat(64);
const PAYLOAD = 'b'.repeat(64);

function entry(id: string, command: Action, createdAt: number, undo?: JournalEntry['undo']) {
  return {
    id,
    kind: command.kind,
    command,
    state: 'active',
    createdAt,
    summary: `did ${command.kind}`,
    ...(undo ? { undo } : {}),
  } as JournalEntry;
}

function record(id: string, action: Action, over: Partial<ActionRecord> = {}): ActionRecord {
  return {
    id,
    action,
    actor: 'rule',
    reason: 'test',
    requestedAt: NOW - DAY,
    status: 'done',
    result: { at: NOW - DAY, simulated: false },
    ...over,
  };
}

function input(over: Partial<InForceInput> = {}): InForceInput {
  const programs = new Map<string, KnownProgram>([
    [SH, { path: '/bin/sh', apple: true }],
    [PAYLOAD, { path: '/Users/me/Downloads/payload' }],
  ]);
  return {
    helper: { journal: [], userBlocks: [] },
    done: [],
    appUserBlocks: [],
    alertTitle: (id) => (id === 'al-1' ? 'Known malware started' : undefined),
    ruleName: (id) => (id === 'r-net' ? 'Known bad address' : undefined),
    program: (sha) => programs.get(sha),
    now: NOW,
    ...over,
  };
}

const block: Action = { kind: 'network.block', address: '203.0.113.9' };

describe('what is in force', () => {
  it('lists what the helper enforces, with the alert or rule behind it', () => {
    const items = buildInForce(
      input({
        helper: { journal: [entry('j1', block, NOW - 2 * DAY)], userBlocks: [] },
        done: [record('a1', block, { alertId: 'al-1', ruleId: 'r-net' })],
      }),
    );
    expect(items).toEqual([
      {
        key: 'j:j1',
        kind: 'network',
        title: 'Blocks connections to 203.0.113.9',
        since: NOW - 2 * DAY,
        cause: {
          alertId: 'al-1',
          alertTitle: 'Known malware started',
          ruleId: 'r-net',
          ruleName: 'Known bad address',
        },
        release: 'release',
        flags: [],
      },
    ]);
  });

  it('leaves out what the helper no longer enforces, even if the app never saw it undone', () => {
    const items = buildInForce(input({ done: [record('a1', block)] }));
    expect(items).toEqual([]);
  });

  it('shows the user block list, retired entries with when they stop, and folds in their Santa rule', () => {
    const santa: Action = {
      kind: 'santa.rule.set',
      ruleType: 'binary',
      identifier: PAYLOAD,
      policy: 'block',
    };
    const items = buildInForce(
      input({
        helper: {
          journal: [entry('j2', santa, NOW - 3 * DAY)],
          userBlocks: [
            { list: 'user_blocked_sha256', entry: PAYLOAD },
            { list: 'user_blocked_sha256', entry: SH.replace('a', 'c'), retiredAt: NOW - DAY },
          ],
        },
        done: [record('a2', santa, { actor: 'user', alertId: 'al-1' })],
      }),
    );
    expect(items.map((i) => [i.key, i.kind, i.title])).toEqual([
      // The Santa rule is part of the block-list entry, not a row of its own.
      ['u:user_blocked_sha256:' + PAYLOAD, 'block-list', 'Blocks /Users/me/Downloads/payload'],
      [
        'u:user_blocked_sha256:' + SH.replace('a', 'c'),
        'block-list',
        `Still blocks the program with hash ${SH.replace('a', 'c').slice(0, 12)}…`,
      ],
    ]);
    expect(items[0]!.since).toBe(NOW - 3 * DAY);
    expect(items[0]!.cause).toMatchObject({ alertId: 'al-1', byYou: true });
    expect(items[1]!.until).toBe(NOW - DAY + RETIRE_MS);
  });

  it('falls back to the app’s own record without the helper, real actions only', () => {
    const items = buildInForce(
      input({
        helper: null,
        appUserBlocks: [{ list: 'user_blocked_sha256', entry: PAYLOAD }],
        done: [
          record('a1', block),
          record(
            'a2',
            { kind: 'network.block', address: '198.51.100.1' },
            {
              result: { at: 1, simulated: true },
            },
          ),
        ],
      }),
    );
    expect(items.map((i) => i.key).sort()).toEqual(['a:a1', `u:user_blocked_sha256:${PAYLOAD}`]);
  });

  it('lists Santa’s pre-launch rules as the rule’s to change, not to release', () => {
    const [item] = buildInForce(
      input({
        helper: {
          journal: [],
          userBlocks: [],
          preexec: [
            { program: '/usr/bin/osascript', identifier: 'platform:x', ruleIds: ['r-net'] },
          ],
        },
      }),
    );
    expect(item).toMatchObject({ kind: 'prelaunch', release: 'rule', flags: [] });
  });
});

describe('the startup check', () => {
  const santaSh: Action = {
    kind: 'santa.rule.set',
    ruleType: 'binary',
    identifier: SH,
    policy: 'block',
  };

  it('calls out a block on a system program, by hash or by platform signing ID', () => {
    const items = buildInForce(
      input({
        helper: {
          journal: [
            entry('j1', santaSh, NOW - DAY),
            entry(
              'j2',
              {
                kind: 'santa.rule.set',
                ruleType: 'signingid',
                identifier: 'platform:com.apple.ls',
                policy: 'block',
              },
              NOW - DAY,
            ),
            entry(
              'j3',
              { kind: 'santa.rule.set', ruleType: 'binary', identifier: SH, policy: 'allow' },
              NOW - DAY,
            ),
          ],
          userBlocks: [],
        },
      }),
    );
    const flagged = Object.fromEntries(items.map((i) => [i.key, i.flags]));
    expect(flagged).toEqual({ 'j:j1': ['apple-program'], 'j:j2': ['apple-program'], 'j:j3': [] });
    const check = checkInForce(items, NOW);
    expect(check?.message).toBe(
      'Vigil blocks /bin/sh, which is part of the system. That can stop apps and scripts from working, and 1 more thing looks wrong.',
    );
    expect(check?.keys).toEqual(['j:j1', 'j:j2']);
  });

  it('calls out what a test run left behind', () => {
    const items = buildInForce(
      input({
        helper: {
          journal: [
            entry(
              'j1',
              { kind: 'file.quarantine', path: '/tmp/vigil-e2e-123/payload' },
              NOW - DAY,
              {
                quarantine: { originalPath: '/private/tmp/vigil-e2e-123/payload' },
              },
            ),
          ],
          userBlocks: [],
        },
      }),
    );
    expect(items[0]!.flags).toEqual(['test-leftover']);
    expect(checkInForce(items, NOW)?.message).toBe(
      'Vigil still moved /tmp/vigil-e2e-123/payload to quarantine, left over from a test run.',
    );
  });

  it('calls out what Vigil did on its own over a week ago, not what the user asked for', () => {
    const old = NOW - LONG_IN_FORCE_MS - DAY;
    const other: Action = { kind: 'network.block', address: '1.1.1.1' };
    const items = buildInForce(
      input({
        helper: {
          journal: [
            entry('j1', block, old),
            entry('j2', other, old),
            entry('j3', block, NOW - DAY),
          ],
          userBlocks: [{ list: 'user_blocked_sha256', entry: PAYLOAD }],
        },
        done: [record('a1', other, { actor: 'user' })],
      }),
    );
    const flagged = Object.fromEntries(items.map((i) => [i.key, i.flags]));
    expect(flagged['j:j1']).toEqual(['long-running']);
    expect(flagged['j:j2']).toEqual([]);
    expect(flagged['j:j3']).toEqual([]);
    expect(flagged[`u:user_blocked_sha256:${PAYLOAD}`]).toEqual([]);
    expect(checkInForce(items, NOW)?.message).toBe(
      'Vigil blocks connections to 203.0.113.9 and has for 8 days.',
    );
  });

  it('says nothing when nothing looks wrong', () => {
    expect(checkInForce(buildInForce(input()), NOW)).toBeNull();
  });

  it('knows the system folders and the test folders', () => {
    expect(isSystemPath('/usr/bin/env')).toBe(true);
    expect(isSystemPath('/System/Library/x')).toBe(true);
    expect(isSystemPath('/usr/local/bin/node')).toBe(false);
    expect(isTestPath('/private/tmp/vigil-helper-test-1/x')).toBe(true);
    expect(isTestPath('/tmp/vigil-e2e/x')).toBe(true);
    expect(isTestPath('/tmp/other')).toBe(false);
  });
});

/** Records what is asked; says no to everything in `refuse`. */
class FakeExecutor implements ActionExecutor {
  readonly ran: Action[] = [];
  refuse = new Set<Action['kind']>();
  async execute(action: Action): Promise<ActionResult> {
    this.ran.push(action);
    return this.refuse.has(action.kind)
      ? { at: NOW, error: 'Not done: not approved' }
      : { at: NOW, simulated: false };
  }
}

const refused = () => Object.assign(new Error('not approved'), { code: 'refused' });

/**
 * The helper link. A plain unblock runs `whileAsking` (the password dialog
 * is open) and then says `answer`; a held one waits in `held` until
 * approveHeld() (sent, then `answer`) or dropHeld(). `refuseAtOnce` fails
 * a held unblock before it is held.
 */
class FakeHelper implements InForceHelper {
  state: HelperInForce = { journal: [], userBlocks: [] };
  readonly unblocks: { list: string; entry: string; hold: boolean }[] = [];
  private held: { yes: () => void; no: (e: Error) => void }[] = [];
  answer: Error | 'yes' = 'yes';
  refuseAtOnce: Error | undefined;
  whileAsking: (() => Promise<void>) | undefined;
  approved = 0;
  dropped = 0;
  async inForce() {
    return this.state;
  }
  async unblock(list: string, entry: string, opts: { hold?: boolean; onHeld?: () => void } = {}) {
    this.unblocks.push({ list, entry, hold: !!opts.hold });
    if (!opts.hold) {
      await this.whileAsking?.();
      if (this.answer !== 'yes') throw this.answer;
      return { unblocked: true };
    }
    if (this.refuseAtOnce) throw this.refuseAtOnce;
    return new Promise<{ unblocked: boolean }>((resolve, reject) => {
      this.held.push({ yes: () => resolve({ unblocked: true }), no: reject });
      opts.onHeld?.();
    });
  }
  async approveHeld() {
    this.approved++;
    for (const h of this.held.splice(0)) {
      if (this.answer === 'yes') h.yes();
      else h.no(this.answer);
    }
  }
  dropHeld() {
    this.dropped++;
    for (const h of this.held.splice(0)) h.no(refused());
  }
}

function setup() {
  const store = memoryStore();
  const executor = new FakeExecutor();
  const core = new VigilCore(store, executor, false, () => NOW);
  const helper = new FakeHelper();
  const list = new Set<string>();
  let syncs = 0;
  core.detector = {
    userBlocks: () => [...list].map((entry) => ({ list: 'user_blocked_sha256', entry })),
    dropUserBlock: (_l: string, e: string) => list.delete(e),
    syncHelper: async () => {
      syncs++;
      return 'applied';
    },
    rule: () => undefined,
  } as unknown as Detector;
  const inForce = new InForce(core, helper, undefined, () => NOW);
  core.inForce = inForce;
  return { store, executor, core, helper, list, inForce, syncs: () => syncs };
}

describe('releasing', () => {
  it('releases through the action’s own undo when the app has its record', async () => {
    const { store, executor, helper, inForce } = setup();
    store.saveAction(record('a1', block));
    helper.state = { journal: [entry('j1', block, NOW - DAY)], userBlocks: [] };
    expect(await inForce.release('j:j1')).toEqual({ ok: true });
    expect(executor.ran).toEqual([{ kind: 'network.unblock', address: '203.0.113.9' }]);
    expect(store.getAction('a1')?.status).toBe('undone');
  });

  it('releases what the app has no record of with its reverse, asked for as the user', async () => {
    const { store, executor, helper, inForce } = setup();
    const quarantine: Action = { kind: 'file.quarantine', path: '/tmp/vigil-e2e-1/x' };
    helper.state = { journal: [entry('qid-1', quarantine, NOW - DAY)], userBlocks: [] };
    expect(await inForce.release('j:qid-1')).toEqual({ ok: true });
    expect(executor.ran).toEqual([{ kind: 'file.restore', quarantineId: 'qid-1' }]);
    const [logged] = store.listActions();
    expect(logged).toMatchObject({
      actor: 'user',
      status: 'done',
      reason: 'Released from In force',
    });
  });

  it('keeps it in force when the password is not given', async () => {
    const { store, executor, helper, inForce } = setup();
    executor.refuse.add('network.unblock');
    store.saveAction(record('a1', block));
    helper.state = { journal: [entry('j1', block, NOW - DAY)], userBlocks: [] };
    expect(await inForce.release('j:j1')).toEqual({ ok: false, error: 'Not done: not approved' });
    expect(store.getAction('a1')?.status).toBe('done');
  });

  it('takes a hash off the block list with its Santa rule, for one password', async () => {
    const { executor, helper, inForce, list, syncs } = setup();
    const santa: Action = {
      kind: 'santa.rule.set',
      ruleType: 'binary',
      identifier: PAYLOAD,
      policy: 'block',
    };
    list.add(PAYLOAD);
    helper.state = {
      journal: [entry('j2', santa, NOW - DAY)],
      userBlocks: [{ list: 'user_blocked_sha256', entry: PAYLOAD }],
    };
    expect(await inForce.release(`u:user_blocked_sha256:${PAYLOAD}`)).toEqual({ ok: true });
    // The unblock waited for the Santa release's dialog, then went with it.
    expect(helper.unblocks).toEqual([{ list: 'user_blocked_sha256', entry: PAYLOAD, hold: true }]);
    expect(executor.ran).toEqual([
      { kind: 'santa.rule.remove', ruleType: 'binary', identifier: PAYLOAD },
    ]);
    expect(helper.approved).toBe(1);
    expect(list.has(PAYLOAD)).toBe(false);
    expect(syncs()).toBe(1);
  });

  it('leaves the block list and Santa rule as they were when the user says no', async () => {
    const { executor, helper, inForce, list, syncs } = setup();
    executor.refuse.add('santa.rule.remove');
    const santa: Action = {
      kind: 'santa.rule.set',
      ruleType: 'binary',
      identifier: PAYLOAD,
      policy: 'block',
    };
    list.add(PAYLOAD);
    helper.state = {
      journal: [entry('j2', santa, NOW - DAY)],
      userBlocks: [{ list: 'user_blocked_sha256', entry: PAYLOAD }],
    };
    const out = await inForce.release(`u:user_blocked_sha256:${PAYLOAD}`);
    expect(out.ok).toBe(false);
    expect(helper.dropped).toBe(1);
    expect(list.has(PAYLOAD)).toBe(true);
    expect(syncs()).toBe(0);
  });

  it('puts the Santa rule back when the unblock fails after the password', async () => {
    const { executor, helper, inForce, list, syncs } = setup();
    helper.answer = Object.assign(new Error('not on your block list'), { code: 'not_found' });
    const santa: Action = {
      kind: 'santa.rule.set',
      ruleType: 'binary',
      identifier: PAYLOAD,
      policy: 'block',
    };
    list.add(PAYLOAD);
    helper.state = {
      journal: [entry('j2', santa, NOW - DAY)],
      userBlocks: [{ list: 'user_blocked_sha256', entry: PAYLOAD }],
    };
    const out = await inForce.release(`u:user_blocked_sha256:${PAYLOAD}`);
    expect(out).toEqual({ ok: false, error: 'not on your block list' });
    // Released, then blocked again: neither half stays.
    expect(executor.ran).toEqual([
      { kind: 'santa.rule.remove', ruleType: 'binary', identifier: PAYLOAD },
      santa,
    ]);
    expect(list.has(PAYLOAD)).toBe(true);
    expect(syncs()).toBe(0);
  });

  it('releases nothing when the unblock is refused before anything is asked', async () => {
    const { executor, helper, inForce, list } = setup();
    helper.refuseAtOnce = Object.assign(new Error('gone'), { code: 'not_found' });
    const santa: Action = {
      kind: 'santa.rule.set',
      ruleType: 'binary',
      identifier: PAYLOAD,
      policy: 'block',
    };
    list.add(PAYLOAD);
    helper.state = {
      journal: [entry('j2', santa, NOW - DAY)],
      userBlocks: [{ list: 'user_blocked_sha256', entry: PAYLOAD }],
    };
    expect((await inForce.release(`u:user_blocked_sha256:${PAYLOAD}`)).ok).toBe(false);
    expect(executor.ran).toEqual([]);
    expect(list.has(PAYLOAD)).toBe(true);
  });

  it('keeps the app’s list as it was while the dialog is open, and after a no', async () => {
    const { helper, inForce, list, syncs, core } = setup();
    list.add(PAYLOAD);
    helper.state = {
      journal: [],
      userBlocks: [{ list: 'user_blocked_sha256', entry: PAYLOAD }],
    };
    helper.answer = refused();
    // A sync while the dialog is open (a feed refresh) still sends the entry.
    helper.whileAsking = async () => {
      expect(core.detector!.userBlocks()).toEqual([
        { list: 'user_blocked_sha256', entry: PAYLOAD },
      ]);
      await core.detector!.syncHelper?.();
    };
    const out = await inForce.release(`u:user_blocked_sha256:${PAYLOAD}`);
    expect(out).toEqual({ ok: false, error: 'Not released: the password was not given.' });
    expect(list.has(PAYLOAD)).toBe(true);
    expect(syncs()).toBe(1);
  });

  it('takes a hash with no Santa rule off with the helper’s own password dialog', async () => {
    const { helper, inForce, list } = setup();
    list.add(PAYLOAD);
    helper.state = {
      journal: [],
      userBlocks: [{ list: 'user_blocked_sha256', entry: PAYLOAD, retiredAt: NOW - DAY }],
    };
    expect(await inForce.release(`u:user_blocked_sha256:${PAYLOAD}`)).toEqual({ ok: true });
    expect(helper.unblocks).toEqual([{ list: 'user_blocked_sha256', entry: PAYLOAD, hold: false }]);
  });

  it('refuses what only a rule change can undo, and anything gone or unknown', async () => {
    const { helper, inForce } = setup();
    expect((await inForce.release('p:platform:x')).ok).toBe(false);
    expect(await inForce.release('j:gone')).toEqual({
      ok: false,
      error: 'It is no longer in force.',
    });
    helper.state = { journal: [] };
    expect((await inForce.release(`u:user_blocked_sha256:${PAYLOAD}`)).error).toMatch(
      /Update the Vigil helper/,
    );
  });

  it('gives the page its items and the check', async () => {
    const { helper, inForce } = setup();
    helper.state = {
      journal: [
        entry(
          'j1',
          {
            kind: 'santa.rule.set',
            ruleType: 'signingid',
            identifier: 'platform:com.apple.sh',
            policy: 'block',
          },
          NOW - DAY,
        ),
      ],
      userBlocks: [],
    };
    const view = await inForce.view();
    expect(view.helper).toBe('connected');
    expect(view.items).toHaveLength(1);
    expect(view.check?.keys).toEqual(['j:j1']);
  });
});
