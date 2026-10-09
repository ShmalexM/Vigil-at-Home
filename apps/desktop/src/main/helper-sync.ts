import { randomUUID } from 'node:crypto';
import { listDigest } from '@vigil/detection/fastpath';
import { HelperCallError } from '@vigil/helper/client';
import type { HelperSync, HelperSyncOptions, HelperSyncOutcome } from './detection.js';
import type { HelperRuleSet } from './helper.js';

/** What the helper client says when the password was cancelled or a held change dropped. */
const PASSWORD_REFUSALS = new Set(['not approved', 'approval was not accepted', 'not sent']);

export interface HelperRulesLink {
  /** Null when no helper is connected: nothing was sent. */
  syncRules(
    set: HelperRuleSet,
    how: { hold?: boolean; onHeld?: () => void; syncId?: string },
  ): Promise<unknown | null>;
  /** Which sync is in force on the helper, or null if it can't say. */
  rulesState(): Promise<{ syncId: string | null } | null>;
}

/**
 * Sends the helper its blocking rules, one sync at a time. The helper runs
 * the blocking rules it can on its own, so blocks happen even while the app
 * is closed, and hands Santa the pre-launch ones.
 *
 * `unavailable` means only that no helper was connected, known before
 * anything was sent. Once a sync is sent, anything short of the helper's yes
 * means the change is not made: a cancelled password (`declined`), or a
 * refusal or a connection lost mid-ask (`failed`, with the reason). When the
 * app stops waiting (the timeout), it asks the helper which sync is in force
 * and goes by that: made if the helper has it, a cancel if not.
 */
export function helperRulesSync(link: HelperRulesLink, current: () => HelperRuleSet | undefined) {
  // Re-sent on every connection and whenever the rules, exceptions or lists change.
  let sent: string | undefined;
  // A set the user declined to approve (a loosening needs their password). Not
  // asked again until the rules change, so the health timer never re-prompts.
  let declined: string | undefined;
  let queue: Promise<unknown> = Promise.resolve();
  let lastSyncId: string | undefined;

  const send = async (opts: HelperSyncOptions): Promise<HelperSyncOutcome> => {
    const set = opts.set ?? current();
    if (!set) return 'unavailable';
    const lists = Object.entries(set.lists).map(([l, entries]) => [l, listDigest(entries)]);
    const key = JSON.stringify({ ...set, lists });
    if (key === sent) return 'applied';
    if (key === declined && !opts.byUser) return 'declined';
    try {
      const syncId = randomUUID();
      const how = {
        syncId,
        ...(opts.hold ? { hold: true, ...(opts.onHeld ? { onHeld: opts.onHeld } : {}) } : {}),
      };
      lastSyncId = syncId;
      if (!(await link.syncRules(set, how))) return 'unavailable';
      sent = key;
      return 'applied';
    } catch (err) {
      if (
        err instanceof HelperCallError &&
        err.code === 'refused' &&
        PASSWORD_REFUSALS.has(err.message)
      ) {
        declined = key;
        return 'declined';
      }
      // The helper looked at the rules and turned them down (one doesn't
      // compile, or a list would drop too much): the change is not made.
      if (err instanceof HelperCallError && (err.code === 'refused' || err.code === 'invalid')) {
        declined = key;
        opts.onError?.(err.message);
        return 'failed';
      }
      console.warn('[helper rules] could not update the helper:', err);
      // The connection dropped while it was being asked.
      if (err instanceof HelperCallError) {
        opts.onError?.('the background helper stopped answering');
        return 'failed';
      }
      // No answer in time (a password dialog left open, Santa slow): ask the
      // helper what is in force and go by that, rather than guess.
      const state = await link.rulesState();
      if (state?.syncId === lastSyncId) {
        sent = key;
        return 'applied';
      }
      return 'declined';
    }
  };

  const sync: HelperSync = (opts = {}) => {
    // `settle` runs inside the queue, so a user change lands before the next sync reads the rules.
    const next = queue.then(async () => {
      const out = await send(opts);
      opts.settle?.(out);
      return out;
    });
    queue = next.catch(() => undefined);
    return next;
  };

  return {
    sync,
    /** A fresh connection: send everything again and ask again. */
    reset(): void {
      sent = undefined;
      declined = undefined;
    },
  };
}
