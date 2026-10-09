// Keeps the helper's copy of the blocking rules and of what is Vigil's own
// in step with the app, over the one connection HelperLink holds.
//
//   rules, exceptions, lists ─► sync()  (one at a time, in order) ─► detection.sync
//   Vigil's own programs     ─► grant() (on its own)              ─► self.grant
//
// The two go separately because naming Vigil's own programs anywhere but the
// installer's folder needs the admin password, and that dialog can stay open
// for minutes. Rule syncs, the user's popup decisions among them, never wait
// on it. Until the grant is approved the helper protects only what it was
// granted before and the installer's folder.
//
// A helper from before self.grant refuses it as an unknown command, and
// refuses rules sent without a self set. Then the self set goes with the
// rules as it used to, in a sync of its own outside the queue; queued rule
// syncs carry the self set the helper last took and never show a dialog
// unless the user asked for the change.

import type { HelperSync, HelperSyncOptions, HelperSyncOutcome } from './detection.js';
import { fromOlderHelper, selfOf, type HelperLink, type HelperRuleSet } from './helper.js';
import { listDigest } from '@vigil/detection/fastpath';
import { HelperCallError } from '@vigil/helper/client';

export interface HelperSyncerOptions {
  link: Pick<HelperLink, 'syncRules' | 'grantSelf'>;
  /** The rules and self set as they stand now; undefined without a detector. */
  rules: () => HelperRuleSet | undefined;
  /** Settles once the self set is complete (an AppImage's programs hashed). */
  ready?: Promise<unknown>;
  log?: (msg: string, err?: unknown) => void;
}

export class HelperSyncer {
  /** What the helper took last, by key; reset on every connection. */
  private rulesSent: string | undefined;
  /**
   * Rules the user declined to approve (a loosening needs their password). Not
   * asked again until the rules change, so the health timer never re-prompts.
   */
  private rulesDeclined: string | undefined;
  private selfSent: string | undefined;
  /** A self set the user declined: asked again only on reconnect or a change. */
  private selfDeclined: string | undefined;
  /** The grant in flight, if any. */
  private granting: Promise<void> | undefined;
  /** The helper predates self.grant. */
  private older = false;
  /** Older helper: the self set it took last, sent with every rule sync. */
  private olderSelf: HelperRuleSet | undefined;
  private queue: Promise<unknown> = Promise.resolve();
  /** Counts connections, so an answer from before a reconnect is ignored. */
  private generation = 0;

  constructor(private readonly opts: HelperSyncerOptions) {}

  /** A new connection: the helper may have restarted or been replaced. */
  connected(): void {
    this.generation++;
    // A grant still waiting on the last connection's dialog no longer counts.
    this.granting = undefined;
    this.rulesSent = undefined;
    this.rulesDeclined = undefined;
    this.selfSent = undefined;
    this.selfDeclined = undefined;
    this.older = false;
    this.olderSelf = undefined;
    void this.sync();
  }

  /** Send the current rules, after any sync before it. Also starts a self grant if the set changed. */
  readonly sync: HelperSync = (opts = {}) => {
    void this.grant();
    const next = this.queue.then(() => this.sendRules(opts));
    this.queue = next;
    return next;
  };

  /**
   * Send the self set if it changed since the helper took or the user refused
   * it. Never queued behind rule syncs, and they never wait on it.
   */
  grant(): Promise<void> {
    if (this.granting) return this.granting;
    const run: Promise<void> = this.grantNow(this.generation).finally(() => {
      if (this.granting === run) this.granting = undefined;
    });
    this.granting = run;
    return run;
  }

  private async grantNow(generation: number): Promise<void> {
    await this.opts.ready;
    // Loop: the set may change while a dialog is open.
    for (;;) {
      const set = this.opts.rules();
      if (!set) return;
      const key = selfKey(set);
      if (key === this.selfSent || key === this.selfDeclined) return;
      const outcome = await this.grantOnce(set, generation);
      if (generation !== this.generation) return;
      if (outcome === 'applied') this.selfSent = key;
      else if (outcome === 'declined') this.selfDeclined = key;
      else return;
    }
  }

  private async grantOnce(
    set: HelperRuleSet,
    generation: number,
  ): Promise<'applied' | 'declined' | 'unavailable'> {
    try {
      if (!this.older) {
        const out = await this.opts.link.grantSelf(set);
        if (out === null || generation !== this.generation) return 'unavailable';
        if (out !== 'unsupported') return out;
        this.older = true;
      }
      // An older helper takes the self set only with the rules: send both,
      // here rather than in the queue, so rule syncs never wait on the dialog.
      const sent = rulesKey(set);
      const out = await this.opts.link.syncRules(set, { withSelf: true });
      if (!out || out === 'needs_password' || generation !== this.generation) return 'unavailable';
      this.olderSelf = set;
      this.rulesSent = olderKey(set, set);
      // Rules that changed while the dialog was open go now. The user may have
      // made the change, so this may ask (an exception the older sync dropped).
      if (rulesKey(this.opts.rules() ?? set) !== sent) void this.sync({ byUser: true });
      return 'applied';
    } catch (err) {
      if (err instanceof HelperCallError && err.code === 'refused') return 'declined';
      this.opts.log?.('[helper self] could not update the helper:', err);
      return 'unavailable';
    }
  }

  private async sendRules(opts: HelperSyncOptions): Promise<HelperSyncOutcome> {
    await this.opts.ready;
    const set = this.opts.rules();
    if (!set) return 'unavailable';
    try {
      if (!this.older) {
        const out = await this.sendCurrent(rulesKey(set), opts, () =>
          this.opts.link.syncRules(set, how(opts)),
        );
        if (out !== 'older') return out;
        this.older = true;
        void this.grant();
      }
      // An older helper: the self set it took last, so the self set never
      // asks here. Before it took one, the whole set, without a dialog unless
      // the user made this change: the grant asks for the self set.
      const self = this.olderSelf ?? set;
      const withSelf = { ...set, ...selfOf(self) };
      const ask = !!(opts.byUser || opts.hold || this.olderSelf);
      const out = await this.sendCurrent(olderKey(set, self), opts, () =>
        this.opts.link.syncRules(withSelf, { ...how(opts), withSelf: true, ask }),
      );
      if (out === 'applied') this.olderSelf = self;
      return out === 'older' ? 'unavailable' : out;
    } catch (err) {
      this.opts.log?.('[helper rules] could not update the helper:', err);
      return 'unavailable';
    }
  }

  private async sendCurrent(
    key: string,
    opts: HelperSyncOptions,
    send: () => ReturnType<HelperLink['syncRules']>,
  ): Promise<HelperSyncOutcome | 'older'> {
    if (key === this.rulesSent) return 'applied';
    if (key === this.rulesDeclined && !opts.byUser) return 'declined';
    const generation = this.generation;
    try {
      const out = await send();
      // Not connected, or an older helper wants the password for a self set
      // the grant is asking for: the rules go with a later sync.
      if (!out || out === 'needs_password') return 'unavailable';
      // Sent before a reconnect: the next sync sends it again.
      if (generation === this.generation) this.rulesSent = key;
      return 'applied';
    } catch (err) {
      if (fromOlderHelper(err, 'selfPaths')) return 'older';
      if (err instanceof HelperCallError && err.code === 'refused') {
        if (generation === this.generation) this.rulesDeclined = key;
        return 'declined';
      }
      throw err;
    }
  }
}

function how(opts: HelperSyncOptions): { hold?: boolean; onHeld?: () => void } {
  return opts.hold ? { hold: true, ...(opts.onHeld ? { onHeld: opts.onHeld } : {}) } : {};
}

/** The rules, exceptions and lists' digests, without the self set. */
function rulesKey(set: HelperRuleSet): string {
  const lists = Object.entries(set.lists).map(([l, entries]) => [l, listDigest(entries)]);
  return JSON.stringify({ rules: set.rules, exceptions: set.exceptions, lists });
}

function selfKey(set: HelperRuleSet): string {
  return JSON.stringify(selfOf(set));
}

/** What an older helper's sync carries: the rules and a self set. */
function olderKey(set: HelperRuleSet, self: HelperRuleSet): string {
  return JSON.stringify({ rules: rulesKey(set), self: selfKey(self) });
}
