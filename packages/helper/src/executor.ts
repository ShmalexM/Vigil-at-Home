// Runs validated helper commands and records them in the journal. This is
// the only place that decides whether a command may run; the socket server
// just passes requests through.
//
// Release actions only reverse what the helper itself did: resume needs a
// suspend in the journal for that process, unblock needs a block, and so on.
// So the helper can never be used to resume or restore something it did not
// contain.

import { AsyncLocalStorage } from 'node:async_hooks';
import { readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import {
  IdentityApprovalNeeded,
  type RuleStore,
  santaProfile,
  type RulePolicy,
  type RuleType,
  type SantaRule,
} from '@vigil/sensors';
import type {
  DetectionListUnblock,
  DetectionSync,
  HelperAction,
  HelperCommand,
  SelfGrant,
} from './protocol.js';
import { needsApproval } from './protocol.js';
import { Journal, type JournalEntry } from './journal.js';
import type { System } from './system.js';
import { PolicyRefused, type FastPath, type SelfSet } from './fastpath.js';
import type { PreexecSync } from './preexec.js';
import { APPROVAL_TTL_MS, type Approvals } from './approval.js';
import { pinnedHashes, runsPinnedApp, type PinCandidate } from './appPin.js';
import type { AppPinStore } from './pinStore.js';
import { ActionError } from './commands/errors.js';
import {
  identifyProcess,
  killProcess,
  suspendProcess,
  type ProcessIdentity,
} from './commands/process.js';
import { Firewall, normalizeTarget, type NetworkFirewall } from './commands/firewall.js';
import { NftFirewall } from './commands/nftables.js';
import type { FapolicydBlocks } from './commands/fapolicyd.js';
import {
  quarantine,
  realParentPath,
  restore,
  touchesHelperState,
  type QuarantineOptions,
  type QuarantineRecord,
} from './commands/quarantine.js';
import {
  disablePersistence,
  restorePersistence,
  type PersistenceRecord,
} from './commands/persistence.js';
import { disableLinuxPersistence, restoreLinuxPersistence } from './commands/linuxPersistence.js';
import { isEnforcing, refuseRealEnforcement } from './testGuard.js';

export interface ExecutorDeps {
  sys: System;
  journal: Journal;
  approvals: Approvals;
  rules: RuleStore;
  quarantine: QuarantineOptions;
  /**
   * Folders whose startup items persistence.disable accepts. Defaults to the
   * real LaunchAgents/LaunchDaemons folders, or on Linux the systemd and
   * autostart folders users and admins add to.
   */
  launchDirs?: RegExp;
  syncPort: number;
  /**
   * Santa's client identity (the PKCS#12 file and its password), written into
   * the profile so Santa presents it on every sync. Absent on Linux and in tests.
   */
  santaClientCert?: () => { path: string; password: string };
  /** Ask Santa to sync now so a new rule applies in seconds, not at the next interval. */
  triggerSantaSync?: () => Promise<void>;
  /**
   * santa.client.reissue: whether the sync port requires Santa's certificate
   * now (so the command loosens it), and the reissue itself. Absent on Linux.
   */
  santaClientReissue?: {
    required(): boolean;
    /** Throws IdentityApprovalNeeded when, unapproved, it would lower the requirement. */
    reissue(approved: boolean): Promise<void>;
  };
  statusExtra?: () => Record<string, unknown>;
  /** Turns block rules into Santa pre-launch rules; absent in tests that don't need it. */
  preexec?: PreexecSync;
  /** Blocking rules the helper runs on the sensor stream itself. */
  fastPath?: FastPath;
  /** Linux: programs blocked by hash, enforced by fapolicyd and the helper. */
  fapolicyd?: FapolicydBlocks;
  /** The clock a sync's `notAfter` is held to; Date.now by default. */
  now?: () => number;
  /** What is Vigil's own: never paused, stopped or blocked. Defaults to fastPath.self(). */
  self?: () => SelfSet;
  /**
   * The app pinned at install (appPin.ts): a process running it is never
   * paused or stopped, and its program never blocked by hash.
   */
  appPin?: AppPinStore;
  /**
   * The programs Vigil and its sensors run on (ownHashes.ts), hashed by the
   * helper itself: no block by hash may name one.
   */
  ownHashes?: { ready(): Promise<void>; owner(identifier: string): string | undefined };
  /** How long a block by hash waits for ownHashes' first pass (default OWN_HASHES_WAIT_MS). */
  ownHashesWaitMs?: number;
  /**
   * Where the test run that put the blocking rules in force is kept, so a
   * helper restart doesn't lose it (teardown.ts needs it). In memory only when absent.
   */
  rulesTestRunFile?: string;
  /** Re-pins the app a self grant covers, with the grant's password (appPin.ts). */
  repin?: {
    /** Before the password is asked for: the app the grant would pin (pinCandidate). */
    candidate: (grant: SelfGrant) => Promise<PinCandidate | undefined>;
    /** After it was given: pin that app if its code is still the same (repinFromGrant). */
    commit: (bound: PinCandidate) => Promise<void>;
  };
}

export type ExecOutcome =
  { kind: 'done'; result: unknown } | { kind: 'needs_approval'; nonce: string; prompt: string };

/** What every action returns: the journal entry, plus the quarantine id for file.quarantine. */
export interface ActionOutcome {
  actionId: string;
  summary: string;
  undoable: boolean;
  quarantineId?: string;
}

/** Longest a block by hash waits at startup for the helper to hash its own programs. */
export const OWN_HASHES_WAIT_MS = 60_000;

const RULE_TYPE: Record<string, RuleType> = {
  binary: 'BINARY',
  certificate: 'CERTIFICATE',
  signingid: 'SIGNINGID',
  teamid: 'TEAMID',
  cdhash: 'CDHASH',
};

const POLICY: Record<string, Exclude<RulePolicy, 'REMOVE'>> = {
  block: 'BLOCKLIST',
  silent_block: 'SILENT_BLOCKLIST',
  allow: 'ALLOWLIST',
};

/** Who asked for a command, beyond the command itself. */
export interface ExecContext {
  /** The opted-in test run that sent it (testGuard.ts); recorded on its journal entries. */
  testRun?: string;
}

export class Executor {
  readonly firewall: NetworkFirewall;
  /** The test run of the command being executed, for record(). */
  private readonly context = new AsyncLocalStorage<ExecContext>();
  private rulesRun: string | undefined;

  constructor(private readonly d: ExecutorDeps) {
    this.firewall = d.sys.platform === 'linux' ? new NftFirewall(d.sys) : new Firewall(d.sys);
    if (d.rulesTestRunFile) {
      try {
        const saved = JSON.parse(readFileSync(d.rulesTestRunFile, 'utf8')) as { testRun?: unknown };
        if (typeof saved.testRun === 'string') this.rulesRun = saved.testRun;
      } catch {
        // None saved: the rules in force are no test run's.
      }
    }
  }

  /**
   * The test run whose sync put the blocking rules in force, if one did: what
   * the fast path then does on its own is that run's too (daemon.ts).
   */
  get rulesTestRun(): string | undefined {
    return this.rulesRun;
  }

  private setRulesTestRun(testRun: string | undefined): void {
    if (testRun === this.rulesRun) return;
    this.rulesRun = testRun;
    const file = this.d.rulesTestRunFile;
    if (!file) return;
    if (!testRun) {
      rmSync(file, { force: true });
      return;
    }
    const tmp = `${file}.tmp-${process.pid}`;
    writeFileSync(tmp, JSON.stringify({ testRun }), { mode: 0o600 });
    renameSync(tmp, file);
  }

  private self(): SelfSet {
    return this.d.self?.() ?? this.d.fastPath?.self() ?? { paths: [], images: [], hashes: [] };
  }

  /** Whether blocking this hash would block Vigil's own program. */
  private isOwnHash(identifier: string): boolean {
    const id = identifier.toLowerCase();
    if (this.self().hashes.includes(id)) return true;
    return pinnedHashes(this.d.appPin?.current()).includes(id);
  }

  /**
   * The program of the helper's, a sensor's, the installed app's or the
   * operating system's that blocking this hash would block, once the first
   * pass over them is done
   * (or after a while, with what is known by then).
   */
  private async ownProgram(identifier: string): Promise<string | undefined> {
    const own = this.d.ownHashes;
    if (!own) return undefined;
    let timer: NodeJS.Timeout | undefined;
    await Promise.race([
      own.ready(),
      new Promise<void>((resolve) => {
        timer = setTimeout(resolve, this.d.ownHashesWaitMs ?? OWN_HASHES_WAIT_MS);
        timer.unref?.();
      }),
    ]);
    clearTimeout(timer);
    return own.owner(identifier);
  }

  /** The pin check for a process about to be paused or stopped; absent without a pin store. */
  private pinCheck(): { isPinnedApp?: (id: ProcessIdentity) => Promise<boolean | 'changed'> } {
    const store = this.d.appPin;
    if (!store) return {};
    const sys = this.d.sys;
    return {
      isPinnedApp: (id) =>
        runsPinnedApp(sys, store.current(), id, () => identifyProcess(sys, id.pid)),
    };
  }

  /** No file command moves, deletes or restores anything into the helper's own folders. */
  private refuseHelperState(path: string): void {
    if (touchesHelperState(path, this.quarantineOpts))
      throw new ActionError('refused', `${path} is protected`);
  }

  /**
   * Quarantine settings with the protected folders of the OS the helper acts
   * on, and the tripwire over the files the helper keeps (pinStore.ts).
   */
  private get quarantineOpts(): QuarantineOptions {
    const store = this.d.appPin;
    // Vigil's own app as pinned and as the app named it (its AppImages by
    // identity), so no rule moves it or turns off what starts it.
    const own = this.self();
    const pinned = store?.current()?.path;
    const selfPaths = [
      ...(this.d.quarantine.selfPaths ?? []),
      ...own.paths,
      ...(pinned ? [pinned] : []),
    ];
    const selfIds = [...(this.d.quarantine.selfIds ?? []), ...own.images];
    const base: QuarantineOptions = { ...this.d.quarantine, selfPaths, selfIds };
    const opts: QuarantineOptions = store ? { guard: () => store.intact(), ...base } : base;
    return this.d.sys.platform === 'linux' ? { platform: 'linux', ...opts } : opts;
  }

  /** Whether a self grant's app is being read now. */
  private grantReading = false;
  /** The self grant waiting for the password, if any. */
  private grantWaiting: string | undefined;

  /** The app each pending self-grant approval re-pins (appPin.ts pinCandidate), by nonce. */
  private readonly pinBindings = new Map<string, { bound: PinCandidate; expiresAt: number }>();

  /** Bind the code `bound` names to approval `nonce`; drops bindings past their approval's life. */
  private bindPin(nonce: string, bound: PinCandidate): void {
    const now = this.d.sys.now();
    for (const [n, b] of this.pinBindings) if (b.expiresAt < now) this.pinBindings.delete(n);
    this.pinBindings.set(nonce, { bound, expiresAt: now + APPROVAL_TTL_MS });
  }

  /** The code bound to `nonce`, once: an approval is single use. */
  private takePin(nonce: string | undefined): PinCandidate | undefined {
    if (!nonce) return undefined;
    const b = this.pinBindings.get(nonce);
    this.pinBindings.delete(nonce);
    return b?.bound;
  }

  execute(cmd: HelperCommand, approval?: string, ctx: ExecContext = {}): Promise<ExecOutcome> {
    return this.context.run(ctx, () => this.executeIn(cmd, approval));
  }

  private async executeIn(cmd: HelperCommand, approval?: string): Promise<ExecOutcome> {
    let bound: PinCandidate | undefined;
    // Refuse what Linux can't do before asking for a password for it.
    if (this.d.sys.platform === 'linux') checkLinuxBlock(cmd);
    if (cmd.kind === 'detection.sync') {
      this.inTime(cmd);
      // A sync with a rule that doesn't compile, or missing list contents,
      // changes nothing; say so before asking for a password.
      try {
        this.d.fastPath?.checkRules(cmd);
      } catch (err) {
        throw policyError(err);
      }
      const need = this.d.fastPath?.missingLists(cmd) ?? [];
      if (need.length)
        return {
          kind: 'done',
          result: { applied: false, needLists: need, preexec: null },
        };
      // Whether a sync weakens anything depends on the policy in force.
      let weakens: string[];
      try {
        weakens = this.d.fastPath?.loosening(cmd) ?? [];
      } catch (err) {
        throw policyError(err);
      }
      if (weakens.length && (!approval || !this.d.approvals.consume(approval, cmd))) {
        const nonce = this.d.approvals.request(cmd);
        return { kind: 'needs_approval', nonce, prompt: syncPrompt(weakens) };
      }
    } else if (cmd.kind === 'santa.client.reissue') {
      if (!this.d.santaClientReissue) throw new ActionError('invalid', 'Santa runs only on macOS');
      // Clearing the requirement lets a client without a certificate sync
      // until Santa presents the new one; with none required, nothing loosens.
      // The store decides again as the new identity takes over (Santa may
      // present its certificate meanwhile) and refuses an unapproved one then.
      const approved = !!approval && this.d.approvals.consume(approval, cmd);
      const ask = (): ExecOutcome => ({
        kind: 'needs_approval',
        nonce: this.d.approvals.request(cmd),
        prompt: REISSUE_PROMPT,
      });
      if (this.d.santaClientReissue.required() && !approved) return ask();
      try {
        await this.d.santaClientReissue.reissue(approved);
      } catch (err) {
        if (err instanceof IdentityApprovalNeeded) return ask();
        throw err;
      }
      // Santa opens the new file on its next sync; ask for that now.
      await this.syncSanta();
      return { kind: 'done', result: { mobileconfig: this.santaProfile() } };
    } else if (cmd.kind === 'self.grant') {
      // Whether it names anything new depends on what was granted before.
      let grants: string[];
      try {
        grants = this.d.fastPath?.selfLoosening(cmd) ?? [];
      } catch (err) {
        throw policyError(err);
      }
      // Only the approval issued for this very grant releases its binding.
      const ours = !!approval && this.d.approvals.issuedFor(approval, cmd);
      if (grants.length && (!approval || !this.d.approvals.consume(approval, cmd))) {
        if (ours) this.takePin(approval);
        // One grant at a time: its app is read (and hashed) once, and a newer
        // grant replaces the one still waiting for the password.
        if (this.grantReading)
          throw new ActionError(
            'refused',
            'Vigil is still checking its app; try again in a moment',
          );
        this.grantReading = true;
        let candidate: PinCandidate | undefined;
        try {
          // Before the dialog: the app this grant would re-pin, as its code is
          // on disk now. The approval re-pins that code and nothing else.
          candidate = await this.d.repin?.candidate(cmd).catch(() => undefined);
        } finally {
          this.grantReading = false;
        }
        if (this.grantWaiting) {
          this.d.approvals.cancel(this.grantWaiting);
          this.takePin(this.grantWaiting);
        }
        const nonce = this.d.approvals.request(cmd);
        this.grantWaiting = nonce;
        if (candidate) this.bindPin(nonce, candidate);
        return { kind: 'needs_approval', nonce, prompt: selfPrompt(grants) };
      }
      if (approval === this.grantWaiting) this.grantWaiting = undefined;
      if (grants.length) bound = this.takePin(approval);
    } else if (cmd.kind === 'detection.list.unblock') {
      // Nothing to approve for an entry that isn't blocking.
      if (!this.d.fastPath?.blocksWith(cmd.list, cmd.entry))
        throw new ActionError('not_found', `${cmd.entry} is not on your block list`);
      if (!approval || !this.d.approvals.consume(approval, cmd)) {
        const nonce = this.d.approvals.request(cmd);
        return { kind: 'needs_approval', nonce, prompt: unblockPrompt(cmd) };
      }
    } else if (needsApproval(cmd)) {
      // Check the release can actually happen before bothering the user.
      this.findContainment(cmd as HelperAction);
      if (!approval || !this.d.approvals.consume(approval, cmd)) {
        const nonce = this.d.approvals.request(cmd);
        return { kind: 'needs_approval', nonce, prompt: this.approvalPrompt(cmd as HelperAction) };
      }
    }
    const result = await this.run(cmd);
    // Only a grant the password approved re-pins, never one that named nothing
    // new, and only the code bound to that approval.
    if (bound && this.d.repin) await this.d.repin.commit(bound).catch(() => undefined);
    return { kind: 'done', result };
  }

  private approvalPrompt(cmd: HelperAction): string {
    switch (cmd.kind) {
      case 'santa.rule.set':
        return `Vigil wants to always allow programs matching ${cmd.ruleType} ${cmd.identifier}.`;
      case 'santa.rule.remove':
        return this.d.sys.platform === 'linux'
          ? `Vigil wants to unblock the program with hash ${cmd.identifier}.`
          : `Vigil wants to remove its Santa rule for ${cmd.ruleType} ${cmd.identifier}.`;
      default: {
        const e = this.findContainment(cmd);
        return e ? `Vigil wants to undo: ${e.summary}.` : 'Vigil needs your permission.';
      }
    }
  }

  /** The active journal entry a release action would reverse. Throws not_found when there is none. */
  private findContainment(cmd: HelperAction): JournalEntry | undefined {
    const active = this.d.journal.active();
    const pick = (pred: (e: JournalEntry) => boolean, what: string) => {
      const found = active.filter(pred).at(-1);
      if (!found) throw new ActionError('not_found', `Vigil has no active ${what} to undo`);
      return found;
    };
    switch (cmd.kind) {
      case 'process.resume':
        return pick(
          (e) =>
            e.kind === 'process.suspend' && (e.undo?.process as ProcessIdentity).pid === cmd.pid,
          `pause of process ${cmd.pid}`,
        );
      case 'network.unblock': {
        const target = normalizeTarget(cmd.address);
        return pick(
          (e) => e.kind === 'network.block' && e.undo?.address === target,
          `network block for ${cmd.address}`,
        );
      }
      case 'file.restore': {
        const found = pick(
          (e) => e.kind === 'file.quarantine' && e.id === cmd.quarantineId,
          'quarantine with that id',
        );
        this.refuseHelperState((found.undo?.quarantine as QuarantineRecord).originalPath);
        return found;
      }
      case 'persistence.enable': {
        // The journal holds the resolved path (see resolveTarget).
        const paths = new Set([cmd.path, realParentPath(cmd.path)]);
        const found = pick(
          (e) =>
            e.kind === 'persistence.disable' &&
            paths.has((e.undo?.persistence as PersistenceRecord).quarantine.originalPath),
          `disabled startup item at ${cmd.path}`,
        );
        this.refuseHelperState(
          (found.undo?.persistence as PersistenceRecord).quarantine.originalPath,
        );
        return found;
      }
      default:
        return undefined;
    }
  }

  private outcome(e: JournalEntry): ActionOutcome {
    const out: ActionOutcome = {
      actionId: e.id,
      summary: e.summary,
      undoable: e.state === 'active',
    };
    if (e.kind === 'file.quarantine') out.quarantineId = e.id;
    return out;
  }

  private record(
    cmd: HelperAction,
    summary: string,
    undo?: Record<string, unknown>,
    id = Journal.newId(),
  ): ActionOutcome {
    const entry: Parameters<Journal['add']>[0] = {
      id,
      kind: cmd.kind,
      command: cmd,
      state: undo ? 'active' : 'final',
      summary,
    };
    if (undo) entry.undo = undo;
    const testRun = this.context.getStore()?.testRun;
    if (testRun) entry.testRun = testRun;
    return this.outcome(this.d.journal.add(entry));
  }

  private release(entry: JournalEntry, cmd: HelperAction, summary: string): ActionOutcome {
    this.d.journal.markUndone(entry.id);
    return this.record(cmd, summary);
  }

  private async run(cmd: HelperCommand): Promise<unknown> {
    const { sys, journal } = this.d;
    // Tests never contain anything on the machine they run on unless they opt in.
    if (sys.real && isEnforcing(cmd)) refuseRealEnforcement(cmd.kind);
    if (cmd.kind === 'santa.rule.set' && cmd.policy !== 'allow') {
      if (this.isOwnHash(cmd.identifier))
        throw new ActionError('refused', 'that program is part of Vigil');
      const own = await this.ownProgram(cmd.identifier);
      if (own) throw new ActionError('refused', `that is ${own}, which no block by hash may name`);
    }
    if (sys.platform === 'linux' && cmd.kind.startsWith('santa.')) return this.runLinuxBlock(cmd);
    switch (cmd.kind) {
      case 'process.suspend': {
        const id = await suspendProcess(sys, cmd.pid, {
          ...target(cmd),
          self: this.self(),
          ...this.pinCheck(),
        });
        return this.record(cmd, `paused ${id.path} (pid ${id.pid})`, { process: id });
      }
      case 'process.resume': {
        const entry = this.findContainment(cmd)!;
        const was = entry.undo?.process as ProcessIdentity;
        const now = await identifyProcess(sys, was.pid);
        // Gone or replaced by another program: nothing to resume, and a
        // signal would hit the wrong process.
        const same = now && now.path === was.path && now.started === was.started;
        if (same) sys.signal(was.pid, 'SIGCONT');
        return this.release(
          entry,
          cmd,
          same ? `resumed ${was.path} (pid ${was.pid})` : `${was.path} had already exited`,
        );
      }
      case 'process.kill': {
        const id = await killProcess(sys, cmd.pid, {
          ...target(cmd),
          self: this.self(),
          ...this.pinCheck(),
        });
        for (const e of journal.active()) {
          if (e.kind === 'process.suspend' && (e.undo?.process as ProcessIdentity).pid === id.pid)
            journal.markUndone(e.id);
        }
        return this.record(cmd, `stopped ${id.path} (pid ${id.pid})`);
      }
      case 'network.block': {
        if (cmd.port !== undefined) {
          throw new ActionError(
            'invalid',
            'blocking a single port is not supported yet; block the whole address',
          );
        }
        const address = await this.firewall.block(cmd.address);
        const existing = journal
          .active()
          .find((e) => e.kind === 'network.block' && e.undo?.address === address);
        if (existing) {
          // The user asking for a block a test made keeps it past the test's teardown.
          const testRun = this.context.getStore()?.testRun;
          if (!testRun) journal.claim(existing.id, undefined);
          return this.outcome(existing);
        }
        return this.record(cmd, `blocked network traffic with ${address}`, { address });
      }
      case 'network.unblock': {
        const entry = this.findContainment(cmd)!;
        await this.firewall.unblock(entry.undo?.address as string);
        return this.release(entry, cmd, `unblocked ${entry.undo?.address as string}`);
      }
      case 'file.quarantine': {
        const id = Journal.newId();
        const rec = await quarantine(sys, cmd.path, id, this.quarantineOpts);
        return this.record(cmd, `quarantined ${rec.originalPath}`, { quarantine: rec }, id);
      }
      case 'file.restore': {
        const entry = this.findContainment(cmd)!;
        const rec = entry.undo?.quarantine as QuarantineRecord;
        await restore(sys, rec, this.quarantineOpts);
        return this.release(entry, cmd, `restored ${rec.originalPath}`);
      }
      case 'persistence.disable': {
        const id = Journal.newId();
        const rec =
          sys.platform === 'linux'
            ? await disableLinuxPersistence(
                sys,
                cmd.path,
                id,
                this.quarantineOpts,
                this.d.launchDirs,
              )
            : await disablePersistence(sys, cmd.path, id, this.quarantineOpts, this.d.launchDirs);
        return this.record(
          cmd,
          `disabled startup item ${rec.label ?? rec.quarantine.originalPath}`,
          { persistence: rec },
          id,
        );
      }
      case 'persistence.enable': {
        const entry = this.findContainment(cmd)!;
        const rec = entry.undo?.persistence as PersistenceRecord;
        if (sys.platform === 'linux') await restoreLinuxPersistence(sys, rec, this.quarantineOpts);
        else await restorePersistence(sys, rec, this.quarantineOpts);
        return this.release(
          entry,
          cmd,
          `re-enabled startup item ${rec.label ?? rec.quarantine.originalPath}`,
        );
      }
      case 'santa.rule.set': {
        const ruleType = RULE_TYPE[cmd.ruleType]!;
        const previous = this.d.rules.get(ruleType, cmd.identifier)?.rule ?? null;
        try {
          this.d.rules.upsert({
            ruleType,
            identifier: cmd.identifier,
            policy: POLICY[cmd.policy]!,
            customMessage: cmd.message,
          });
        } catch (err) {
          throw new ActionError('invalid', (err as Error).message);
        }
        await this.syncSanta();
        const verb = cmd.policy === 'allow' ? 'allowed' : 'blocked';
        return this.record(cmd, `${verb} programs matching ${cmd.ruleType} ${cmd.identifier}`, {
          ruleType,
          previous,
        });
      }
      case 'santa.rule.remove': {
        const ruleType = RULE_TYPE[cmd.ruleType]!;
        const removed = this.d.rules.remove(ruleType, cmd.identifier);
        if (!removed) throw new ActionError('not_found', 'there is no such Santa rule');
        await this.syncSanta();
        for (const e of journal.active()) {
          const c = e.command as HelperAction;
          if (
            c.kind === 'santa.rule.set' &&
            c.ruleType === cmd.ruleType &&
            c.identifier === cmd.identifier
          )
            journal.markUndone(e.id);
        }
        return this.record(cmd, `removed the Santa rule for ${cmd.ruleType} ${cmd.identifier}`);
      }
      case 'helper.status':
        return {
          pid: process.pid,
          uptimeSeconds: Math.round(process.uptime()),
          activeActions: journal.active().length,
          santaRules: {
            active: this.d.rules.active().length,
            rev: this.d.rules.rev,
            syncedRev: this.d.rules.syncedRev,
          },
          firewall: await this.firewall.list(),
          ...(this.d.appPin ? { appPin: this.d.appPin.status() } : {}),
          ...this.d.statusExtra?.(),
        };
      case 'helper.journal':
        return cmd.active
          ? journal
              .active()
              .slice(-(cmd.limit ?? 1000))
              .reverse()
          : journal.recent(cmd.limit ?? 100);
      case 'detection.sync': {
        if (!this.d.fastPath) throw new ActionError('failed', 'helper rules are not set up');
        // From here to the save nothing waits, so a detection.status read
        // after this sync's line always sees whether it went in.
        this.inTime(cmd);
        let synced;
        try {
          synced = this.d.fastPath.sync(cmd);
        } catch (err) {
          throw policyError(err);
        }
        if (synced.applied) this.setRulesTestRun(this.context.getStore()?.testRun);
        if (!this.d.preexec || !synced.applied) return { ...synced, preexec: null };
        // The rules and lists are in force and saved: answer now. Santa's
        // pre-launch rules follow in the background; detection.status says how.
        this.startPreexec(cmd.rules);
        return { ...synced, preexec: 'pending' };
      }
      case 'detection.list.unblock': {
        if (!this.d.fastPath) throw new ActionError('failed', 'helper rules are not set up');
        return { unblocked: this.d.fastPath.unblock(cmd.list, cmd.entry) };
      }
      case 'detection.status':
        return {
          ...(this.d.fastPath?.status() ?? {}),
          userBlocks: this.d.fastPath?.userBlocks() ?? [],
          syncId: this.d.fastPath?.syncId() ?? null,
          preexec: this.preexecState,
          testRun: this.rulesTestRun ?? null,
        };
      case 'self.grant': {
        if (!this.d.fastPath) throw new ActionError('failed', 'helper rules are not set up');
        try {
          return this.d.fastPath.grantSelf(cmd);
        } catch (err) {
          throw policyError(err);
        }
      }
      case 'detection.list.set': {
        if (!this.d.fastPath) throw new ActionError('failed', 'helper rules are not set up');
        try {
          return this.d.fastPath.putList(cmd);
        } catch (err) {
          throw policyError(err);
        }
      }
      case 'santa.profile':
        return { mobileconfig: this.santaProfile() };
      case 'santa.client.reissue':
        // Handled in execute(), which owns its approval.
        throw new ActionError('invalid', 'santa.client.reissue is handled by execute');
      case 'events.subscribe':
        // Handled by the server, which owns the connection.
        throw new ActionError('invalid', 'events.subscribe is handled by the connection');
    }
  }

  /**
   * Refuse a sync the app has stopped waiting for. The admin password is
   * asked for in the app, between two sends of the same sync; once the app
   * gives up it counts the change as cancelled, so a late yes must not
   * apply it.
   */
  private inTime(cmd: DetectionSync): void {
    if (cmd.notAfter !== undefined && (this.d.now ?? Date.now)() > cmd.notAfter)
      throw new ActionError('refused', 'the app stopped waiting for this change');
  }

  /** How the last hand-off of pre-launch rules to Santa went: pending, its outcome, or the error. */
  private preexecState: unknown = null;
  private preexecChain: Promise<void> = Promise.resolve();

  /** Hand Santa the pre-launch rules for these rules, one hand-off at a time, without waiting. */
  private startPreexec(rules: DetectionSync['rules']): void {
    this.preexecState = 'pending';
    this.preexecChain = this.preexecChain.then(async () => {
      try {
        const before = this.d.rules.rev;
        const outcome = await this.d.preexec!.apply(rules);
        if (this.d.rules.rev !== before) await this.syncSanta();
        this.preexecState = outcome;
      } catch (err) {
        this.preexecState = { error: (err as Error).message };
      }
    });
  }

  /** Wait for pre-launch rules already handed off (tests). */
  async preexecSettled(): Promise<unknown> {
    await this.preexecChain;
    return this.preexecState;
  }

  /**
   * Linux has no Santa. A binary block becomes a fapolicyd rule by hash
   * (commands/fapolicyd.ts); every other Santa rule type is macOS-only.
   */
  private async runLinuxBlock(cmd: HelperCommand): Promise<unknown> {
    const blocks = this.d.fapolicyd;
    checkLinuxBlock(cmd);
    if (cmd.kind !== 'santa.rule.set' && cmd.kind !== 'santa.rule.remove') return undefined;
    if (!blocks) throw new ActionError('failed', 'program blocking is not set up');
    const sha = cmd.identifier.toLowerCase();
    if (cmd.kind === 'santa.rule.set') {
      await blocks.block(sha);
      const existing = this.d.journal
        .active()
        .find(
          (e) =>
            e.kind === 'santa.rule.set' &&
            (e.command as HelperAction & { identifier: string }).identifier.toLowerCase() === sha,
        );
      if (existing) return this.outcome(existing);
      return this.record(cmd, `blocked programs with hash ${sha}`, {
        ruleType: 'BINARY',
        previous: null,
      });
    }
    if (!(await blocks.unblock(sha)))
      throw new ActionError('not_found', 'that program is not blocked');
    for (const e of this.d.journal.active()) {
      const c = e.command as HelperAction;
      if (c.kind === 'santa.rule.set' && c.identifier.toLowerCase() === sha)
        this.d.journal.markUndone(e.id);
    }
    return this.record(cmd as HelperAction, `unblocked programs with hash ${sha}`);
  }

  private santaProfile(): string {
    const client = this.d.santaClientCert?.();
    return santaProfile({
      syncPort: this.d.syncPort,
      ...(client ? { clientCertPath: client.path, clientCertPassword: client.password } : {}),
    });
  }

  private async syncSanta(): Promise<void> {
    try {
      await this.d.triggerSantaSync?.();
    } catch {
      // The rule is stored; Santa picks it up at its next scheduled sync.
    }
  }

  /** At start: pf forgets its tables on reboot, so put active blocks back. */
  async reapplyFirewallBlocks(): Promise<number> {
    const active = this.d.journal.active().filter((e) => e.kind === 'network.block');
    if (active.length === 0) return 0;
    await this.firewall.ensureLoaded();
    for (const e of active) await this.firewall.block(e.undo?.address as string);
    return active.length;
  }
}

/** The password prompt for santa.client.reissue while the sync port requires Santa's certificate. */
export const REISSUE_PROMPT =
  'Vigil wants to repair Santa’s connection: it lets Santa sync without its certificate until Santa uses a new one.';

/** The password prompt for a sync that weakens the helper's rules. Kept short: macOS shows it in a small dialog. */
export function syncPrompt(weakens: string[]): string {
  const shown = weakens.slice(0, 3).join('; ');
  const more = weakens.length > 3 ? ` and ${weakens.length - 3} more` : '';
  return `Vigil wants to loosen its blocking rules: ${shown}${more}.`;
}

/** The password prompt for naming more of Vigil's own programs, which no rule then blocks. */
export function selfPrompt(grants: string[]): string {
  const shown = grants.slice(0, 3).join('; ');
  const more = grants.length > 3 ? ` and ${grants.length - 3} more` : '';
  return `Vigil wants to keep its blocking rules off its own programs: ${shown}${more}.`;
}

function unblockPrompt(cmd: DetectionListUnblock): string {
  return `Vigil wants to stop blocking ${cmd.entry}, which you put on your block list.`;
}

/** The Santa commands Linux can carry out: blocking or unblocking a program by hash. */
function checkLinuxBlock(cmd: HelperCommand): void {
  if (!cmd.kind.startsWith('santa.')) return;
  if (cmd.kind !== 'santa.rule.set' && cmd.kind !== 'santa.rule.remove')
    throw new ActionError('invalid', 'Santa runs only on macOS');
  if (cmd.ruleType !== 'binary')
    throw new ActionError('invalid', 'on Linux a program can only be blocked by its sha256');
  if (cmd.kind === 'santa.rule.set' && cmd.policy === 'allow')
    throw new ActionError('invalid', 'Linux needs no allow rules; Vigil only blocks there');
}

function policyError(err: unknown): ActionError {
  const message = (err as Error).message;
  return new ActionError(err instanceof PolicyRefused ? 'refused' : 'invalid', message);
}

function target(cmd: { startTime?: number | undefined; path?: string | undefined }): {
  startTime?: number;
  path?: string;
} {
  if (cmd.path === undefined && cmd.startTime === undefined) {
    throw new ActionError(
      'invalid',
      'give the process path or start time, so a reused pid is never hit',
    );
  }
  const t: { startTime?: number; path?: string } = {};
  if (cmd.path !== undefined) t.path = cmd.path;
  if (cmd.startTime !== undefined) t.startTime = cmd.startTime;
  return t;
}

export type { SantaRule };
