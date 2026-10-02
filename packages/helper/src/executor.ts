// Runs validated helper commands and records them in the journal. This is
// the only place that decides whether a command may run; the socket server
// just passes requests through.
//
// Release actions only reverse what the helper itself did: resume needs a
// suspend in the journal for that process, unblock needs a block, and so on.
// So the helper can never be used to resume or restore something it did not
// contain.

import {
  type RuleStore,
  santaProfile,
  type RulePolicy,
  type RuleType,
  type SantaRule,
} from '@vigil/sensors';
import type { HelperAction, HelperCommand } from './protocol.js';
import { needsApproval } from './protocol.js';
import { Journal, type JournalEntry } from './journal.js';
import type { Approvals } from './approval.js';
import type { System } from './system.js';
import { PolicyRefused, type FastPath } from './fastpath.js';
import type { PreexecSync } from './preexec.js';
import { ActionError } from './commands/errors.js';
import {
  identifyProcess,
  killProcess,
  suspendProcess,
  type ProcessIdentity,
} from './commands/process.js';
import { Firewall, normalizeTarget } from './commands/firewall.js';
import {
  quarantine,
  realParentPath,
  restore,
  type QuarantineOptions,
  type QuarantineRecord,
} from './commands/quarantine.js';
import {
  disablePersistence,
  restorePersistence,
  type PersistenceRecord,
} from './commands/persistence.js';

export interface ExecutorDeps {
  sys: System;
  journal: Journal;
  approvals: Approvals;
  rules: RuleStore;
  quarantine: QuarantineOptions;
  /** Folders whose plists persistence.disable accepts. Defaults to the real LaunchAgents/LaunchDaemons folders. */
  launchDirs?: RegExp;
  syncPort: number;
  /** Ask Santa to sync now so a new rule applies in seconds, not at the next interval. */
  triggerSantaSync?: () => Promise<void>;
  statusExtra?: () => Record<string, unknown>;
  /** Turns block rules into Santa pre-launch rules; absent in tests that don't need it. */
  preexec?: PreexecSync;
  /** Blocking rules the helper runs on the sensor stream itself. */
  fastPath?: FastPath;
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

export class Executor {
  readonly firewall: Firewall;

  constructor(private readonly d: ExecutorDeps) {
    this.firewall = new Firewall(d.sys);
  }

  async execute(cmd: HelperCommand, approval?: string): Promise<ExecOutcome> {
    if (cmd.kind === 'detection.sync') {
      // Whether a sync weakens anything depends on the policy in force.
      const weakens = this.d.fastPath?.loosening(cmd) ?? [];
      if (weakens.length && (!approval || !this.d.approvals.consume(approval, cmd))) {
        const nonce = this.d.approvals.request(cmd);
        return { kind: 'needs_approval', nonce, prompt: syncPrompt(weakens) };
      }
    } else if (needsApproval(cmd)) {
      // Check the release can actually happen before bothering the user.
      this.findContainment(cmd as HelperAction);
      if (!approval || !this.d.approvals.consume(approval, cmd)) {
        const nonce = this.d.approvals.request(cmd);
        return { kind: 'needs_approval', nonce, prompt: this.approvalPrompt(cmd as HelperAction) };
      }
    }
    return { kind: 'done', result: await this.run(cmd) };
  }

  private approvalPrompt(cmd: HelperAction): string {
    switch (cmd.kind) {
      case 'santa.rule.set':
        return `Vigil wants to always allow programs matching ${cmd.ruleType} ${cmd.identifier}.`;
      case 'santa.rule.remove':
        return `Vigil wants to remove its Santa rule for ${cmd.ruleType} ${cmd.identifier}.`;
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
      case 'file.restore':
        return pick(
          (e) => e.kind === 'file.quarantine' && e.id === cmd.quarantineId,
          'quarantine with that id',
        );
      case 'persistence.enable': {
        // The journal holds the resolved path (see resolveTarget).
        const paths = new Set([cmd.path, realParentPath(cmd.path)]);
        return pick(
          (e) =>
            e.kind === 'persistence.disable' &&
            paths.has((e.undo?.persistence as PersistenceRecord).quarantine.originalPath),
          `disabled startup item at ${cmd.path}`,
        );
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
    return this.outcome(this.d.journal.add(entry));
  }

  private release(entry: JournalEntry, cmd: HelperAction, summary: string): ActionOutcome {
    this.d.journal.markUndone(entry.id);
    return this.record(cmd, summary);
  }

  private async run(cmd: HelperCommand): Promise<unknown> {
    const { sys, journal } = this.d;
    switch (cmd.kind) {
      case 'process.suspend': {
        const id = await suspendProcess(sys, cmd.pid, target(cmd));
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
        const id = await killProcess(sys, cmd.pid, target(cmd));
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
        if (existing) return this.outcome(existing);
        return this.record(cmd, `blocked network traffic with ${address}`, { address });
      }
      case 'network.unblock': {
        const entry = this.findContainment(cmd)!;
        await this.firewall.unblock(entry.undo?.address as string);
        return this.release(entry, cmd, `unblocked ${entry.undo?.address as string}`);
      }
      case 'file.quarantine': {
        const id = Journal.newId();
        const rec = quarantine(cmd.path, id, this.d.quarantine);
        return this.record(cmd, `quarantined ${rec.originalPath}`, { quarantine: rec }, id);
      }
      case 'file.restore': {
        const entry = this.findContainment(cmd)!;
        const rec = entry.undo?.quarantine as QuarantineRecord;
        restore(rec);
        return this.release(entry, cmd, `restored ${rec.originalPath}`);
      }
      case 'persistence.disable': {
        const id = Journal.newId();
        const rec = await disablePersistence(
          sys,
          cmd.path,
          id,
          this.d.quarantine,
          this.d.launchDirs,
        );
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
        await restorePersistence(sys, rec);
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
          ...this.d.statusExtra?.(),
        };
      case 'helper.journal':
        return journal.recent(cmd.limit ?? 100);
      case 'detection.sync': {
        if (!this.d.fastPath) throw new ActionError('failed', 'helper rules are not set up');
        let synced;
        try {
          synced = this.d.fastPath.sync(cmd);
        } catch (err) {
          throw policyError(err);
        }
        if (!this.d.preexec) return { ...synced, preexec: null };
        const before = this.d.rules.rev;
        const preexec = await this.d.preexec.apply(cmd.rules);
        if (this.d.rules.rev !== before) await this.syncSanta();
        return { ...synced, preexec };
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
        return { mobileconfig: santaProfile({ syncPort: this.d.syncPort }) };
      case 'events.subscribe':
        // Handled by the server, which owns the connection.
        throw new ActionError('invalid', 'events.subscribe is handled by the connection');
    }
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

/** The password prompt for a sync that weakens the helper's rules. Kept short: macOS shows it in a small dialog. */
export function syncPrompt(weakens: string[]): string {
  const shown = weakens.slice(0, 3).join('; ');
  const more = weakens.length > 3 ? ` and ${weakens.length - 3} more` : '';
  return `Vigil wants to loosen its blocking rules: ${shown}${more}.`;
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
