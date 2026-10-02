// Blocking rules run inside the helper, on the sensor stream itself.
//
//   Santa / osquery ─► SensorHub ─► FastPath.check(event) ─► Executor (kill, block...)
//                                        │                      │ journaled, so undo works
//                                        └──── event + what ran ┴─► app (alert, popup)
//
// Before this, every block made two trips over the socket and waited on the
// app's event loop, and nothing was blocked while the app was closed. The app
// still runs every rule; it raises the alert and, for actions the helper
// already ran, records the helper's result instead of running them again.
//
// The rules, exceptions and lists come from the app (detection.sync) and are
// kept on disk, so blocking resumes at boot before anyone logs in. Only
// containment runs here: the helper never releases anything on its own.

import { readFileSync, renameSync, writeFileSync } from 'node:fs';
import { isRelease, type Action, type SensorEvent } from '@vigil/core';
import {
  DetectionEngine,
  DetectionRule,
  memoryStores,
  type RuleException,
  type Stores,
} from '@vigil/detection';
import { listDigest } from '@vigil/detection/fastpath';
import { z } from 'zod';
import type { ActionOutcome } from './executor.js';
import {
  HelperAction,
  RuleExceptionSchema,
  type DetectionListSet,
  type DetectionSync,
} from './protocol.js';

/** An action the helper ran for a rule, sent to the app with the event. */
export interface HelperRan {
  ruleId: string;
  action: Action;
  /** When it finished (ms). */
  at: number;
  outcome?: ActionOutcome;
  error?: string;
}

export interface FastPathOptions {
  /** Where the synced rules are kept between restarts. */
  file: string;
  run: (action: HelperAction) => Promise<ActionOutcome>;
  log?: (msg: string) => void;
}

const Saved = z.object({
  rules: z.array(DetectionRule),
  exceptions: z.array(RuleExceptionSchema),
  selfPaths: z.array(z.string()),
  lists: z.record(z.string(), z.array(z.string())),
});
type Saved = z.infer<typeof Saved>;

const EMPTY: Saved = { rules: [], exceptions: [], selfPaths: [], lists: {} };

export class FastPath {
  private state: Saved = EMPTY;
  private engine: DetectionEngine | undefined;
  private digests = new Map<string, string>();
  /** Lists arriving in parts: name → digest and the parts so far. */
  private incoming = new Map<string, { digest: string; parts: (string[] | undefined)[] }>();

  constructor(private readonly opts: FastPathOptions) {}

  /** Pick up the rules saved by the last sync. A missing or damaged file means none. */
  load(): void {
    let raw: string;
    try {
      raw = readFileSync(this.opts.file, 'utf8');
    } catch {
      return;
    }
    const parsed = Saved.safeParse(safeJson(raw));
    if (!parsed.success) {
      this.opts.log?.('fast path: ignoring saved rules that do not parse');
      return;
    }
    try {
      this.apply(parsed.data);
    } catch (err) {
      this.opts.log?.(`fast path: saved rules did not load: ${(err as Error).message}`);
    }
  }

  /** Replace the rules. Returns the lists whose contents the app should send. */
  sync(cmd: DetectionSync): { needLists: string[] } {
    const lists: Saved['lists'] = {};
    for (const name of Object.keys(cmd.lists)) {
      const have = this.state.lists[name];
      if (have && this.digests.get(name) === cmd.lists[name]) lists[name] = have;
    }
    // Throws RuleCompileError before anything changes.
    this.apply({ rules: cmd.rules, exceptions: cmd.exceptions, selfPaths: cmd.selfPaths, lists });
    this.save();
    return { needLists: Object.keys(cmd.lists).filter((n) => !(n in lists)) };
  }

  /** One part of a list. The list changes only once every part is in and the digest matches. */
  putList(cmd: DetectionListSet): { complete: boolean } {
    let inc = this.incoming.get(cmd.list);
    if (!inc || inc.digest !== cmd.digest || inc.parts.length !== cmd.parts) {
      inc = { digest: cmd.digest, parts: Array.from({ length: cmd.parts }, () => undefined) };
      // Bounded: anything running as the user can reach the socket.
      if (this.incoming.size >= 8) this.incoming.delete(this.incoming.keys().next().value!);
      this.incoming.set(cmd.list, inc);
    }
    if (cmd.part >= cmd.parts) throw new Error('part is past the last one');
    inc.parts[cmd.part] = cmd.entries;
    if (inc.parts.some((p) => p === undefined)) return { complete: false };
    this.incoming.delete(cmd.list);
    const entries = inc.parts.flat() as string[];
    if (listDigest(entries) !== cmd.digest) throw new Error(`list ${cmd.list} arrived damaged`);
    this.apply({ ...this.state, lists: { ...this.state.lists, [cmd.list]: entries } });
    this.save();
    return { complete: true };
  }

  status(): { rules: number; lists: Record<string, number> } {
    const lists: Record<string, number> = {};
    for (const [n, e] of Object.entries(this.state.lists)) lists[n] = e.length;
    return { rules: this.state.rules.length, lists };
  }

  /**
   * Run the rules on one event and carry out what block-mode rules ask for.
   * Never throws: a failed action is reported to the app like any other.
   */
  async check(e: SensorEvent): Promise<HelperRan[]> {
    if (!this.engine) return [];
    let detections;
    try {
      detections = this.engine.evaluate(e as Parameters<DetectionEngine['evaluate']>[0]);
    } catch (err) {
      this.opts.log?.(`fast path: ${(err as Error).message}`);
      return [];
    }
    const ran: HelperRan[] = [];
    for (const d of detections) {
      if (d.mode !== 'block') continue;
      for (const action of d.execute) {
        const parsed = HelperAction.safeParse(action);
        // Containment only. Rules never carry releases, but the helper checks.
        if (!parsed.success || isRelease(action)) continue;
        try {
          const outcome = await this.opts.run(parsed.data);
          ran.push({ ruleId: d.match.ruleId, action, at: Date.now(), outcome });
        } catch (err) {
          ran.push({
            ruleId: d.match.ruleId,
            action,
            at: Date.now(),
            error: (err as Error).message,
          });
        }
      }
    }
    return ran;
  }

  private apply(next: Saved): void {
    const stores: Stores = memoryStores();
    for (const [name, entries] of Object.entries(next.lists)) {
      stores.lists.replace(name, entries, { source: 'app', updatedAt: 0 });
    }
    for (const ex of next.exceptions) stores.exceptions.add(ex as RuleException);
    const engine = next.rules.length
      ? new DetectionEngine(
          next.rules.map((r) => ({ ...r, mode: 'block' as const })),
          stores,
          { safety: { selfPaths: next.selfPaths }, recordHistory: false },
        )
      : undefined;
    this.engine = engine;
    this.state = next;
    this.digests = new Map(Object.entries(next.lists).map(([n, e]) => [n, listDigest(e)]));
  }

  private save(): void {
    const tmp = `${this.opts.file}.tmp`;
    try {
      writeFileSync(tmp, JSON.stringify(this.state), { mode: 0o600 });
      renameSync(tmp, this.opts.file);
    } catch (err) {
      this.opts.log?.(`fast path: could not save rules: ${(err as Error).message}`);
    }
  }
}

function safeJson(raw: string): unknown {
  try {
    return JSON.parse(raw) as unknown;
  } catch {
    return undefined;
  }
}
