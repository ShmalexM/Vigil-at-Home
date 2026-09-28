import { EventEmitter } from 'node:events';
import { totalmem } from 'node:os';
import { z } from 'zod';
import {
  SetupMode,
  type ApiKeyInput,
  type ApiKeyProvider,
  type CheckId,
  type SetupStepView,
  type SetupView,
} from '../../shared/setup.js';
import type { Store } from '../db/store.js';
import { CHECKS, type CheckResult, type Probe } from './checks.js';
import type { KeyStore } from './keys.js';
import { API_KEYS, localModelFor, stepsFor, type PlanInputs } from './plan.js';

const KEY_MODE = 'onboarding.mode';
const KEY_FINISHED = 'onboarding.finishedAt';
const KEY_SKIPPED = 'onboarding.skipped';

/** Checks are cheap but spawn processes; the wizard polls, so reuse fresh results. */
const CACHE_MS = 2000;

export interface OnboardingOptions {
  store: Store;
  keys: KeyStore;
  probe: Probe;
  /** Filled in as the helper and blocking ship; until then those steps say they're coming. */
  plan?: () => PlanInputs;
  supported?: boolean;
  now?: () => number;
}

/**
 * First-run setup. Vigil shows each command, the user runs it in Terminal,
 * and Vigil checks the result itself. Nothing here installs anything.
 */
export class OnboardingService extends EventEmitter<{ changed: [] }> {
  private cache?: { at: number; results: Map<CheckId, CheckResult> };
  private inflight: Promise<Map<CheckId, CheckResult>> | undefined;
  private readonly now: () => number;

  constructor(private readonly o: OnboardingOptions) {
    super();
    this.now = o.now ?? Date.now;
  }

  mode(): SetupMode | undefined {
    return this.o.store.getSetting(KEY_MODE, SetupMode.optional(), undefined);
  }

  finished(): boolean {
    return this.o.store.getSetting(KEY_FINISHED, z.number().nullable(), null) !== null;
  }

  setMode(mode: SetupMode): void {
    this.o.store.setSetting(KEY_MODE, SetupMode.parse(mode));
    this.emit('changed');
  }

  skip(stepId: string, skipped: boolean): void {
    const set = new Set(this.skipped());
    if (skipped) set.add(stepId);
    else set.delete(stepId);
    this.o.store.setSetting(KEY_SKIPPED, [...set]);
    this.emit('changed');
  }

  finish(): void {
    if (!this.mode()) throw new Error('Choose how Vigil runs first');
    this.o.store.setSetting(KEY_FINISHED, this.now());
    this.emit('changed');
  }

  /** "Run setup again" in Settings. Keeps the mode and saved keys. */
  restart(): void {
    this.o.store.setSetting(KEY_FINISHED, null);
    this.emit('changed');
  }

  setKey(input: ApiKeyInput): void {
    this.o.keys.set(input);
    this.emit('changed');
  }

  clearKey(provider: ApiKeyProvider): void {
    this.o.keys.clear(provider);
    this.emit('changed');
  }

  async view(fresh = false): Promise<SetupView> {
    const mode = this.mode();
    const supported = this.o.supported ?? process.platform === 'darwin';
    const inputs = { localModel: localModelFor(totalmem()), ...this.o.plan?.() };
    // Before a mode is chosen, show everything so the choice screen can count steps.
    const defs = stepsFor(mode ?? 'both', inputs);
    const results = supported
      ? await this.results(
          stepsFor('both', inputs).map((d) => d.check),
          fresh,
        )
      : new Map<CheckId, CheckResult>();
    const skipped = new Set(this.skipped());

    const steps: SetupStepView[] = [];
    const doneIds = new Set<string>();
    for (const d of defs) {
      const r = results.get(d.check);
      const base = {
        id: d.id,
        group: d.group,
        title: d.title,
        why: d.why,
        optional: d.optional ?? false,
        commands: d.commands,
        manual: d.manual ?? [],
        checks: d.checks,
        skipped: skipped.has(d.id),
      };
      let view: SetupStepView;
      if (!supported) {
        view = { ...base, state: 'unavailable', detail: 'Setup checks run on macOS only' };
      } else if (r?.ok) {
        view = { ...base, state: 'done', ...(r.detail ? { detail: r.detail } : {}) };
      } else if ((d.after ?? []).some((id) => defs.some((x) => x.id === id) && !doneIds.has(id))) {
        view = { ...base, state: 'waiting' };
      } else if (!d.commands.length && !d.manual?.length) {
        view = {
          ...base,
          state: 'unavailable',
          detail: d.unavailable ?? 'Not available in this build',
        };
      } else {
        view = { ...base, state: 'todo', ...(r?.detail ? { detail: r.detail } : {}) };
      }
      if (view.state === 'done' || view.skipped) doneIds.add(d.id);
      steps.push(view);
    }

    const saved = this.o.keys.list();
    return {
      ...(mode ? { mode } : {}),
      finished: this.finished(),
      supported,
      steps,
      keys: API_KEYS.map((k) => {
        const s = saved[k.provider];
        return {
          provider: k.provider,
          name: k.name,
          ...(k.url ? { url: k.url } : {}),
          use: k.use,
          needsBaseUrl: k.needsBaseUrl ?? false,
          more: k.more ?? false,
          ...(s ? { saved: s.last4, ...(s.baseUrl ? { baseUrl: s.baseUrl } : {}) } : {}),
        };
      }),
      canSaveKeys: this.o.keys.canSave(),
      checkedAt: this.cache?.at ?? this.now(),
    };
  }

  private skipped(): string[] {
    return this.o.store.getSetting(KEY_SKIPPED, z.array(z.string()), []);
  }

  private async results(ids: CheckId[], fresh: boolean): Promise<Map<CheckId, CheckResult>> {
    if (!fresh && this.cache && this.now() - this.cache.at < CACHE_MS) return this.cache.results;
    // Concurrent callers share one round of checks.
    this.inflight ??= (async () => {
      const unique = [...new Set(ids)];
      const out = await Promise.all(
        unique.map(async (id) => {
          try {
            return [id, await CHECKS[id](this.o.probe)] as const;
          } catch {
            return [id, { ok: false }] as const;
          }
        }),
      );
      const results = new Map<CheckId, CheckResult>(out);
      this.cache = { at: this.now(), results };
      return results;
    })().finally(() => {
      this.inflight = undefined;
    });
    return this.inflight;
  }
}
