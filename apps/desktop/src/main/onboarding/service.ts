import { EventEmitter } from 'node:events';
import { totalmem } from 'node:os';
import { z } from 'zod';
import {
  SetupMode,
  type ApiKeyInput,
  type ApiKeyProvider,
  type CheckId,
  type SetupAction,
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
/** Asking about Codex starts Codex, so the wizard's polling reuses the answer longer. */
const CODEX_CACHE_MS = 30_000;

/**
 * What setup needs from the AI bridge for Codex. `status` re-probes, so
 * `canShareSignIn` is current; `share` links Vigil's Codex folder to the sign-in
 * the user already has (@vigil/ai `shareCodexSignIn`).
 */
export interface CodexSetup {
  status(): Promise<{ state: string; account?: string; detail?: string; canShareSignIn?: boolean }>;
  share(): Promise<{ ok: boolean; reason?: string }>;
}

type CodexStatus = Awaited<ReturnType<CodexSetup['status']>>;

export interface OnboardingOptions {
  store: Store;
  keys: KeyStore;
  probe: Probe;
  /** Filled in as the helper and blocking ship; until then those steps say they're coming. */
  plan?: () => PlanInputs;
  /** Set once the AI is in the app; without it the Codex step only checks it's installed. */
  codex?: CodexSetup;
  supported?: boolean;
  now?: () => number;
}

/**
 * First-run setup. Vigil shows each command, the user runs it in Terminal,
 * and Vigil checks the result itself. Nothing here installs anything.
 */
export class OnboardingService extends EventEmitter<{ changed: [] }> {
  private cache?: { at: number; results: Map<CheckId, CheckResult> };
  private codex: { at: number; status: CodexStatus } | undefined;
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

  /** A step's one-click fix. Only runs when the user presses its button. */
  async runAction(action: SetupAction): Promise<SetupView> {
    switch (action) {
      case 'codex-share': {
        if (!this.o.codex) throw new Error('Codex isn’t connected to Vigil yet');
        const r = await this.o.codex.share();
        if (!r.ok)
          throw new Error(
            r.reason === 'no_sign_in_file'
              ? 'Your Codex keeps its sign-in in the Keychain, so Vigil can’t share it. Sign in with ChatGPT from Vigil instead.'
              : 'Vigil couldn’t use your Codex sign-in. Sign in with ChatGPT from Vigil instead.',
          );
        this.emit('changed');
        return this.view(true);
      }
    }
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
      const codex = d.check === 'codex' && r?.ok ? this.codex?.status : undefined;
      if (supported && codex && codex.state !== 'ready') {
        // Installed but not signed in to Vigil's own Codex folder yet.
        view = {
          ...base,
          // It's installed, so the install command no longer applies.
          commands: [],
          state: 'todo',
          detail: codex.detail ?? 'Installed. Sign in with ChatGPT from Vigil to use it.',
          ...(codex.canShareSignIn
            ? { action: { id: 'codex-share' as const, label: 'Use my Codex sign-in' } }
            : {}),
        };
      } else if (supported && codex) {
        view = {
          ...base,
          state: 'done',
          detail: codex.account ? `Signed in as ${codex.account}` : 'Signed in',
        };
      } else if (!supported) {
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
      // Only ask the AI bridge once Codex is installed; its probe starts Codex.
      if (!this.o.codex || !results.get('codex')?.ok) this.codex = undefined;
      else if (fresh || !this.codex || this.now() - this.codex.at >= CODEX_CACHE_MS) {
        try {
          this.codex = { at: this.now(), status: await this.o.codex.status() };
        } catch {
          this.codex = undefined;
        }
      }
      this.cache = { at: this.now(), results };
      return results;
    })().finally(() => {
      this.inflight = undefined;
    });
    return this.inflight;
  }
}
