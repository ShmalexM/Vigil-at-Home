import { EventEmitter } from 'node:events';
import { z } from 'zod';
import {
  API_PRESETS,
  createVigilAi,
  defaultAiSettings,
  MONTHLY_CAP_HELD,
  PLAN_LIMITS_HELD,
  isCodexSignInShared,
  shareCodexSignIn,
  stopSharingCodexSignIn,
  canRun,
  candidatesFor,
  jevRoute,
  whoRuns,
  type AiKeysSaved,
  type AiNotRunning,
  type AiPurpose,
  type AiSettings,
  type ExecutablePin,
  type PinStore,
  type PromptLogEntry,
  type ProviderId,
  type ProviderStatus,
  type ShareCodexSignInResult,
  type VigilAi,
  type VigilAiOptions,
} from '@vigil/ai';
import type { AiAssessment, Alert, SensorEvent } from '@vigil/core';
import type { AnalyzeRunner } from '@vigil/detection';
import { localNames } from '@vigil/ai/redact';
import {
  AiPrefs,
  AiPrefsPatch,
  DEFAULT_AI_PREFS,
  type AiActionResult,
  type AiProvider,
  type AiProviderView,
  type AiView,
} from '../shared/ai.js';
import type { AlertDetail, EventOutcome } from '../shared/ipc.js';
import type { HelperHeld } from '../shared/agents.js';
import type { DogNoteInput, HelperId, NoteUsage } from '../shared/pack.js';
import type { PackAi } from './pack/service.js';
import type { ApiKeyProvider, SetupMode } from '../shared/setup.js';
import type { Store } from './db/store.js';
import type { VigilCore } from './service.js';
import { labelKey } from './label-filter.js';
import { TEST_RULE } from './test-alert.js';
import { WORTH_A_LOOK_RULE, WorthALook } from './worth-a-look.js';
import { monthStart, sumCost, toRun, type UsageService } from './usage.js';
import { isKeyBilled } from '../shared/usage.js';

const KEY_PREFS = 'ai.prefs';
const KEY_PINS = 'ai.pins';
const PROVIDER_PREFS = ['claude', 'codex', 'api', 'ollama', 'jev'] as const;
const PROVIDER_LABEL: Record<(typeof PROVIDER_PREFS)[number], string> = {
  claude: 'Claude',
  codex: 'Codex',
  api: 'the API connection',
  ollama: 'Ollama',
  jev: 'Jev',
};

/** "a", "a and b", "a, b and c". */
function listWords(words: string[]): string {
  return words.length < 2
    ? (words[0] ?? 'AI')
    : `${words.slice(0, -1).join(', ')} and ${words.at(-1)}`;
}

/** Where Settings › AI keeps each switch (Ai.tsx). */
const EXPLAINS = '“Explains alerts”';
const LABELS = '“Labels events no rule matched”';
const KEY_NEEDED: Record<AiProvider, string> = {
  claude: 'an Anthropic API key',
  codex: 'an OpenAI API key',
  api: 'an OpenRouter or OpenAI key',
  ollama: 'nothing',
  jev: 'an OpenRouter or TypeSafe key',
};

/** "Codex needs an OpenAI API key and Jev needs an OpenRouter or TypeSafe key". */
function needsKeys(ks: readonly AiProvider[]): string {
  return listWords(ks.map((k) => `${PROVIDER_LABEL[k]} needs ${KEY_NEEDED[k]}`));
}

/** What to set up for apps a switch alone won't start: the key, then the switch. */
function setupHint(ks: readonly AiProvider[]): string {
  const them = ks.length > 1 ? 'them' : 'it';
  const where = [
    ...(ks.some((k) => k !== 'jev') ? [EXPLAINS] : []),
    ...(ks.includes('jev') ? [LABELS] : []),
  ];
  const text = `${needsKeys(ks)}: add ${them} under API keys in Setup, then turn ${them} on under ${where.join(' and ')}`;
  return text.charAt(0).toUpperCase() + text.slice(1);
}

const NO_RECORD = Symbol('no saved prefs');

/**
 * Saved prefs, field by field, so one bad field never discards the rest. A
 * field that is missing (saved by an older Vigil) or unreadable takes its
 * default, except an AI app's switch, which stays off: a bad record never
 * turns AI on. Only with nothing saved at all do the apps start on.
 */
function readPrefs(read: () => unknown): AiPrefs {
  let raw: unknown;
  try {
    raw = read();
  } catch {
    // Saved but not JSON: the switches stay off.
    raw = undefined;
  }
  if (raw === NO_RECORD) return DEFAULT_AI_PREFS;
  const saved = (raw && typeof raw === 'object' ? raw : {}) as Record<string, unknown>;
  const out: Record<string, unknown> = {};
  for (const [field, schema] of Object.entries(AiPrefs.shape)) {
    const r = schema.safeParse(saved[field]);
    if (r.success && r.data !== undefined) out[field] = r.data;
    else if ((PROVIDER_PREFS as readonly string[]).includes(field)) out[field] = false;
    else if (field in DEFAULT_AI_PREFS) out[field] = DEFAULT_AI_PREFS[field as keyof AiPrefs];
  }
  return AiPrefs.parse(out);
}

function offView(fix: { notice: string; label?: string } | undefined): Partial<AiView> {
  if (!fix) return {};
  return { off: fix.notice, ...(fix.label ? { offAction: fix.label } : {}) };
}
/** An explanation for a popup should be there by the time the user reads it. */
const EXPLAIN_NOW_DEADLINE_MS = 90_000;
const EXPLAIN_BACKGROUND_DEADLINE_MS = 180_000;
/** Most events of one alert the AI sees. */
const MAX_EVENTS = 20;
const LABEL_EVERY_MS = 60_000;
/** The same program or destination is labelled at most once an hour. */
const REPEAT_MS = 60 * 60_000;
const MAX_LABEL_QUEUE = 200;
/**
 * Apple tools (shells, curl, osascript…) labelled per command line, at most
 * this many an hour, so a busy build can't flood the labeller.
 */
const MAX_TOOL_LABELS_PER_HOUR = 30;
const MAX_REMEMBERED = 5_000;
/** How often to ask the rule reviewer whether a review is due. It runs about once a day. */
const REVIEW_CHECK_MS = 60 * 60_000;
/**
 * Rule reviews need a capable model with tools: the user's Claude or Codex,
 * or the API connection. Never Jev (it only picks labels) or the small local model.
 */
const REVIEW_PROVIDERS: ProviderId[] = ['claude', 'codex', 'api'];

/**
 * Alerts without a popup waiting for an explanation at once. More than this
 * (a burst) go unexplained, so AI work never crowds out Vigil's routine jobs.
 */
const MAX_QUEUED_BACKGROUND = 3;

/**
 * Labelling waits while the Mac is busy and retries what failed, so a pause
 * comes and goes; it is only worth a line once it has lasted this long. The
 * explainer's is shown at once: an alert is waiting on it.
 */
const LABELLER_HELD_SHOWN_AFTER_MS = 60 * 60_000;

const NAMES: Record<AiProvider, string> = {
  claude: 'Claude Code',
  codex: 'Codex',
  api: 'Cloud API',
  ollama: 'Local model (Ollama)',
  jev: 'Jev by TypeSafe',
};

/** The keys that can serve as the OpenAI-style API connection, in the order Vigil prefers them. */
const API_KEYS: ReadonlyArray<{
  provider: 'openrouter' | 'openai' | 'custom';
  name: string;
  baseUrl?: string;
}> = [
  { provider: 'openrouter', name: 'OpenRouter', baseUrl: API_PRESETS.openrouter.baseUrl },
  { provider: 'openai', name: 'OpenAI', baseUrl: API_PRESETS.openai.baseUrl },
  { provider: 'custom', name: 'OpenAI-compatible gateway' },
];

/** What the bridge reads keys from. `KeyStore` fits; `get` never reaches the renderer. */
export interface KeySource {
  list(): Partial<Record<ApiKeyProvider, { last4: string; baseUrl?: string }>>;
  get(provider: ApiKeyProvider): { key: string; baseUrl?: string } | undefined;
}

export interface AiBridgeOptions {
  readonly store: Store;
  readonly usage: UsageService;
  readonly keys: KeySource;
  /** Local, cloud or both, as chosen in setup. */
  readonly mode: () => SetupMode | undefined;
  /** Vigil's own folder (Codex's home goes under it). */
  readonly dataDir: string;
  /** Optional AI work waits while the Mac is busy or on low battery. */
  readonly isBusy?: () => boolean;
  /** Why the Mac is busy (PowerPolicy.busyReason); lets labelling go after a long wait on load alone. */
  readonly busyReason?: () => 'power' | 'load' | undefined;
  /** Opens a vendor's sign-in page in the user's browser. */
  readonly openExternal: (url: string) => Promise<void>;
  /** For tests. */
  readonly create?: (options: VigilAiOptions) => VigilAi;
  readonly now?: () => number;
}

const Pin = z.object({
  realPath: z.string(),
  sha256: z.string(),
  teamId: z.string().optional(),
});

/**
 * Vigil's AI inside the app: the runner from @vigil/ai, configured from setup,
 * Settings and the saved keys, with every run recorded for the Usage page.
 * The AI explains alerts. It never blocks, releases or allows anything, and a
 * block never waits for it.
 */
export class AiBridge extends EventEmitter<{
  changed: [];
  /** A built-in helper started or finished a run (the Pack page's dogs move). */
  busy: [helper: HelperId, busy: boolean];
  /** What a built-in helper was asked and answered, for its notebook on the Pack page. */
  note: [helper: HelperId, note: Omit<DogNoteInput, 'dog'>];
}> {
  private instance: { ai: VigilAi; key: string } | undefined;
  private readonly now: () => number;
  private readonly explaining = new Set<string>();
  private queuedBackground = 0;
  /** Events waiting for a label, oldest first. */
  private labelQueue: SensorEvent[] = [];
  /** Events a run gave back to the queue (see labelBatch); the cap keeps them. */
  private readonly retrying = new Set<string>();
  private worthALook: WorthALook | undefined;
  private cachedPrefs: AiPrefs | undefined;
  /** When each program or destination was last queued, so repeats aren't sent again. */
  private readonly lastQueued = new Map<string, number>();
  /** When recent Apple-tool events were queued, for the hourly cap. */
  private toolQueuedAt: number[] = [];
  /** The model behind recent runs, so an explanation can say who wrote it. */
  private readonly models = new Map<string, string>();
  /** Tokens and cost of the same recent runs, for the pack's notebooks. */
  private readonly spent = new Map<string, NoteUsage>();
  /**
   * Why the explainer or labeller has been trying without reaching an AI
   * since its last answer (the cap, nothing ready, a busy Mac). Cleared by
   * its next answer. So AI work that stops never stops silently.
   */
  private readonly held = new Map<'explainer' | 'labeller', HelperHeld>();
  private labellerShowTimer: ReturnType<typeof setTimeout> | undefined;
  /** When labelling last sent a batch, kept when the runner is rebuilt. */
  private readonly labelClock: { lastSentAt?: number } = {};

  constructor(private readonly o: AiBridgeOptions) {
    super();
    this.now = o.now ?? Date.now;
  }

  prefs(): AiPrefs {
    // Read once: `consider` asks for every event.
    this.cachedPrefs ??= readPrefs(() =>
      this.o.store.getSetting(KEY_PREFS, z.unknown(), NO_RECORD),
    );
    return this.cachedPrefs;
  }

  setPrefs(raw: AiPrefsPatch): AiView['prefs'] {
    const patch = AiPrefsPatch.parse(raw);
    const { monthlyCapUsd, ...rest } = patch;
    const current = this.prefs();
    const defined = Object.fromEntries(Object.entries(rest).filter(([, v]) => v !== undefined));
    let next: AiPrefs = { ...current, ...defined };
    if (monthlyCapUsd === null) {
      const { monthlyCapUsd: _dropped, ...withoutCap } = next;
      next = withoutCap;
    } else if (monthlyCapUsd !== undefined) next = { ...next, monthlyCapUsd };
    this.o.store.setSetting(KEY_PREFS, AiPrefs.parse(next));
    this.cachedPrefs = undefined;
    this.emit('changed');
    return this.prefs();
  }

  /** Which keys are saved, for @vigil/ai's `canRun`. `api` is the API connection's. */
  private savedKeys(): AiKeysSaved {
    const saved = this.o.keys.list();
    return {
      anthropic: !!saved.anthropic,
      openai: !!saved.openai,
      api: !!this.apiConnection(),
      typesafe: !!saved.typesafe,
    };
  }

  /**
   * Whether this app would serve the purpose with these switches, by
   * @vigil/ai's own `canRun`. The API switch alone is off in `settings()`
   * without a key, so here it counts as needing one.
   */
  private reachOf(
    q: AiPrefs,
    keys: AiKeysSaved,
    k: AiProvider,
    purpose: AiPurpose,
  ): true | AiNotRunning {
    const s = this.settings(q);
    if (k === 'api' && q.api && !keys.api)
      return canRun({ ...s, api: { ...s.api, enabled: true } }, keys, k, purpose);
    return canRun(s, keys, k, purpose);
  }

  /**
   * Which AI apps the "Turn on" button switches back on: the ones Vigil's
   * runs have used, or else every one, kept to those the mode allows and
   * that would run on a switch alone (a key they need isn't saved by a
   * button). Labelling on with none of them labelling adds Ollama, outside
   * cloud mode. Never the Claude plan switch, which stays the user's own
   * opt-in. `needs` are the ones (of those that ran before, when any did)
   * that would run once their key is saved.
   */
  private providersToRestore(
    p: AiPrefs,
    keys: AiKeysSaved,
  ): { patch: Partial<Record<AiProvider, boolean>>; needs: AiProvider[] } {
    const why = (k: AiProvider): true | AiNotRunning => {
      const q = { ...p, [k]: true };
      const explain = this.reachOf(q, keys, k, 'explain');
      const label = this.reachOf(q, keys, k, 'label');
      return explain === true || label === true
        ? true
        : explain === 'needs_setup' || label === 'needs_setup'
          ? 'needs_setup'
          : explain;
    };
    const used = new Set(this.o.store.aiRunProviders());
    const fromRuns = PROVIDER_PREFS.filter((k) => used.has(k));
    const pool: AiProvider[] = fromRuns.length ? fromRuns : [...PROVIDER_PREFS];
    let restore = pool.filter((k) => why(k) === true);
    // What ran before isn't allowed or usable any more: fall back to every app.
    if (!restore.length) restore = PROVIDER_PREFS.filter((k) => why(k) === true);
    const patch: Partial<Record<AiProvider, boolean>> = Object.fromEntries(
      restore.map((k) => [k, true]),
    );
    if (
      restore.length &&
      p.labelling &&
      !whoRuns(this.settings({ ...p, ...patch }), keys, 'label').provider &&
      this.reachOf({ ...p, ...patch, ollama: true }, keys, 'ollama', 'label') === true
    )
      patch.ollama = true;
    return { patch, needs: pool.filter((k) => why(k) === 'needs_setup') };
  }

  /**
   * When the switches leave the AI unable to work, in words, and the one
   * change the user's button makes: every app off, or labelling on with
   * nothing that labels. Vigil never makes this change on its own, since a
   * deliberate opt-out looks the same as an accidental one. From prefs,
   * setup's mode and the saved keys only, by @vigil/ai's `whoRuns`, so it
   * is cheap enough for Home and agrees with what the runner would do.
   */
  offFix(): { notice: string; label?: string; patch?: AiPrefsPatch } | undefined {
    const p = this.prefs();
    const keys = this.savedKeys();
    const mode = this.o.mode() ?? 'both';
    if (PROVIDER_PREFS.every((k) => !p[k])) {
      const { patch, needs } = this.providersToRestore(p, keys);
      const names = PROVIDER_PREFS.filter((k) => patch[k]).map((k) => PROVIDER_LABEL[k]);
      const notice =
        'Every AI app is switched off, so new alerts aren’t explained and events aren’t labelled';
      // Nothing would run on a switch alone: say what to set up, and where.
      if (!names.length)
        return {
          notice: `${notice}. ${needs.length ? setupHint(needs) : `Turn one on under ${EXPLAINS}`}`,
        };
      return {
        notice:
          notice +
          // `patch.claude` means the mode allows Claude.
          (patch.claude && p.claudePlan
            ? '. Turning Claude back on also uses your Claude plan again for explanations you ask for'
            : ''),
        label: `Turn on ${listWords(names)}`,
        patch,
      };
    }
    if (!p.labelling || whoRuns(this.settings(p), keys, 'label').provider) return undefined;
    const settings = this.settings(p);
    // The apps switched on that would label once their key is saved.
    const needs = candidatesFor(settings, 'label').filter(
      (k): k is AiProvider => p[k] && this.reachOf(p, keys, k, 'label') === 'needs_setup',
    );
    const notice = needs.length
      ? `Event labelling is on, but ${needsKeys(needs)} to label events. Add ${needs.length > 1 ? 'them' : 'it'} under API keys in Setup`
      : 'Event labelling is on, but no AI app that labels events is switched on';
    // Outside cloud mode Ollama labels on this computer, at no cost. In cloud
    // mode each labeller needs a key or a subscription, so the user picks one.
    if (mode !== 'cloud' && this.reachOf({ ...p, ollama: true }, keys, 'ollama', 'label') === true)
      return {
        notice: needs.length ? `${notice}, or label with Ollama on this Mac` : notice,
        label: 'Label with Ollama',
        patch: { ollama: true },
      };
    return {
      notice: needs.length
        ? `${notice}, or pick another app under ${EXPLAINS}`
        : `${notice}. Pick one: Codex, Claude or the API under ${EXPLAINS}, or Jev under ${LABELS}. Claude, the API and Jev each need a key under API keys in Setup`,
    };
  }

  offNotice(): string | undefined {
    return this.offFix()?.notice;
  }

  /** The user's button under the notice (Settings › AI): makes exactly the change it names. */
  turnBackOn(): AiView['prefs'] {
    const patch = this.offFix()?.patch;
    return patch ? this.setPrefs(patch) : this.prefs();
  }

  /** The OpenAI-style API connection, from whichever key the user saved. */
  private apiConnection() {
    const saved = this.o.keys.list();
    for (const k of API_KEYS) {
      const s = saved[k.provider];
      const baseUrl = k.baseUrl ?? s?.baseUrl;
      if (s && baseUrl) return { ...k, baseUrl, last4: s.last4 };
    }
    return undefined;
  }

  /** The settings @vigil/ai runs with. Built fresh each time from what's saved (or `prefs`). */
  settings(prefs: AiPrefs = this.prefs()): AiSettings {
    const base = defaultAiSettings(this.o.dataDir);
    const api = this.apiConnection();
    const cap = prefs.monthlyCapUsd;
    return {
      ...base,
      mode: this.o.mode() ?? base.mode,
      // Automatic Claude work always uses an Anthropic API key. The plan is
      // opt-in and only ever answers an explanation the user asked for.
      claude: {
        ...base.claude,
        enabled: prefs.claude,
        mode: 'apiKey',
        allowPlan: prefs.claudePlan,
      },
      codex: { ...base.codex, enabled: prefs.codex, mode: prefs.codexUses },
      ollama: { ...base.ollama, enabled: prefs.ollama },
      api: api
        ? {
            ...base.api,
            enabled: prefs.api,
            preset: api.provider,
            baseUrl: api.baseUrl,
          }
        : { ...base.api, enabled: false },
      jev: { ...base.jev, enabled: prefs.jev },
      classifier: { ...base.classifier, enabled: prefs.labelling },
      quota: { ...base.quota, ...(cap !== undefined ? { apiKeyMonthlyCapUsd: cap } : {}) },
      // The account and Mac names are replaced before anything reaches a model.
      redaction: { ...base.redaction, ...localNames() },
    };
  }

  /** The runner, rebuilt whenever the settings it was made with change. */
  ai(): VigilAi {
    const settings = this.settings();
    const keys = this.savedKeys();
    // A key saved or removed changes what runs (Jev, Claude Haiku), so it rebuilds too.
    const key = JSON.stringify({ settings, keys: this.o.keys.list() });
    if (this.instance?.key === key) return this.instance.ai;
    const keyOf = (p: ApiKeyProvider) => async () => this.o.keys.get(p)?.key;
    const api = this.apiConnection();
    const ai = (this.o.create ?? createVigilAi)({
      settings,
      log: { record: (entry) => this.record(entry) },
      pins: this.pins(),
      getAnthropicApiKey: keyOf('anthropic'),
      // Codex sends this only to api.openai.com, so only an OpenAI key is offered.
      getOpenAiApiKey: keyOf('openai'),
      ...(api ? { getApiKey: keyOf(api.provider) } : {}),
      ...(keys.typesafe ? { getJevApiKey: keyOf('typesafe') } : {}),
      keys,
      spentThisMonthUsd: async () => this.spentThisMonthUsd(),
      ...(this.o.isBusy ? { isBusy: this.o.isBusy } : {}),
      ...(this.o.busyReason ? { busyReason: this.o.busyReason } : {}),
      labelClock: this.labelClock,
    });
    this.instance = { ai, key };
    return ai;
  }

  /** Every run, wherever it went, lands in the Usage page's store. */
  private record(entry: PromptLogEntry): void {
    // The labeller's state comes from its batches (labelBatch), which try
    // several AIs in turn; one attempt alone says little.
    if (entry.purpose === 'explain') {
      if (entry.provider === null) this.hold('explainer', heldWhy(entry.outcome, entry.detail));
      else if (entry.outcome === 'ok') this.unhold('explainer');
    }
    if (entry.model) {
      this.models.set(entry.id, entry.model);
      if (this.models.size > 100) this.models.delete(this.models.keys().next().value!);
    }
    // The Usage page's own reading of the run, so a notebook shows the same numbers.
    const run = entry.usage ? toRun(entry) : undefined;
    if (run) {
      const { inputTokens, cachedInputTokens, outputTokens, costUsd } = run;
      this.spent.set(entry.id, { inputTokens, cachedInputTokens, outputTokens, costUsd });
      if (this.spent.size > 100) this.spent.delete(this.spent.keys().next().value!);
    }
    try {
      this.o.usage.record(entry);
    } catch (err) {
      console.error('[ai] recording a run failed:', err);
    }
  }

  /** The model and spend behind a run, for a helper's notebook entry. */
  private ranOn(logId: string): Pick<DogNoteInput, 'model' | 'usage'> {
    const model = this.models.get(logId);
    const usage = this.spent.get(logId);
    return { ...(model ? { model } : {}), ...(usage ? { usage } : {}) };
  }

  /**
   * Why the explainer or labeller hasn't been answering, when it has been
   * trying since its last answer without reaching an AI. For the Agents page.
   */
  heldBack(helper: HelperId): HelperHeld | undefined {
    if (helper !== 'explainer' && helper !== 'labeller') return undefined;
    const h = this.held.get(helper);
    if (!h) return undefined;
    if (helper === 'labeller' && this.now() - h.since < LABELLER_HELD_SHOWN_AFTER_MS)
      return undefined;
    return { ...h };
  }

  /**
   * Note why a helper's work reached no AI. The most important reason seen
   * since its last answer stays (the cap, then no AI ready, then failures,
   * then a busy Mac), so the line doesn't flip between them; the page hears
   * of it only when what it shows changes.
   */
  private hold(helper: 'explainer' | 'labeller', why: string): void {
    const prev = this.held.get(helper);
    if (prev && heldRank(prev.why) > heldRank(why)) return;
    this.held.set(helper, { since: prev?.since ?? this.now(), why });
    if (helper === 'labeller' && !prev) {
      // Shown only after an hour: tell the page when that hour is up.
      clearTimeout(this.labellerShowTimer);
      this.labellerShowTimer = setTimeout(
        () => this.emit('changed'),
        LABELLER_HELD_SHOWN_AFTER_MS + 1_000,
      );
      this.labellerShowTimer.unref?.();
      return;
    }
    if (prev?.why !== why && this.heldBack(helper)) this.emit('changed');
  }

  private unhold(helper: 'explainer' | 'labeller'): void {
    const shown = this.heldBack(helper) !== undefined;
    if (!this.held.delete(helper)) return;
    if (helper === 'labeller') clearTimeout(this.labellerShowTimer);
    if (shown) this.emit('changed');
  }

  /** What Vigil charged to the user's keys since the 1st, all providers together, for the cap. */
  spentThisMonthUsd(): number {
    return sumCost(this.o.store.listAiRuns(monthStart(this.now())).filter(isKeyBilled));
  }

  /** Binaries recorded at setup, kept in the app's database. */
  private pins(): PinStore {
    const read = () => this.o.store.getSetting(KEY_PINS, z.record(z.string(), Pin), {});
    return {
      get: async (provider) => read()[provider] as ExecutablePin | undefined,
      set: async (provider, pin) => {
        this.o.store.setSetting(KEY_PINS, { ...read(), [provider]: Pin.parse(pin) });
      },
    };
  }

  /** Plan limits and the key cap for the Usage page. */
  async limits() {
    const snapshot = await this.ai().spending([]);
    const cap = this.prefs().monthlyCapUsd;
    return {
      plans: snapshot.plans,
      backgroundSharePercent: snapshot.limits.backgroundSharePercent,
      ...(cap !== undefined ? { capUsd: cap } : {}),
    };
  }

  async view(): Promise<AiView> {
    const settings = this.settings();
    const statuses = await this.ai().status();
    const shared = await isCodexSignInShared(settings.codex.codexHome);
    const providers: AiProviderView[] = statuses.map((s) =>
      // With no key the API is off in the runner. Other apps explain alerts without it,
      // so to the user it's an optional extra, not a problem.
      s.provider === 'api' && !this.apiConnection() && this.prefs().api && settings.mode !== 'local'
        ? { ...providerView({ provider: 'api', state: 'disabled' }, shared), state: 'optional' }
        : providerView(s, shared, settings.codex.mode === 'apiKey'),
    );
    // Jev isn't a runner provider; it rides on the keys, by the classifier's own route.
    const saved = this.o.keys.list();
    const api = this.apiConnection();
    const route =
      !settings.jev.enabled || settings.mode === 'local'
        ? undefined
        : jevRoute(settings, this.savedKeys());
    const jevVia = route?.typesafe ? 'typesafe' : route?.openrouter ? 'openrouter' : null;
    providers.push({
      provider: 'jev',
      name: NAMES.jev,
      local: false,
      state: !this.prefs().jev
        ? 'disabled'
        : settings.mode === 'local'
          ? 'disabled'
          : jevVia
            ? 'ready'
            : 'needs_setup',
      ...(jevVia
        ? { detail: jevVia === 'typesafe' ? 'Uses your TypeSafe key' : 'Uses your OpenRouter key' }
        : this.prefs().jev && settings.mode !== 'local'
          ? { detail: 'Add an OpenRouter or TypeSafe key' }
          : {}),
      canSignIn: false,
      canShareSignIn: false,
      signInShared: false,
    });
    const mode = this.o.mode();
    return {
      ...(mode ? { mode } : {}),
      prefs: this.prefs(),
      providers,
      ...(api ? { api: { name: api.name, last4: api.last4 } } : {}),
      anthropicKey: !!saved.anthropic,
      jevVia,
      ...offView(this.offFix()),
      checkedAt: this.now(),
    };
  }

  /** Opens the vendor's sign-in page. The login stays with the vendor's own CLI. */
  async signIn(provider: AiProvider): Promise<AiActionResult> {
    if (provider === 'jev') return { ok: false, error: 'Jev uses a saved key' };
    try {
      const flow = await this.ai().signIn(provider);
      // Only ever hand the browser a web page, never a file or app link.
      if (!isHttps(flow.url)) {
        flow.cancel();
        throw new Error('The sign-in link was not a secure web address');
      }
      await this.o.openExternal(flow.url);
      void flow.completed.then(() => this.emit('changed'));
      return { ok: true };
    } catch (err) {
      return { ok: false, error: err instanceof Error ? err.message : String(err) };
    }
  }

  /** Codex's status, probed now, for setup's Codex step. */
  async codexStatus(): Promise<ProviderStatus> {
    const statuses = await this.ai().status();
    return statuses.find((s) => s.provider === 'codex') ?? { provider: 'codex', state: 'disabled' };
  }

  /** Links Vigil's Codex folder to the user's own Codex sign-in. Only when the user asks. */
  async shareCodexSignIn(): Promise<ShareCodexSignInResult> {
    const r = await shareCodexSignIn(this.settings().codex.codexHome);
    this.forget();
    return r;
  }

  async stopSharingCodexSignIn(): Promise<void> {
    await stopSharingCodexSignIn(this.settings().codex.codexHome);
    this.forget();
  }

  /** Drops the runner so the next use probes every provider afresh. */
  private forget(): void {
    this.instance = undefined;
    this.emit('changed');
  }

  /**
   * Explains each new alert once its response has run. Popups go first, in
   * the scheduler's urgent lane. The test alert is never sent, and neither
   * are "worth a look" alerts: the labeller's reason already explains them,
   * and the user can still press Explain.
   */
  explainAlertsFrom(core: Pick<VigilCore, 'alerts' | 'scheduler' | 'alertDetail'>): void {
    core.alerts.on('raised', (alert) => {
      if (alert.ruleId === TEST_RULE.id || alert.ruleId === WORTH_A_LOOK_RULE.id) return;
      const urgent = alert.notify === 'popup';
      if (!urgent) {
        if (this.queuedBackground >= MAX_QUEUED_BACKGROUND) return;
        this.queuedBackground++;
      }
      void core.scheduler
        .enqueue(
          `explain-${alert.id}`,
          () => this.explain(alert, core.alertDetail(alert.id)),
          urgent ? 'urgent' : 'routine',
        )
        .then((assessment) => {
          if (assessment) core.alerts.recordAssessment(alert.id, assessment);
        })
        .catch((err) => console.error('[ai] explaining an alert failed:', err))
        .finally(() => {
          if (!urgent) this.queuedBackground--;
        });
    });
  }

  /**
   * Labels events no rule matched, a batch a minute, as hints in Activity.
   * Apple's own programs (except the tools attackers borrow, see
   * label-filter.ts) and repeats within an hour are skipped; the
   * classifier keeps to its hourly and CPU budgets and waits while the Mac is
   * busy. A label never blocks, allows or raises anything.
   */
  labelEventsFrom(
    core: Pick<VigilCore, 'scheduler' | 'store'> & {
      onIngest: VigilCore['onIngest'];
      alerts?: VigilCore['alerts'];
    },
  ): void {
    core.onIngest = (event, outcome) => this.consider(event, outcome);
    // The strongest catches become quiet "worth a look" alerts (worth-a-look.ts).
    if (core.alerts) this.worthALook = new WorthALook(core.alerts, this.now);
    core.scheduler.every('label-events', LABEL_EVERY_MS, async () => {
      await this.labelBatch(core.store);
    });
  }

  /**
   * About once a day the signed-in AI reads a redacted summary of this Mac's
   * activity and proposes new rules, narrow exclusions for noisy ones, or
   * turning a broken rule down. Each proposal is checked and replayed on 14
   * days of history, then waits on the Rules page for the user. Nothing here
   * changes a live rule, and nothing can allow anything.
   */
  reviewRulesFrom(core: Pick<VigilCore, 'scheduler' | 'detector'>): void {
    const detector = core.detector;
    if (!detector) return;
    detector.attachReviewer(() => this.ruleReviewRunner(), this.o.isBusy);
    core.scheduler.every('rule-review', REVIEW_CHECK_MS, async () => {
      const out = await detector.reviewRules();
      if (out.ran) this.emit('changed');
    });
  }

  /** The runner for rule reviews, or undefined when no cloud AI may run them. */
  ruleReviewRunner(): AnalyzeRunner | undefined {
    const prefs = this.prefs();
    if (this.o.mode() === 'local' || !(prefs.claude || prefs.codex || prefs.api)) return undefined;
    return {
      run: async (req) => {
        const r = await this.busyWhile('rule-reviewer', () =>
          this.ai().run({ ...req, providers: REVIEW_PROVIDERS }),
        );
        const proposed = r.ok ? reviewReasons(r.value) : [];
        this.emit('note', 'rule-reviewer', {
          kind: 'review',
          ok: r.ok,
          ask: 'Review Vigil’s rules against recent activity',
          lookedAt: (req.tools ?? []).map((t) => t.name),
          answer: r.ok
            ? proposed.length
              ? `Suggested ${proposed.length} change${proposed.length === 1 ? '' : 's'} for you to review`
              : 'No changes to suggest'
            : whyNot(r.reason),
          reasons: proposed,
          ...(r.ok ? { provider: r.provider } : {}),
          ...this.ranOn(r.logId),
        });
        if (r.ok) return { ok: true, value: r.value, provider: r.provider };
        return { ok: false, reason: r.reason, ...(r.detail ? { detail: r.detail } : {}) };
      },
    };
  }

  /** Queues an event for labelling when it's worth a model's look. Cheap: runs for every event. */
  consider(event: SensorEvent, outcome: EventOutcome | undefined): void {
    if (!outcome || outcome.matches.length > 0) return;
    const found = labelKey(event);
    if (!found || !this.prefs().labelling) return;
    const { key, tool } = found;
    const at = this.now();
    const last = this.lastQueued.get(key);
    if (last !== undefined && at - last < REPEAT_MS) return;
    if (tool) {
      this.toolQueuedAt = this.toolQueuedAt.filter((t) => at - t < REPEAT_MS);
      if (this.toolQueuedAt.length >= MAX_TOOL_LABELS_PER_HOUR) return;
      this.toolQueuedAt.push(at);
    }
    this.lastQueued.delete(key);
    this.lastQueued.set(key, at);
    if (this.lastQueued.size > MAX_REMEMBERED)
      this.lastQueued.delete(this.lastQueued.keys().next().value!);
    this.labelQueue.push(event);
    this.trimLabelQueue();
  }

  /**
   * Sends one batch to the classifier and stores what comes back. If the
   * classifier fails, the batch goes back to the front of the queue; the
   * queue's cap drops newer events to make room for it, never the other way
   * round. (The classifier's own deadline bounds the wait.)
   */
  async labelBatch(store: Pick<Store, 'setEventLabels'>): Promise<number> {
    if (this.labelQueue.length === 0) return 0;
    const classifier = this.ai().classifier;
    if (!classifier) {
      this.labelQueue = [];
      this.retrying.clear();
      return 0;
    }
    const batch = this.labelQueue;
    this.labelQueue = [];
    this.retrying.clear();
    const giveBack = (events: readonly SensorEvent[]): void => {
      for (const e of events) this.retrying.add(e.id);
      this.labelQueue = [...events, ...this.labelQueue];
      this.trimLabelQueue();
    };
    let result: Awaited<ReturnType<typeof classifier.classify>>;
    try {
      result = await this.busyWhile('labeller', () => classifier.classify(batch));
    } catch (err) {
      giveBack(batch);
      throw err;
    }
    // Whatever wasn't labelled goes back ahead of newer events.
    const deferred = new Set(result.deferred);
    giveBack(batch.filter((e) => deferred.has(e.id)));
    if (!result.ok) {
      // A batch over the hourly budget isn't held back: the labeller ran recently.
      if (result.reason === 'busy') this.hold('labeller', MAC_BUSY);
      else if (result.reason === 'failed') this.hold('labeller', heldWhy('failed', result.detail));
      return 0;
    }
    this.unhold('labeller');
    const at = this.now();
    const labelled = result.labels.map((l) => ({
      eventId: l.eventId,
      label: {
        label: l.label,
        score: l.score,
        reason: l.reason.slice(0, 300),
        by: l.by,
        at,
      },
    }));
    store.setEventLabels(labelled);
    this.emit('note', 'labeller', labelNote(batch, result.labels));
    if (this.worthALook) {
      const byId = new Map(batch.map((e) => [e.id, e]));
      for (const l of labelled) {
        const event = byId.get(l.eventId);
        if (!event) continue;
        try {
          await this.worthALook.consider(event, l.label);
        } catch (err) {
          console.warn('[labels] could not raise a worth-a-look alert:', err);
        }
      }
    }
    return result.labels.length;
  }

  /**
   * Keep the label queue within its cap by dropping the newest events, never
   * ones a run gave back: those already waited longest.
   */
  private trimLabelQueue(): void {
    for (
      let i = this.labelQueue.length - 1;
      this.labelQueue.length > MAX_LABEL_QUEUE && i >= 0;
      i--
    )
      if (!this.retrying.has(this.labelQueue[i]!.id)) this.labelQueue.splice(i, 1);
  }

  private async busyWhile<T>(helper: HelperId, work: () => Promise<T>): Promise<T> {
    this.emit('busy', helper, true);
    try {
      return await work();
    } finally {
      this.emit('busy', helper, false);
    }
  }

  /**
   * The runner for the pack (Pack page). The Lead dog's chat is the user's
   * own request and may use their Claude plan when they opted in; pack jobs
   * and risk checks for them never do (mayUsePlan in @vigil/ai).
   */
  packAi(): PackAi {
    return {
      run: (req) => this.ai().run(req),
      modelOf: (logId) => this.models.get(logId),
      usageOf: (logId) => this.spent.get(logId),
      status: async () => {
        const v = await this.view();
        const ready = (p: AiProvider) =>
          v.providers.some((x) => x.provider === p && x.state === 'ready');
        const claudeOnKey = ready('claude') && v.anthropicKey;
        const judges = [
          claudeOnKey && 'Claude (API key)',
          ready('codex') && 'Codex',
          ready('api') && (v.api?.name ?? 'the cloud API'),
          ready('ollama') && 'the local model',
        ].filter((x): x is string => typeof x === 'string');
        const planOnly = ready('claude') && !v.anthropicKey && v.prefs.claudePlan;
        return {
          anyReady: judges.length > 0 || planOnly,
          judge: judges.length
            ? { ready: true, detail: `${judges[0]} checks risky calls` }
            : {
                ready: false,
                detail: planOnly
                  ? 'Only your Claude plan is set up, so risky calls in pack jobs are asked instead'
                  : 'No AI can check risky calls, so they are asked instead',
              },
          leadMayUsePlan: v.prefs.claudePlan && ready('claude'),
        };
      },
    };
  }

  /**
   * The user asked Vigil to explain this alert (the Explain button). The only
   * path that may use their Claude plan, when they've turned it on.
   */
  async explainOnRequest(
    core: Pick<VigilCore, 'alerts' | 'alertDetail'>,
    alertId: string,
  ): Promise<AiActionResult> {
    const detail = core.alertDetail(alertId);
    if (!detail) return { ok: false, error: 'That alert is gone' };
    const assessment = await this.explain(detail.alert, detail, true);
    if (!assessment) return { ok: false, error: 'No AI could explain it right now' };
    core.alerts.recordAssessment(alertId, assessment);
    return { ok: true };
  }

  /**
   * Asks the AI to explain a new alert in plain words. Advisory: the response
   * already ran, and nothing here changes it. Popups ask right away; other
   * alerts wait for quota headroom.
   */
  async explain(
    alert: Alert,
    detail: AlertDetail | null,
    asked = false,
  ): Promise<AiAssessment | undefined> {
    if (!detail || (alert.ai && !asked) || this.explaining.has(alert.id)) return undefined;
    this.explaining.add(alert.id);
    try {
      const urgent = asked || alert.notify === 'popup';
      const result = await this.busyWhile('explainer', () =>
        this.ai().run({
          purpose: 'explain',
          urgency: urgent ? 'now' : 'background',
          // Only an explanation the user asked for may use their Claude plan.
          ...(asked ? { requestedByUser: true } : {}),
          instructions: EXPLAIN_INSTRUCTIONS,
          data: explainData(detail),
          output: Explanation,
          deadlineMs: urgent ? EXPLAIN_NOW_DEADLINE_MS : EXPLAIN_BACKGROUND_DEADLINE_MS,
        }),
      );
      const ask = `Explain the alert “${alert.title}”`;
      const subject = { kind: 'alert' as const, id: alert.id };
      if (!result.ok) {
        // A background run that never reached an AI isn't worth a note.
        if (asked || !NOTHING_RAN.has(result.reason))
          this.emit('note', 'explainer', {
            kind: 'explain',
            ok: false,
            ask,
            subject,
            answer: whyNot(result.reason),
          });
        return undefined;
      }
      const v = result.value;
      this.emit('note', 'explainer', {
        kind: 'explain',
        ok: true,
        ask,
        subject,
        lookedAt: ['The alert, its evidence and the program behind it'],
        answer: `${VERDICT_WORDS[v.verdict]}. ${v.summary}`,
        reasons: v.details ? [v.details] : [],
        provider: result.provider,
        ...this.ranOn(result.logId),
      });
      return {
        provider: result.provider,
        ...(this.models.has(result.logId) ? { model: this.models.get(result.logId)! } : {}),
        at: this.now(),
        verdict: v.verdict,
        ...(v.confidence !== undefined ? { confidence: v.confidence } : {}),
        summary: v.summary,
        ...(v.details ? { details: v.details } : {}),
        proposalIds: [],
      };
    } finally {
      this.explaining.delete(alert.id);
    }
  }
}

function providerView(s: ProviderStatus, codexShared: boolean, codexOnKey = false): AiProviderView {
  const provider = s.provider as Exclude<ProviderId, 'jev'>;
  // On an OpenAI API key, Codex's sign-in buttons don't apply.
  const noSignIn = provider === 'codex' && codexOnKey;
  return {
    provider,
    name: NAMES[provider],
    local: provider === 'ollama',
    state: s.state,
    ...(s.version ? { version: s.version } : {}),
    ...(s.account ? { account: provider === 'claude' ? claudeAuth(s.account) : s.account } : {}),
    ...(s.detail ? { detail: s.detail } : {}),
    canSignIn: !noSignIn && s.canSignIn === true,
    canShareSignIn: !noSignIn && s.canShareSignIn === true,
    signInShared: !noSignIn && provider === 'codex' && codexShared,
  };
}

/** Claude Code reports how it's signed in, not who; say it in words. */
function claudeAuth(method: string): string {
  const words: Record<string, string> = {
    'claude.ai': 'Signed in with your Claude account',
    oauth_token: 'Signed in with a Claude token',
    api_key: 'Signed in with an API key',
    apiKey: 'Signed in with an API key',
  };
  return words[method] ?? method;
}

const Explanation = z.object({
  verdict: z.enum(['likely_malicious', 'suspicious', 'likely_benign', 'unsure']),
  confidence: z.number().min(0).max(1).optional(),
  summary: z.string().min(1).max(600),
  details: z.string().max(2000).optional(),
});

const CAP_USED_UP = 'This month’s spending cap on your API keys is used up';
const NO_AI_READY = 'No AI app is ready';
const MAC_BUSY = 'The Mac has been busy or on battery';

/** Which held-back reason matters most when several come up. */
function heldRank(why: string): number {
  if (why === CAP_USED_UP) return 3;
  if (why === NO_AI_READY) return 2;
  if (why === MAC_BUSY) return 0;
  return 1;
}

/** In words, why a helper's runs aren't reaching an AI. */
function heldWhy(outcome: string, detail: string | undefined): string {
  if (detail === MONTHLY_CAP_HELD) return CAP_USED_UP;
  if (detail === PLAN_LIMITS_HELD || outcome === 'quota')
    return 'Your AI plans are near their limits';
  if (outcome === 'no_provider' || detail === 'no_provider') return NO_AI_READY;
  if (detail === 'quota') return 'Your AI plans are near their limits';
  return detail ? `Its tries keep failing (${detail.slice(0, 160)})` : whyNot(outcome);
}

/** Failures where no AI ran at all. */
const NOTHING_RAN = new Set(['no_provider', 'quota']);

function whyNot(reason: string): string {
  switch (reason) {
    case 'no_provider':
      return 'No AI was ready';
    case 'quota':
      return 'The AI’s limit was used up';
    case 'timeout':
      return 'It took too long and was stopped';
    case 'invalid_output':
      return 'The answer came back garbled';
    default:
      return 'Something went wrong';
  }
}

const VERDICT_WORDS: Record<z.infer<typeof Explanation>['verdict'], string> = {
  likely_malicious: 'Likely malicious',
  suspicious: 'Suspicious',
  likely_benign: 'Likely fine',
  unsure: 'Unsure',
};

/** The rationale the rule reviewer wrote for each change it proposed. */
function reviewReasons(value: unknown): string[] {
  if (!value || typeof value !== 'object') return [];
  const out: string[] = [];
  for (const list of ['newRules', 'tunings', 'retirements'] as const) {
    const items = (value as Record<string, unknown>)[list];
    if (!Array.isArray(items)) continue;
    for (const it of items) {
      const why = (it as { rationale?: unknown } | null)?.rationale;
      if (typeof why === 'string' && why.trim()) out.push(why);
    }
  }
  return out;
}

/** One notebook entry per labelling batch: what was looked at, and why anything stood out. */
function labelNote(
  batch: readonly SensorEvent[],
  labels: readonly { eventId: string; label: string; score: number; reason: string; by: string }[],
): Omit<DogNoteInput, 'dog'> {
  const byId = new Map(batch.map((e) => [e.id, e]));
  const flagged = labels.filter((l) => l.label !== 'benign' && l.reason.trim());
  return {
    kind: 'label',
    ok: true,
    ask: `Label ${batch.length} new event${batch.length === 1 ? '' : 's'}`,
    lookedAt: batch.map(describeEvent),
    answer: flagged.length
      ? `${flagged.length} of ${labels.length} stood out`
      : `All ${labels.length} looked routine`,
    reasons: flagged.map((l) => {
      const e = byId.get(l.eventId);
      return `${e ? describeEvent(e) : 'An event'} (${l.label}): ${l.reason}`;
    }),
    ...(labels.some((l) => l.by === 'jev') ? { provider: 'jev' } : {}),
  };
}

function describeEvent(e: SensorEvent): string {
  const name = (p: string | undefined) => (p ? (p.split('/').pop() ?? p) : 'a program');
  switch (e.kind) {
    case 'process.exec':
      return `${name(e.process.path)} started`;
    case 'network.connection':
      return `${name(e.process?.path)} connected to ${e.remoteHost ?? e.remoteAddress}`;
    case 'network.listen':
      return `${name(e.process?.path)} listened on port ${e.localPort}`;
    case 'file':
      return `${name(e.process?.path)} touched ${name(e.path)}`;
    default:
      return e.kind;
  }
}

const EXPLAIN_INSTRUCTIONS =
  "A security rule on this person's Mac raised the alert in the data. Explain it to someone who " +
  'is not a security expert: what the program is, what it did, and why the rule cares, in two or ' +
  'three short sentences for `summary`. Say what Vigil actually did from `actions` (a failed or ' +
  'pending action did not happen). Put anything longer in `details`. Give your read as ' +
  '`verdict` and how sure you are as `confidence`. Say `unsure` rather than guess. Never tell the ' +
  'person to allow, release or trust anything; they decide that themselves.';

/** What the AI sees of an alert: the rule, the subject and a capped list of events. */
function explainData(d: AlertDetail) {
  return {
    alert: {
      title: d.alert.title,
      summary: d.alert.summary,
      severity: d.alert.severity,
      subject: d.alert.subject,
      containment: d.alert.containment,
    },
    ...(d.rule
      ? { rule: { name: d.rule.name, description: d.rule.description, mode: d.rule.mode } }
      : {}),
    // What really happened, so the explanation never claims a block or release that failed.
    actions: d.actions.map((a) => ({
      kind: a.action.kind,
      status: a.status,
      ...(a.result?.error ? { error: a.result.error.slice(0, 200) } : {}),
    })),
    events: d.events.slice(0, MAX_EVENTS),
  };
}

function isHttps(url: string): boolean {
  try {
    return new URL(url).protocol === 'https:';
  } catch {
    return false;
  }
}
