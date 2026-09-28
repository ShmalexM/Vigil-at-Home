import { EventEmitter } from 'node:events';
import { z } from 'zod';
import {
  API_PRESETS,
  createVigilAi,
  defaultAiSettings,
  isCodexSignInShared,
  shareCodexSignIn,
  stopSharingCodexSignIn,
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
import type { ApiKeyProvider, SetupMode } from '../shared/setup.js';
import type { Store } from './db/store.js';
import type { VigilCore } from './service.js';
import { TEST_RULE } from './test-alert.js';
import { monthStart, type UsageService } from './usage.js';

const KEY_PREFS = 'ai.prefs';
const KEY_PINS = 'ai.pins';
/** An explanation for a popup should be there by the time the user reads it. */
const EXPLAIN_NOW_DEADLINE_MS = 90_000;
const EXPLAIN_BACKGROUND_DEADLINE_MS = 180_000;
/** Most events of one alert the AI sees. */
const MAX_EVENTS = 20;
const LABEL_EVERY_MS = 60_000;
/** The same program or destination is labelled at most once an hour. */
const REPEAT_MS = 60 * 60_000;
const MAX_LABEL_QUEUE = 200;
const MAX_REMEMBERED = 5_000;

/**
 * Alerts without a popup waiting for an explanation at once. More than this
 * (a burst) go unexplained, so AI work never crowds out Vigil's routine jobs.
 */
const MAX_QUEUED_BACKGROUND = 3;

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
export class AiBridge extends EventEmitter<{ changed: [] }> {
  private instance: { ai: VigilAi; key: string } | undefined;
  private readonly now: () => number;
  private readonly explaining = new Set<string>();
  private queuedBackground = 0;
  /** Events waiting for a label, oldest first. */
  private labelQueue: SensorEvent[] = [];
  private cachedPrefs: AiPrefs | undefined;
  /** When each program or destination was last queued, so repeats aren't sent again. */
  private readonly lastQueued = new Map<string, number>();
  /** The model behind recent runs, so an explanation can say who wrote it. */
  private readonly models = new Map<string, string>();

  constructor(private readonly o: AiBridgeOptions) {
    super();
    this.now = o.now ?? Date.now;
  }

  prefs(): AiPrefs {
    // Read once: `consider` asks for every event.
    if (this.cachedPrefs) return this.cachedPrefs;
    // Prefs saved by an older Vigil lack newer switches; those take their defaults.
    const saved = this.o.store.getSetting(KEY_PREFS, AiPrefs.partial(), {});
    const defined = Object.fromEntries(Object.entries(saved).filter(([, v]) => v !== undefined));
    this.cachedPrefs = AiPrefs.parse({ ...DEFAULT_AI_PREFS, ...defined });
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

  /** The settings @vigil/ai runs with. Built fresh each time from what's saved. */
  settings(): AiSettings {
    const base = defaultAiSettings(this.o.dataDir);
    const prefs = this.prefs();
    const api = this.apiConnection();
    const cap = prefs.monthlyCapUsd;
    return {
      ...base,
      mode: this.o.mode() ?? base.mode,
      claude: { ...base.claude, enabled: prefs.claude, mode: prefs.claudeUses },
      codex: { ...base.codex, enabled: prefs.codex },
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
    };
  }

  /** The runner, rebuilt whenever the settings it was made with change. */
  ai(): VigilAi {
    const settings = this.settings();
    const key = JSON.stringify(settings);
    if (this.instance?.key === key) return this.instance.ai;
    const keyOf = (p: ApiKeyProvider) => async () => this.o.keys.get(p)?.key;
    const api = this.apiConnection();
    const ai = (this.o.create ?? createVigilAi)({
      settings,
      log: { record: (entry) => this.record(entry) },
      pins: this.pins(),
      getAnthropicApiKey: keyOf('anthropic'),
      ...(api ? { getApiKey: keyOf(api.provider) } : {}),
      ...(this.o.keys.list().typesafe ? { getJevApiKey: keyOf('typesafe') } : {}),
      spentThisMonthUsd: async (p) => this.spentThisMonthUsd(p),
      ...(this.o.isBusy ? { isBusy: this.o.isBusy } : {}),
    });
    this.instance = { ai, key };
    return ai;
  }

  /** Every run, wherever it went, lands in the Usage page's store. */
  private record(entry: PromptLogEntry): void {
    if (entry.model) {
      this.models.set(entry.id, entry.model);
      if (this.models.size > 100) this.models.delete(this.models.keys().next().value!);
    }
    try {
      this.o.usage.record(entry);
    } catch (err) {
      console.error('[ai] recording a run failed:', err);
    }
  }

  /** What Vigil's runs on one provider cost since the 1st, for the monthly cap. */
  spentThisMonthUsd(provider: ProviderId): number {
    return this.o.store
      .listAiRuns(monthStart(this.now()))
      .filter((r) => r.provider === provider)
      .reduce((sum, r) => sum + (r.costUsd ?? 0), 0);
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

  /** Plan limits and key caps for the Usage page. */
  async limits() {
    const snapshot = await this.ai().spending([]);
    const cap = this.prefs().monthlyCapUsd;
    const settings = this.settings();
    return {
      plans: snapshot.plans,
      backgroundSharePercent: snapshot.limits.backgroundSharePercent,
      ...(cap !== undefined
        ? {
            caps: {
              api: cap,
              jev: cap,
              ...(settings.claude.mode === 'apiKey' ? { claude: cap } : {}),
            },
          }
        : {}),
    };
  }

  async view(): Promise<AiView> {
    const settings = this.settings();
    const statuses = await this.ai().status();
    const shared = await isCodexSignInShared(settings.codex.codexHome);
    const providers: AiProviderView[] = statuses.map((s) =>
      // With no key the API is off in the runner, but to the user it's waiting on a key.
      s.provider === 'api' && !this.apiConnection() && this.prefs().api && settings.mode !== 'local'
        ? providerView({ provider: 'api', state: 'needs_setup' }, shared)
        : providerView(s, shared),
    );
    // Jev isn't a runner provider; it rides on the keys.
    const saved = this.o.keys.list();
    const api = this.apiConnection();
    const jevVia =
      !settings.jev.enabled || settings.mode === 'local'
        ? null
        : saved.typesafe
          ? 'typesafe'
          : api?.provider === 'openrouter' && settings.api.enabled
            ? 'openrouter'
            : null;
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
      jevVia,
      checkedAt: this.now(),
    };
  }

  /** Opens the vendor's sign-in page. The login stays with the vendor's own CLI. */
  async signIn(provider: AiProvider): Promise<AiActionResult> {
    if (provider === 'jev') return { ok: false, error: 'Jev uses a saved key' };
    try {
      const flow = await this.ai().signIn(provider);
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
   * the scheduler's urgent lane; the test alert is never sent.
   */
  explainAlertsFrom(core: Pick<VigilCore, 'alerts' | 'scheduler' | 'alertDetail'>): void {
    core.alerts.on('raised', (alert) => {
      if (alert.ruleId === TEST_RULE.id) return;
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
   * Apple's own programs and repeats within an hour are skipped; the
   * classifier keeps to its hourly and CPU budgets and waits while the Mac is
   * busy. A label never blocks, allows or raises anything.
   */
  labelEventsFrom(
    core: Pick<VigilCore, 'scheduler' | 'store'> & { onIngest: VigilCore['onIngest'] },
  ): void {
    core.onIngest = (event, outcome) => this.consider(event, outcome);
    core.scheduler.every('label-events', LABEL_EVERY_MS, async () => {
      await this.labelBatch(core.store);
    });
  }

  /** Queues an event for labelling when it's worth a model's look. Cheap: runs for every event. */
  consider(event: SensorEvent, outcome: EventOutcome | undefined): void {
    if (!outcome || outcome.matches.length > 0) return;
    const key = labelKey(event);
    if (!key || !this.prefs().labelling) return;
    const at = this.now();
    const last = this.lastQueued.get(key);
    if (last !== undefined && at - last < REPEAT_MS) return;
    this.lastQueued.delete(key);
    this.lastQueued.set(key, at);
    if (this.lastQueued.size > MAX_REMEMBERED)
      this.lastQueued.delete(this.lastQueued.keys().next().value!);
    this.labelQueue.push(event);
    if (this.labelQueue.length > MAX_LABEL_QUEUE) this.labelQueue.shift();
  }

  /** Sends one batch to the classifier and stores what comes back. */
  async labelBatch(store: Pick<Store, 'setEventLabels'>): Promise<number> {
    if (this.labelQueue.length === 0) return 0;
    const classifier = this.ai().classifier;
    if (!classifier) {
      this.labelQueue = [];
      return 0;
    }
    const batch = this.labelQueue;
    this.labelQueue = [];
    const result = await classifier.classify(batch);
    // Whatever wasn't labelled goes back ahead of newer events, within the cap.
    const deferred = new Set(result.deferred);
    this.labelQueue = [...batch.filter((e) => deferred.has(e.id)), ...this.labelQueue].slice(
      -MAX_LABEL_QUEUE,
    );
    if (!result.ok) return 0;
    const at = this.now();
    store.setEventLabels(
      result.labels.map((l) => ({
        eventId: l.eventId,
        label: {
          label: l.label,
          score: l.score,
          reason: l.reason.slice(0, 300),
          by: l.by,
          at,
        },
      })),
    );
    return result.labels.length;
  }

  /**
   * Asks the AI to explain a new alert in plain words. Advisory: the response
   * already ran, and nothing here changes it. Popups ask right away; other
   * alerts wait for quota headroom.
   */
  async explain(alert: Alert, detail: AlertDetail | null): Promise<AiAssessment | undefined> {
    if (!detail || alert.ai || this.explaining.has(alert.id)) return undefined;
    this.explaining.add(alert.id);
    try {
      const urgent = alert.notify === 'popup';
      const result = await this.ai().run({
        purpose: 'explain',
        urgency: urgent ? 'now' : 'background',
        instructions: EXPLAIN_INSTRUCTIONS,
        data: explainData(detail),
        output: Explanation,
        deadlineMs: urgent ? EXPLAIN_NOW_DEADLINE_MS : EXPLAIN_BACKGROUND_DEADLINE_MS,
      });
      if (!result.ok) return undefined;
      const v = result.value;
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

function providerView(s: ProviderStatus, codexShared: boolean): AiProviderView {
  const provider = s.provider as Exclude<ProviderId, 'jev'>;
  return {
    provider,
    name: NAMES[provider],
    local: provider === 'ollama',
    state: s.state,
    ...(s.version ? { version: s.version } : {}),
    ...(s.account ? { account: provider === 'claude' ? claudeAuth(s.account) : s.account } : {}),
    ...(s.detail ? { detail: s.detail } : {}),
    canSignIn: s.canSignIn === true,
    canShareSignIn: s.canShareSignIn === true,
    signInShared: provider === 'codex' && codexShared,
  };
}

/** Claude Code reports how it's signed in, not who; say it in words. */
/**
 * What makes two events the same for labelling: the program, plus where it
 * connected. Undefined for events not worth a model's look: Apple's own
 * programs, exits, file events and system alerts.
 */
export function labelKey(e: SensorEvent): string | undefined {
  switch (e.kind) {
    case 'process.exec':
      return e.process.signing === 'apple' ? undefined : `exec:${e.process.path}`;
    case 'network.connection':
      return e.process?.signing === 'apple'
        ? undefined
        : `net:${e.process?.path ?? '?'}>${e.remoteHost ?? e.remoteAddress}:${e.remotePort ?? ''}`;
    case 'network.listen':
      return e.process?.signing === 'apple'
        ? undefined
        : `listen:${e.process?.path ?? '?'}:${e.localPort}`;
    case 'persistence':
      return e.change === 'removed' ? undefined : `persist:${e.path}`;
    case 'browser.extension':
      return e.change === 'removed' ? undefined : `ext:${e.extensionId}`;
    default:
      return undefined;
  }
}

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

const EXPLAIN_INSTRUCTIONS =
  "A security rule on this person's Mac raised the alert in the data. Explain it to someone who " +
  'is not a security expert: what the program is, what it did, and why the rule cares, in two or ' +
  'three short sentences for `summary`. Put anything longer in `details`. Give your read as ' +
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
    actions: d.actions.map((a) => ({ kind: a.action.kind, status: a.status })),
    events: d.events.slice(0, MAX_EVENTS),
  };
}
