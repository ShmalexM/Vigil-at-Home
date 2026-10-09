import { randomUUID } from 'node:crypto';
import { z } from 'zod';
import { buildSystemPrompt, buildUserPrompt } from './prompt.js';
import { QuotaTracker } from './quota.js';
import { allowedByMode, switchedOn } from './reach.js';
import { redactAndSerialize, redactValue } from './redact.js';
import type { AiSettings } from './settings.js';
import { spendingDays, spendingLimits, spendingPlans, type SpendingSnapshot } from './spending.js';
import { MONTHLY_CAP_HELD, PLAN_LIMITS_HELD, mayUsePlan } from './types.js';
import type {
  AdapterRunOutput,
  PromptLog,
  PromptLogEntry,
  ProviderAdapter,
  ProviderId,
  ProviderStatus,
  ReadTool,
  RunFailureReason,
  SignInFlow,
  RunRequest,
  RunResult,
  RunUsage,
  ToolAudit,
} from './types.js';

const STATUS_TTL_MS = 5 * 60_000;
/** A probe that timed out is asked again this soon. */
const TIMED_OUT_STATUS_TTL_MS = 30_000;
const PLAN_USAGE_TTL_MS = 5 * 60_000;
const DAY_MS = 24 * 60 * 60_000;

export interface AiRunner {
  run<T>(request: RunRequest<T>): Promise<RunResult<T> & { readonly audit?: ToolAudit }>;
  /** Fresh status for every configured provider, for the settings screen. */
  status(): Promise<ProviderStatus[]>;
  /**
   * Starts a provider's own sign-in in the browser, when `status()` reports
   * `canSignIn`. The provider is re-checked once it finishes.
   */
  signIn(provider: ProviderId): Promise<SignInFlow>;
  /**
   * For the spending page: each plan's windows with Vigil's share, and Vigil's
   * own runs per day from the prompt log the app keeps. Asks each signed-in
   * vendor CLI for fresh plan numbers at most every few minutes.
   */
  spending(log: Iterable<PromptLogEntry>, options?: { days?: number }): Promise<SpendingSnapshot>;
  readonly quota: QuotaTracker;
}

export interface AiRunnerDeps {
  readonly settings: AiSettings;
  readonly adapters: readonly ProviderAdapter[];
  readonly log: PromptLog;
  readonly now?: () => number;
  /**
   * What Vigil charged to the user's keys this calendar month, all providers
   * together (log entries with `billed`). Needed only for the monthly cap.
   */
  readonly spentThisMonthUsd?: () => Promise<number>;
  /** Another runner's quota, so a second runner on the same plans keeps within one share. */
  readonly quota?: QuotaTracker;
}

export function jsonSchemaFor(output: z.ZodType): Record<string, unknown> {
  const schema = z.toJSONSchema(output, { io: 'output' }) as Record<string, unknown>;
  delete schema.$schema;
  return schema;
}

export { allowedByMode };

function enabled(settings: AiSettings, id: ProviderId): boolean {
  return switchedOn(settings, id) === undefined;
}

/** Longest a provider's probe, usage read or key lookup may take before it counts as not ready. */
export const PROBE_DEADLINE_MS = 30_000;

/** `p`, or `fallback` once `ms` passed (or p failed). Never leaves a caller waiting forever. */
function settleWithin<T, F>(p: Promise<T>, ms: number, fallback: F): Promise<T | F> {
  return new Promise((resolve) => {
    const t = setTimeout(() => resolve(fallback), ms);
    t.unref?.();
    p.then(
      (v) => (clearTimeout(t), resolve(v)),
      () => (clearTimeout(t), resolve(fallback)),
    );
  });
}

export function createAiRunner(deps: AiRunnerDeps): AiRunner {
  const now = deps.now ?? Date.now;
  const quota = deps.quota ?? new QuotaTracker(deps.settings.quota.backgroundSharePercent, now);
  const adapters = new Map(deps.adapters.map((a) => [a.id, a]));
  const statusCache = new Map<ProviderId, { status: ProviderStatus; at: number; ttl?: number }>();
  const probing = new Map<ProviderId, Promise<ProviderStatus>>();
  const redaction = deps.settings.redaction;
  const planNames = new Map<ProviderId, string>();
  let planUsageAt = -Infinity;

  async function refreshPlanUsage(): Promise<void> {
    if (now() - planUsageAt < PLAN_USAGE_TTL_MS) return;
    planUsageAt = now();
    await Promise.all(
      deps.settings.order.map(async (id) => {
        const adapter = adapters.get(id);
        if (!adapter?.readUsage || !enabled(deps.settings, id)) return;
        if ((await statusOf(adapter)).state !== 'ready') return;
        const usage = await settleWithin(adapter.readUsage(), PROBE_DEADLINE_MS, undefined);
        if (!usage) return;
        if (usage.plan) planNames.set(id, usage.plan);
        usage.windows.forEach((w) => quota.observe(w));
      }),
    );
  }

  /**
   * Whether a run on this provider is charged to one of the user's keys: the
   * Cloud API, Jev, Codex on an OpenAI key, and Claude unless this run goes to
   * the user's plan.
   */
  function billsKey(id: ProviderId, planOk: boolean): boolean {
    switch (id) {
      case 'api':
      case 'jev':
        return true;
      case 'codex':
        return deps.settings.codex.mode === 'apiKey';
      case 'claude':
        return (
          !(planOk && deps.settings.claude.allowPlan) && deps.settings.claude.mode === 'apiKey'
        );
      default:
        return false;
    }
  }

  /**
   * Whether a Claude run goes to the user's plan: the run may use it and the
   * user allows it (a subscription login implies that, as in the adapter).
   */
  function usesPlan(planOk: boolean): boolean {
    const c = deps.settings.claude;
    return planOk && (c.allowPlan ?? c.mode === 'subscription');
  }

  /** One cap for everything Vigil charges to the user's keys this month, all providers together. */
  async function overMonthlyCap(id: ProviderId, planOk: boolean): Promise<boolean> {
    const cap = deps.settings.quota.apiKeyMonthlyCapUsd;
    if (cap === undefined || !deps.spentThisMonthUsd || !billsKey(id, planOk)) return false;
    return (await deps.spentThisMonthUsd()) >= cap;
  }

  async function statusOf(adapter: ProviderAdapter, fresh = false): Promise<ProviderStatus> {
    const cached = statusCache.get(adapter.id);
    if (!fresh && cached && now() - cached.at < (cached.ttl ?? STATUS_TTL_MS)) return cached.status;
    // One probe at a time per provider: a slow one is waited on again, not started twice.
    let probe = probing.get(adapter.id);
    if (!probe) {
      probe = adapter.probe().then(
        (status) => {
          // A late answer still counts, for the next run.
          statusCache.set(adapter.id, { status, at: now() });
          return status;
        },
        (error: unknown): ProviderStatus => ({
          provider: adapter.id,
          state: 'error',
          detail: error instanceof Error ? error.message : String(error),
        }),
      );
      const settled = probe.finally(() => probing.delete(adapter.id));
      probing.set(adapter.id, settled);
      probe = settled;
    }
    // A probe that never answers (a CLI that hangs) must not hold the run, or
    // the app's scheduler slot it runs in, forever. It counts as not ready
    // only briefly, so a slow subscription CLI isn't passed over for long.
    const late = Symbol('late');
    const status = await settleWithin(probe, PROBE_DEADLINE_MS, late);
    if (status !== late) {
      statusCache.set(adapter.id, { status, at: now() });
      return status;
    }
    const timedOut: ProviderStatus = {
      provider: adapter.id,
      state: 'error',
      detail: 'It did not answer in time.',
    };
    statusCache.set(adapter.id, { status: timedOut, at: now(), ttl: TIMED_OUT_STATUS_TTL_MS });
    return timedOut;
  }

  /** Tool results go through the same redaction as the data before the model sees them. */
  function redactingTools(tools: readonly ReadTool[]): ReadTool[] {
    return tools.map((t) => ({
      ...t,
      run: async (args) => redactValue(await t.run(args), redaction),
    }));
  }

  async function runWithDeadline(
    adapter: ProviderAdapter,
    input: Omit<Parameters<ProviderAdapter['run']>[0], 'signal' | 'onUsage'>,
    signal: AbortSignal,
  ): Promise<AdapterRunOutput | 'timeout'> {
    if (signal.aborted) return 'timeout';
    const timedOut = new Promise<'timeout'>((resolve) =>
      signal.addEventListener('abort', () => resolve('timeout'), { once: true }),
    );
    return Promise.race([
      adapter.run({ ...input, signal, onUsage: (w) => quota.observe(w) }),
      timedOut,
    ]);
  }

  return {
    quota,

    async status() {
      const out: ProviderStatus[] = [];
      for (const id of deps.settings.order) {
        const adapter = adapters.get(id);
        if (!adapter) continue;
        if (deps.settings.pausedByVigil.includes(id))
          out.push({ provider: id, state: 'paused_by_vigil' });
        else if (!enabled(deps.settings, id)) out.push({ provider: id, state: 'disabled' });
        else {
          const status = await statusOf(adapter, true);
          out.push(
            status.state === 'needs_sign_in' && adapter.signIn
              ? { ...status, canSignIn: true }
              : status,
          );
        }
      }
      return out;
    },

    async spending(log, options = {}) {
      await refreshPlanUsage();
      const at = now();
      return {
        asOf: at,
        plans: spendingPlans(quota, planNames, at),
        days: spendingDays(log, at - (options.days ?? 30) * DAY_MS),
        limits: spendingLimits(deps.settings),
      };
    },

    async signIn(id) {
      const adapter = adapters.get(id);
      if (!adapter?.signIn) throw new Error(`${id} is signed in with its own app, not from Vigil.`);
      const flow = await adapter.signIn();
      void flow.completed.then(() => statusCache.delete(id));
      return flow;
    },

    async run<T>(request: RunRequest<T>) {
      // Every attempt is its own log entry with its own id, so a retry never
      // overwrites what the attempt before it cost. runId ties them together.
      const runId = randomUUID();
      let logId = runId;
      let entries = 0;
      const tools = redactingTools(request.tools ?? []);
      const systemPrompt = buildSystemPrompt(
        request.purpose,
        tools.map((t) => t.name),
      );
      const userPrompt = buildUserPrompt(
        request.instructions,
        redactAndSerialize(request.data, { ...redaction, maxBytes: redaction.maxDataBytes }),
      );
      const jsonSchema = jsonSchemaFor(request.output);
      const signal = AbortSignal.timeout(request.deadlineMs);

      const record = (
        provider: ProviderId | null,
        outcome: 'ok' | RunFailureReason,
        audit?: ToolAudit,
        detail?: string,
        usage?: RunUsage,
      ) => {
        logId = entries++ === 0 ? runId : randomUUID();
        deps.log.record({
          id: logId,
          runId,
          at: now(),
          purpose: request.purpose,
          urgency: request.urgency,
          provider,
          systemPrompt,
          userPrompt,
          outcome,
          ...(audit ? { audit } : {}),
          ...(detail ? { detail } : {}),
          ...(usage ? { usage } : {}),
          ...(usage?.model ? { model: usage.model } : {}),
          ...(provider !== null ? { billed: billsKey(provider, planOk) } : {}),
        });
      };

      const planOk = mayUsePlan(request);
      let lastReason: RunFailureReason = 'no_provider';
      let lastDetail: string | undefined;
      /** Why a ready provider was passed over without a call, when that is all that happened. */
      let held: string | undefined;

      for (const id of deps.settings.order) {
        const adapter = adapters.get(id);
        if (!adapter || !enabled(deps.settings, id)) continue;
        if (request.providers && !request.providers.includes(id)) continue;
        if (
          adapter.canServe &&
          !(await settleWithin(adapter.canServe(planOk), PROBE_DEADLINE_MS, false))
        )
          continue;
        const status = await statusOf(adapter);
        if (status.state !== 'ready') continue;
        if (!(request.urgency === 'now' ? quota.allowNow(id) : quota.allowBackground(id))) {
          lastReason = 'quota';
          held ??= PLAN_LIMITS_HELD;
          continue;
        }
        if (await overMonthlyCap(id, planOk)) {
          lastReason = 'quota';
          held = MONTHLY_CAP_HELD;
          continue;
        }

        let prompt = userPrompt;
        for (let attempt = 0; attempt < 2; attempt++) {
          const before = quota.snapshot(id);
          const out = await runWithDeadline(
            adapter,
            { systemPrompt, userPrompt: prompt, jsonSchema, tools, mayUsePlan: planOk },
            signal,
          );
          quota.attribute(id, before);

          if (out === 'timeout') {
            record(id, 'timeout');
            return { ok: false, reason: 'timeout', logId };
          }
          if (out.kind === 'quota') {
            quota.observe({
              provider: id,
              windowId: 'run',
              usedPercent: 100,
              rejected: true,
              ...(out.resetsAt ? { resetsAt: out.resetsAt } : {}),
            });
            record(id, 'quota', out.audit, undefined, out.usage);
            lastReason = 'quota';
            break;
          }
          if (out.kind === 'error') {
            statusCache.delete(id);
            record(id, 'error', out.audit, out.message, out.usage);
            lastReason = 'error';
            lastDetail = out.message;
            break;
          }
          const parsed = request.output.safeParse(out.json);
          if (parsed.success) {
            record(id, 'ok', out.audit, undefined, out.usage);
            return {
              ok: true,
              value: parsed.data,
              provider: id,
              logId,
              viaPlan: id === 'claude' && usesPlan(planOk),
              audit: out.audit,
            };
          }
          // A bare string is a reply that never became JSON, usually one cut off
          // at the output cap. Say so, with its end, instead of a schema error.
          const cutOff = typeof out.json === 'string';
          const detail = cutOff
            ? `The answer was not complete JSON (${out.usage?.outputTokens ?? '?'} output tokens), ending: ${JSON.stringify(out.json.slice(-120))}`
            : parsed.error.message;
          record(id, 'invalid_output', out.audit, detail, out.usage);
          lastReason = 'invalid_output';
          lastDetail = detail;
          prompt = cutOff
            ? `${userPrompt}\n\nYour previous answer ran too long and was cut off. Answer again with the JSON only, keeping every text field under 60 words.`
            : `${userPrompt}\n\nYour previous answer did not match the required format: ${parsed.error.message}`;
        }
      }

      // A run that reached no AI still leaves one entry, so it is never silent:
      // nothing was set up, or every ready AI was held back (the monthly cap
      // on the user's keys, or their plans' limits).
      if (lastReason === 'no_provider') record(null, 'no_provider');
      else if (entries === 0 && lastReason === 'quota') record(null, 'quota', undefined, held);
      return {
        ok: false,
        reason: lastReason,
        ...(lastDetail ? { detail: lastDetail } : {}),
        logId,
      };
    },
  };
}
