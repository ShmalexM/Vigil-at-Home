import { randomUUID } from 'node:crypto';
import { z } from 'zod';
import { buildSystemPrompt, buildUserPrompt } from './prompt.js';
import { QuotaTracker } from './quota.js';
import { redactAndSerialize, redactValue } from './redact.js';
import type { AiSettings } from './settings.js';
import { spendingDays, spendingLimits, spendingPlans, type SpendingSnapshot } from './spending.js';
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
   * What Vigil's Claude runs cost this calendar month, from the app's prompt
   * log. Needed only for the API-key monthly cap.
   */
  readonly spentThisMonthUsd?: (provider: ProviderId) => Promise<number>;
}

export function jsonSchemaFor(output: z.ZodType): Record<string, unknown> {
  const schema = z.toJSONSchema(output, { io: 'output' }) as Record<string, unknown>;
  delete schema.$schema;
  return schema;
}

function enabled(settings: AiSettings, id: ProviderId): boolean {
  if (settings.pausedByVigil.includes(id)) return false;
  return settings[id].enabled;
}

export function createAiRunner(deps: AiRunnerDeps): AiRunner {
  const now = deps.now ?? Date.now;
  const quota = new QuotaTracker(deps.settings.quota.backgroundSharePercent, now);
  const adapters = new Map(deps.adapters.map((a) => [a.id, a]));
  const statusCache = new Map<ProviderId, { status: ProviderStatus; at: number }>();
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
        const usage = await adapter.readUsage();
        if (!usage) return;
        if (usage.plan) planNames.set(id, usage.plan);
        usage.windows.forEach((w) => quota.observe(w));
      }),
    );
  }

  /** The API-key cap applies only to Claude on the user's own key. */
  async function overMonthlyCap(id: ProviderId): Promise<boolean> {
    const cap = deps.settings.quota.apiKeyMonthlyCapUsd;
    if (id !== 'claude' || deps.settings.claude.mode !== 'apiKey' || cap === undefined)
      return false;
    if (!deps.spentThisMonthUsd) return false;
    return (await deps.spentThisMonthUsd(id)) >= cap;
  }

  async function statusOf(adapter: ProviderAdapter, fresh = false): Promise<ProviderStatus> {
    const cached = statusCache.get(adapter.id);
    if (!fresh && cached && now() - cached.at < STATUS_TTL_MS) return cached.status;
    const status = await adapter.probe();
    statusCache.set(adapter.id, { status, at: now() });
    return status;
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
        else if (!deps.settings[id].enabled) out.push({ provider: id, state: 'disabled' });
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
      const logId = randomUUID();
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
      ) =>
        deps.log.record({
          id: logId,
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
        });

      let lastReason: RunFailureReason = 'no_provider';
      let lastDetail: string | undefined;

      for (const id of deps.settings.order) {
        const adapter = adapters.get(id);
        if (!adapter || !enabled(deps.settings, id)) continue;
        const status = await statusOf(adapter);
        if (status.state !== 'ready') continue;
        const allowed =
          (request.urgency === 'now' ? quota.allowNow(id) : quota.allowBackground(id)) &&
          !(await overMonthlyCap(id));
        if (!allowed) {
          lastReason = 'quota';
          continue;
        }

        let prompt = userPrompt;
        for (let attempt = 0; attempt < 2; attempt++) {
          const before = quota.snapshot(id);
          const out = await runWithDeadline(
            adapter,
            { systemPrompt, userPrompt: prompt, jsonSchema, tools },
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
            return { ok: true, value: parsed.data, provider: id, logId, audit: out.audit };
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

      if (lastReason === 'no_provider') record(null, 'no_provider');
      return {
        ok: false,
        reason: lastReason,
        ...(lastDetail ? { detail: lastDetail } : {}),
        logId,
      };
    },
  };
}
