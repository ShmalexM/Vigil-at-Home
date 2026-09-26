import { randomUUID } from 'node:crypto';
import { z } from 'zod';
import { buildSystemPrompt, buildUserPrompt } from './prompt.js';
import { QuotaTracker } from './quota.js';
import { redactAndSerialize, redactValue } from './redact.js';
import type { AiSettings } from './settings.js';
import type {
  AdapterRunOutput,
  PromptLog,
  ProviderAdapter,
  ProviderId,
  ProviderStatus,
  ReadTool,
  RunFailureReason,
  SignInFlow,
  RunRequest,
  RunResult,
  ToolAudit,
} from './types.js';

const STATUS_TTL_MS = 5 * 60_000;

export interface AiRunner {
  run<T>(request: RunRequest<T>): Promise<RunResult<T> & { readonly audit?: ToolAudit }>;
  /** Fresh status for every configured provider, for the settings screen. */
  status(): Promise<ProviderStatus[]>;
  /**
   * Starts a provider's own sign-in in the browser, when `status()` reports
   * `canSignIn`. The provider is re-checked once it finishes.
   */
  signIn(provider: ProviderId): Promise<SignInFlow>;
  readonly quota: QuotaTracker;
}

export interface AiRunnerDeps {
  readonly settings: AiSettings;
  readonly adapters: readonly ProviderAdapter[];
  readonly log: PromptLog;
  readonly now?: () => number;
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
        });

      let lastReason: RunFailureReason = 'no_provider';
      let lastDetail: string | undefined;

      for (const id of deps.settings.order) {
        const adapter = adapters.get(id);
        if (!adapter || !enabled(deps.settings, id)) continue;
        const status = await statusOf(adapter);
        if (status.state !== 'ready') continue;
        const allowed = request.urgency === 'now' ? quota.allowNow(id) : quota.allowBackground(id);
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
            record(id, 'quota', out.audit);
            lastReason = 'quota';
            break;
          }
          if (out.kind === 'error') {
            statusCache.delete(id);
            record(id, 'error', out.audit, out.message);
            lastReason = 'error';
            lastDetail = out.message;
            break;
          }
          const parsed = request.output.safeParse(out.json);
          if (parsed.success) {
            record(id, 'ok', out.audit);
            return { ok: true, value: parsed.data, provider: id, logId, audit: out.audit };
          }
          record(id, 'invalid_output', out.audit, parsed.error.message);
          lastReason = 'invalid_output';
          lastDetail = parsed.error.message;
          prompt = `${userPrompt}\n\nYour previous answer did not match the required format: ${parsed.error.message}`;
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
