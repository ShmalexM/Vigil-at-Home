import { callTool, toolJsonSchema } from '../tools.js';
import type {
  AdapterRunInput,
  AdapterRunOutput,
  ProviderAdapter,
  ProviderStatus,
  RunUsage,
  ToolAudit,
} from '../types.js';

export interface OllamaAdapterOptions {
  readonly baseUrl: string;
  /** A model to use. Without one, Vigil picks the largest installed model that supports tools. */
  readonly model?: string;
  /**
   * Picks among installed models when `model` is unset. Default: the largest
   * one that supports tools.
   */
  readonly pickModel?: (
    installed: ReadonlyArray<{ name: string; size?: number }>,
  ) => string | undefined;
  /** Keeps a small model light on a slow laptop. Passed to Ollama as is. */
  readonly runtime?: {
    /** Context window in tokens. */
    readonly numCtx?: number;
    /** CPU threads Ollama may use for this model. */
    readonly numThread?: number;
    /** Most tokens one reply may generate. Defaults to DEFAULT_MAX_OUTPUT_TOKENS. */
    readonly numPredict?: number;
    /** How long Ollama keeps the model in memory after a request, e.g. "1m". */
    readonly keepAlive?: string;
  };
  /** What to suggest pulling when nothing suitable is installed. */
  readonly suggestedModel?: string;
  readonly fetch?: typeof fetch;
}

interface ChatMessage {
  role: 'system' | 'user' | 'assistant' | 'tool';
  content: string;
  tool_calls?: Array<{ function: { name: string; arguments: unknown } }>;
  tool_name?: string;
}

const MAX_TOOL_ROUNDS = 6;

/**
 * Small models sometimes loop instead of closing their JSON. A cap turns that
 * into a fast invalid answer (which the runner retries) instead of minutes of
 * CPU until the deadline.
 */
export const DEFAULT_MAX_OUTPUT_TOKENS = 1024;

/**
 * A local model through Ollama. There is no vendor agent here: Vigil runs the
 * small tool loop itself, so only Vigil's tools can ever be called.
 */
export function createOllamaAdapter(options: OllamaAdapterOptions): ProviderAdapter {
  const http = options.fetch ?? fetch;
  const base = options.baseUrl.replace(/\/$/, '');
  let chosen: string | undefined;
  const rt = options.runtime;
  const runtimeOptions = {
    num_predict: rt?.numPredict ?? DEFAULT_MAX_OUTPUT_TOKENS,
    ...(rt?.numCtx !== undefined ? { num_ctx: rt.numCtx } : {}),
    ...(rt?.numThread !== undefined ? { num_thread: rt.numThread } : {}),
  };

  async function supportsTools(model: string): Promise<boolean> {
    const res = await http(`${base}/api/show`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ model }),
      signal: AbortSignal.timeout(3_000),
    });
    if (!res.ok) return false;
    const body = (await res.json()) as { capabilities?: string[] };
    return (body.capabilities ?? []).includes('tools');
  }

  /** The configured model if it's installed, otherwise the largest installed one with tool support. */
  async function pickModel(models: ReadonlyArray<{ name: string; size?: number }>) {
    if (options.model) {
      const wanted = options.model;
      return models.some((m) => m.name === wanted || m.name === `${wanted}:latest`)
        ? wanted
        : undefined;
    }
    if (options.pickModel) return options.pickModel(models);
    const bySize = [...models].sort((a, b) => (b.size ?? 0) - (a.size ?? 0));
    for (const m of bySize) if (await supportsTools(m.name)) return m.name;
    return undefined;
  }

  return {
    id: 'ollama',

    async probe(): Promise<ProviderStatus> {
      let models: Array<{ name: string; size?: number }>;
      try {
        const res = await http(`${base}/api/tags`, { signal: AbortSignal.timeout(3_000) });
        if (!res.ok) return { provider: 'ollama', state: 'error', detail: `HTTP ${res.status}` };
        models = ((await res.json()) as { models?: typeof models }).models ?? [];
      } catch {
        return { provider: 'ollama', state: 'not_installed', detail: 'Ollama is not running.' };
      }
      try {
        chosen = await pickModel(models);
      } catch (error) {
        return {
          provider: 'ollama',
          state: 'error',
          detail: error instanceof Error ? error.message : String(error),
        };
      }
      return chosen
        ? { provider: 'ollama', state: 'ready', version: chosen }
        : {
            provider: 'ollama',
            state: 'not_installed',
            detail: `Run: ollama pull ${options.model ?? options.suggestedModel ?? 'gpt-oss:20b'}`,
          };
    },

    async run(input: AdapterRunInput): Promise<AdapterRunOutput> {
      const audit: ToolAudit = { called: [], denied: [] };
      const model = options.model ?? chosen;
      if (!model) return { kind: 'error', message: 'No Ollama model with tool support.', audit };
      const tools = new Map(input.tools.map((t) => [t.name, t]));
      let inputTokens = 0;
      let outputTokens = 0;
      // Local, so there is nothing to pay.
      const usage = (): RunUsage => ({
        inputTokens,
        cachedInputTokens: 0,
        outputTokens,
        costUsd: 0,
      });
      const messages: ChatMessage[] = [
        { role: 'system', content: input.systemPrompt },
        { role: 'user', content: input.userPrompt },
      ];
      try {
        for (let round = 0; round <= MAX_TOOL_ROUNDS; round++) {
          const res = await http(`${base}/api/chat`, {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            signal: input.signal,
            body: JSON.stringify({
              model,
              messages,
              stream: false,
              options: runtimeOptions,
              ...(options.runtime?.keepAlive ? { keep_alive: options.runtime.keepAlive } : {}),
              format: input.jsonSchema,
              ...(tools.size > 0 && round < MAX_TOOL_ROUNDS
                ? {
                    tools: input.tools.map((t) => ({
                      type: 'function',
                      function: {
                        name: t.name,
                        description: t.description,
                        parameters: toolJsonSchema(t),
                      },
                    })),
                  }
                : {}),
            }),
          });
          if (!res.ok) return { kind: 'error', message: `Ollama HTTP ${res.status}`, audit };
          const body = (await res.json()) as {
            message: ChatMessage;
            prompt_eval_count?: number;
            eval_count?: number;
          };
          inputTokens += body.prompt_eval_count ?? 0;
          outputTokens += body.eval_count ?? 0;
          const calls = body.message.tool_calls ?? [];
          if (calls.length === 0) {
            try {
              return { kind: 'ok', json: JSON.parse(body.message.content), audit, usage: usage() };
            } catch {
              return {
                kind: 'error',
                message: 'Ollama answer was not JSON.',
                audit,
                usage: usage(),
              };
            }
          }
          messages.push(body.message);
          for (const call of calls) {
            const tool = tools.get(call.function.name);
            let text = 'Not allowed.';
            if (tool) {
              audit.called.push(tool.name);
              text = (await callTool(tool, call.function.arguments)).text;
            } else {
              audit.denied.push(`tool: ${call.function.name}`);
            }
            messages.push({ role: 'tool', tool_name: call.function.name, content: text });
          }
        }
        return { kind: 'error', message: 'Too many tool calls.', audit, usage: usage() };
      } catch (error) {
        return {
          kind: 'error',
          message: error instanceof Error ? error.message : String(error),
          audit,
        };
      }
    },
  };
}
