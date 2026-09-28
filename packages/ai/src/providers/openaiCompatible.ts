import { callTool, toolJsonSchema } from '../tools.js';
import type {
  AdapterRunInput,
  AdapterRunOutput,
  ProviderAdapter,
  ProviderStatus,
  RunUsage,
  ToolAudit,
} from '../types.js';

export interface ApiAdapterOptions {
  /** For example https://openrouter.ai/api/v1. Must be https unless it is on this Mac. */
  readonly baseUrl: string;
  readonly model?: string;
  /** Reads the key from the Keychain for each call. Vigil keeps no copy. */
  readonly getApiKey: () => Promise<string | undefined>;
  readonly fetch?: typeof fetch;
}

interface ChatMessage {
  role: 'system' | 'user' | 'assistant' | 'tool';
  content: string | null;
  tool_calls?: Array<{
    id: string;
    type: 'function';
    function: { name: string; arguments: string };
  }>;
  tool_call_id?: string;
}

interface ChatResponse {
  choices?: Array<{ message: ChatMessage; finish_reason?: string }>;
  usage?: {
    prompt_tokens?: number;
    completion_tokens?: number;
    prompt_tokens_details?: { cached_tokens?: number };
    /** OpenRouter reports what the call cost, in US dollars. */
    cost?: number;
  };
  error?: { message?: string };
}

const MAX_TOOL_ROUNDS = 6;

/** A key goes only to an https endpoint, or to one on this Mac. */
export function isSafeBaseUrl(baseUrl: string): boolean {
  try {
    const url = new URL(baseUrl);
    if (url.username || url.password) return false;
    if (url.protocol === 'https:') return true;
    return url.protocol === 'http:' && ['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname);
  } catch {
    return false;
  }
}

export interface ApiModel {
  readonly id: string;
  readonly name?: string;
  /** Whether the API says the model supports tool calls and JSON-schema answers. Unknown when absent. */
  readonly supportsTools?: boolean;
  readonly supportsStructuredOutput?: boolean;
}

/**
 * Any OpenAI-style chat API with the user's own key: OpenRouter, OpenAI, or a
 * gateway. Like Ollama, there is no vendor agent: Vigil runs the tool loop, so
 * only Vigil's tools can be called.
 */
export function createApiAdapter(options: ApiAdapterOptions): ProviderAdapter & {
  listModels(): Promise<ApiModel[]>;
} {
  const http = options.fetch ?? fetch;
  const base = options.baseUrl.replace(/\/$/, '');

  async function headers(): Promise<Record<string, string> | undefined> {
    const key = await options.getApiKey();
    if (!key) return undefined;
    return {
      authorization: `Bearer ${key}`,
      'content-type': 'application/json',
      // OpenRouter shows this name on the user's own activity page.
      'x-title': 'Vigil at Home',
    };
  }

  async function listModels(): Promise<ApiModel[]> {
    if (!isSafeBaseUrl(base)) throw new Error('The API address must use https.');
    const h = await headers();
    if (!h) throw new Error('No API key saved.');
    const res = await http(`${base}/models`, { headers: h, signal: AbortSignal.timeout(10_000) });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const body = (await res.json()) as {
      data?: Array<{ id: string; name?: string; supported_parameters?: string[] }>;
    };
    return (body.data ?? []).map((m) => ({
      id: m.id,
      ...(m.name ? { name: m.name } : {}),
      ...(m.supported_parameters
        ? {
            supportsTools: m.supported_parameters.includes('tools'),
            supportsStructuredOutput:
              m.supported_parameters.includes('structured_outputs') ||
              m.supported_parameters.includes('response_format'),
          }
        : {}),
    }));
  }

  return {
    id: 'api',
    listModels,

    async probe(): Promise<ProviderStatus> {
      if (!base || !isSafeBaseUrl(base))
        return { provider: 'api', state: 'needs_setup', detail: 'Add an https API address.' };
      const h = await headers();
      if (!h) return { provider: 'api', state: 'needs_setup', detail: 'Add an API key.' };
      if (!options.model)
        return { provider: 'api', state: 'needs_setup', detail: 'Choose a model.' };
      try {
        const res = await http(`${base}/models`, {
          headers: h,
          signal: AbortSignal.timeout(5_000),
        });
        if (res.status === 401 || res.status === 403)
          return { provider: 'api', state: 'needs_setup', detail: 'The API key was refused.' };
        if (!res.ok) return { provider: 'api', state: 'error', detail: `HTTP ${res.status}` };
        return { provider: 'api', state: 'ready', version: options.model };
      } catch (error) {
        return {
          provider: 'api',
          state: 'error',
          detail: error instanceof Error ? error.message : String(error),
        };
      }
    },

    async run(input: AdapterRunInput): Promise<AdapterRunOutput> {
      const audit: ToolAudit = { called: [], denied: [] };
      const h = await headers();
      if (!h || !options.model || !isSafeBaseUrl(base))
        return { kind: 'error', message: 'The API is not set up.', audit };
      const tools = new Map(input.tools.map((t) => [t.name, t]));
      const messages: ChatMessage[] = [
        { role: 'system', content: input.systemPrompt },
        { role: 'user', content: input.userPrompt },
      ];
      let inputTokens = 0;
      let cachedInputTokens = 0;
      let outputTokens = 0;
      let costUsd: number | null = null;
      const usage = (): RunUsage => ({
        inputTokens,
        cachedInputTokens,
        outputTokens,
        costUsd,
        model: options.model!,
      });

      try {
        for (let round = 0; round <= MAX_TOOL_ROUNDS; round++) {
          const offerTools = tools.size > 0 && round < MAX_TOOL_ROUNDS;
          const res = await http(`${base}/chat/completions`, {
            method: 'POST',
            headers: h,
            signal: input.signal,
            body: JSON.stringify({
              model: options.model,
              messages,
              response_format: {
                type: 'json_schema',
                json_schema: { name: 'vigil_answer', strict: true, schema: input.jsonSchema },
              },
              ...(offerTools
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
          if (res.status === 402 || res.status === 429)
            return { kind: 'quota', audit, usage: usage() };
          const body = (await res.json().catch(() => ({}))) as ChatResponse;
          if (!res.ok)
            return {
              kind: 'error',
              message: `API HTTP ${res.status}${body.error?.message ? `: ${body.error.message}` : ''}`,
              audit,
              usage: usage(),
            };
          const u = body.usage ?? {};
          const cached = u.prompt_tokens_details?.cached_tokens ?? 0;
          inputTokens += Math.max(0, (u.prompt_tokens ?? 0) - cached);
          cachedInputTokens += cached;
          outputTokens += u.completion_tokens ?? 0;
          if (typeof u.cost === 'number') costUsd = (costUsd ?? 0) + u.cost;

          const message = body.choices?.[0]?.message;
          if (!message)
            return { kind: 'error', message: 'The API returned no answer.', audit, usage: usage() };
          const calls = message.tool_calls ?? [];
          if (calls.length === 0) {
            try {
              return { kind: 'ok', json: JSON.parse(message.content ?? ''), audit, usage: usage() };
            } catch {
              // The runner counts this as a wrong format and asks once more.
              return { kind: 'ok', json: message.content ?? '', audit, usage: usage() };
            }
          }
          messages.push({ role: 'assistant', content: message.content ?? null, tool_calls: calls });
          for (const call of calls) {
            const tool = tools.get(call.function.name);
            let text = 'Not allowed.';
            if (tool) {
              audit.called.push(tool.name);
              let args: unknown;
              try {
                args = JSON.parse(call.function.arguments || '{}');
              } catch {
                // Left as the raw text, which fails the tool's argument check.
                args = call.function.arguments;
              }
              text = (await callTool(tool, args)).text;
            } else {
              audit.denied.push(`tool: ${call.function.name}`);
            }
            messages.push({ role: 'tool', tool_call_id: call.id, content: text });
          }
        }
        return { kind: 'error', message: 'Too many tool calls.', audit, usage: usage() };
      } catch (error) {
        return {
          kind: 'error',
          message: error instanceof Error ? error.message : String(error),
          audit,
          usage: usage(),
        };
      }
    },
  };
}
