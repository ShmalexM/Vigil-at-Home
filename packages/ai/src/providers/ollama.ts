import { callTool, toolJsonSchema } from '../tools.js';
import type {
  AdapterRunInput,
  AdapterRunOutput,
  ProviderAdapter,
  ProviderStatus,
  ToolAudit,
} from '../types.js';

export interface OllamaAdapterOptions {
  readonly baseUrl: string;
  readonly model: string;
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
 * A local model through Ollama. There is no vendor agent here: Vigil runs the
 * small tool loop itself, so only Vigil's tools can ever be called.
 */
export function createOllamaAdapter(options: OllamaAdapterOptions): ProviderAdapter {
  const http = options.fetch ?? fetch;
  const base = options.baseUrl.replace(/\/$/, '');

  return {
    id: 'ollama',

    async probe(): Promise<ProviderStatus> {
      try {
        const res = await http(`${base}/api/tags`, { signal: AbortSignal.timeout(3_000) });
        if (!res.ok) return { provider: 'ollama', state: 'error', detail: `HTTP ${res.status}` };
        const body = (await res.json()) as { models?: Array<{ name: string }> };
        const names = (body.models ?? []).map((m) => m.name);
        const present = names.some((n) => n === options.model || n === `${options.model}:latest`);
        return present
          ? { provider: 'ollama', state: 'ready', version: options.model }
          : {
              provider: 'ollama',
              state: 'not_installed',
              detail: `Run: ollama pull ${options.model}`,
            };
      } catch {
        return { provider: 'ollama', state: 'not_installed', detail: 'Ollama is not running.' };
      }
    },

    async run(input: AdapterRunInput): Promise<AdapterRunOutput> {
      const audit: ToolAudit = { called: [], denied: [] };
      const tools = new Map(input.tools.map((t) => [t.name, t]));
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
              model: options.model,
              messages,
              stream: false,
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
          const body = (await res.json()) as { message: ChatMessage };
          const calls = body.message.tool_calls ?? [];
          if (calls.length === 0) {
            try {
              return { kind: 'ok', json: JSON.parse(body.message.content), audit };
            } catch {
              return { kind: 'error', message: 'Ollama answer was not JSON.', audit };
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
        return { kind: 'error', message: 'Too many tool calls.', audit };
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
