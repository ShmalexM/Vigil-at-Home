import { execFile } from 'node:child_process';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { promisify } from 'node:util';
import {
  createSdkMcpServer,
  query,
  tool as sdkTool,
  type CanUseTool,
  type Options,
  type SDKMessage,
} from '@anthropic-ai/claude-agent-sdk';
import { buildChildEnv } from '../env.js';
import type { PinStore } from '../executable.js';
import { callTool } from '../tools.js';
import type {
  AdapterRunInput,
  AdapterRunOutput,
  ProviderAdapter,
  ProviderStatus,
  ReadTool,
  UsageWindow,
} from '../types.js';
import { verifyBinary } from './verifyBinary.js';

const execFileAsync = promisify(execFile);

export const VIGIL_MCP_NAME = 'vigil';
const CLIENT_APP = 'vigil-at-home/0.1.0';

export interface ClaudeAdapterOptions {
  readonly mode: 'subscription' | 'apiKey';
  readonly executablePath?: string;
  readonly pins: PinStore;
  /** Only used in apiKey mode. Reads the key from the Keychain at run time. */
  readonly getApiKey?: () => Promise<string | undefined>;
}

export function vigilToolName(name: string): string {
  return `mcp__${VIGIL_MCP_NAME}__${name}`;
}

/** Every tool request goes through here. Only Vigil's own tools are allowed. */
export function makeCanUseTool(tools: readonly ReadTool[], denied: string[]): CanUseTool {
  const allowed = new Set(tools.map((t) => vigilToolName(t.name)));
  return async (toolName, _input, options) => {
    // Trust is keyed on the server's source, not the name: "sdk" is Vigil's in-process server.
    const source = options.mcpServer?.source;
    if (allowed.has(toolName) && (source === undefined || source === 'sdk')) {
      return { behavior: 'allow' };
    }
    denied.push(toolName);
    return { behavior: 'deny', message: 'Vigil does not allow this tool.' };
  };
}

/**
 * The locked-down options for one run. Exported so tests can check every
 * setting that keeps the agent away from the shell, files, web and the user's
 * own Claude configuration.
 */
export function claudeQueryOptions(params: {
  executablePath: string;
  cwd: string;
  env: Record<string, string>;
  systemPrompt: string;
  jsonSchema: Record<string, unknown>;
  tools: readonly ReadTool[];
  canUseTool: CanUseTool;
  abortController: AbortController;
}): Options {
  const mcpServers: Options['mcpServers'] =
    params.tools.length === 0
      ? {}
      : {
          [VIGIL_MCP_NAME]: createSdkMcpServer({
            name: VIGIL_MCP_NAME,
            version: '0.1.0',
            tools: params.tools.map((t) =>
              sdkTool(t.name, t.description, t.input, async (args) => {
                const result = await callTool(t, args);
                return {
                  content: [{ type: 'text' as const, text: result.text }],
                  isError: !result.ok,
                };
              }),
            ),
          }),
        };
  return {
    pathToClaudeCodeExecutable: params.executablePath,
    cwd: params.cwd,
    // Replaces the child environment entirely.
    env: params.env,
    systemPrompt: params.systemPrompt,
    // No built-in tools at all: no Bash, Read, Write, Edit, WebFetch, WebSearch, Task...
    tools: [],
    mcpServers,
    // Ignore .mcp.json, user settings, plugins and agent frontmatter MCP servers.
    strictMcpConfig: true,
    // Load no settings files: no user hooks, permissions, CLAUDE.md or plugins.
    settingSources: [],
    plugins: [],
    skills: [],
    // Anything not explicitly allowed by canUseTool is refused. Never bypassPermissions.
    permissionMode: 'default',
    canUseTool: params.canUseTool,
    persistSession: false,
    outputFormat: { type: 'json_schema', schema: params.jsonSchema },
    maxTurns: params.tools.length === 0 ? 3 : 10,
    abortController: params.abortController,
  };
}

function usageFromEvent(message: Extract<SDKMessage, { type: 'rate_limit_event' }>): UsageWindow[] {
  const info = message.rate_limit_info as typeof message.rate_limit_info & {
    unifiedWindows?: Record<string, { utilization?: number; resetsAt?: number }>;
  };
  const windows: UsageWindow[] = [];
  for (const [windowId, w] of Object.entries(info.unifiedWindows ?? {})) {
    if (typeof w.utilization !== 'number') continue;
    windows.push({
      provider: 'claude',
      windowId,
      usedPercent: w.utilization * 100,
      ...(w.resetsAt ? { resetsAt: w.resetsAt * 1000 } : {}),
    });
  }
  if (windows.length === 0 && info.rateLimitType && typeof info.utilization === 'number') {
    windows.push({
      provider: 'claude',
      windowId: info.rateLimitType,
      usedPercent: info.utilization * 100,
      ...(info.resetsAt ? { resetsAt: info.resetsAt * 1000 } : {}),
    });
  }
  if (info.status === 'rejected') {
    windows.push({
      provider: 'claude',
      windowId: info.rateLimitType ?? 'unknown',
      usedPercent: 100,
      rejected: true,
      ...(info.resetsAt ? { resetsAt: info.resetsAt * 1000 } : {}),
    });
  }
  return windows;
}

export function createClaudeAdapter(options: ClaudeAdapterOptions): ProviderAdapter {
  async function childEnv(): Promise<Record<string, string> | undefined> {
    const extra: Record<string, string | undefined> = { CLAUDE_AGENT_SDK_CLIENT_APP: CLIENT_APP };
    if (options.mode === 'apiKey') {
      const key = await options.getApiKey?.();
      if (!key) return undefined;
      extra.ANTHROPIC_API_KEY = key;
    }
    return buildChildEnv(extra);
  }

  return {
    id: 'claude',

    async probe(): Promise<ProviderStatus> {
      const binary = await verifyBinary('claude', 'claude', options.pins, options.executablePath);
      if (binary.state !== 'ok') return { provider: 'claude', state: binary.state };
      const env = await childEnv();
      if (!env) return { provider: 'claude', state: 'needs_sign_in', detail: 'No API key saved.' };
      try {
        const [{ stdout: version }, { stdout: auth }] = await Promise.all([
          execFileAsync(binary.path, ['--version'], { env, timeout: 15_000 }),
          execFileAsync(binary.path, ['auth', 'status', '--json'], { env, timeout: 15_000 }),
        ]);
        const status = JSON.parse(auth) as { loggedIn?: boolean; authMethod?: string };
        const signedIn = options.mode === 'apiKey' || status.loggedIn === true;
        return {
          provider: 'claude',
          state: signedIn ? 'ready' : 'needs_sign_in',
          version: version.trim(),
          ...(status.authMethod ? { account: status.authMethod } : {}),
        };
      } catch (error) {
        return {
          provider: 'claude',
          state: 'error',
          detail: error instanceof Error ? error.message : String(error),
        };
      }
    },

    async run(input: AdapterRunInput): Promise<AdapterRunOutput> {
      const audit = { called: [] as string[], denied: [] as string[] };
      const binary = await verifyBinary('claude', 'claude', options.pins, options.executablePath);
      if (binary.state !== 'ok')
        return { kind: 'error', message: `Claude Code: ${binary.state}`, audit };
      const env = await childEnv();
      if (!env) return { kind: 'error', message: 'No API key saved for Claude.', audit };

      const cwd = await mkdtemp(join(tmpdir(), 'vigil-claude-'));
      const abortController = new AbortController();
      const onAbort = () => abortController.abort();
      input.signal.addEventListener('abort', onAbort, { once: true });
      const allowedNames = new Set(input.tools.map((t) => vigilToolName(t.name)));

      try {
        const q = query({
          prompt: input.userPrompt,
          options: claudeQueryOptions({
            executablePath: binary.path,
            cwd,
            env,
            systemPrompt: input.systemPrompt,
            jsonSchema: input.jsonSchema,
            tools: input.tools,
            canUseTool: makeCanUseTool(input.tools, audit.denied),
            abortController,
          }),
        });
        for await (const message of q) {
          if (message.type === 'assistant') {
            for (const block of message.message.content) {
              if (block.type !== 'tool_use') continue;
              if (allowedNames.has(block.name)) audit.called.push(block.name);
              else if (block.name !== 'StructuredOutput' && !audit.denied.includes(block.name)) {
                audit.denied.push(block.name);
              }
            }
          } else if (message.type === 'rate_limit_event') {
            const windows = usageFromEvent(message);
            windows.forEach(input.onUsage);
            const rejected = windows.find((w) => w.rejected);
            if (rejected) {
              // Claude Code would otherwise hold the turn until the window reopens.
              abortController.abort();
              return {
                kind: 'quota',
                ...(rejected.resetsAt ? { resetsAt: rejected.resetsAt } : {}),
                audit,
              };
            }
          } else if (message.type === 'result') {
            if (message.subtype === 'success' && message.structured_output !== undefined) {
              return { kind: 'ok', json: message.structured_output, audit };
            }
            const detail = 'errors' in message ? message.errors.join('; ') : message.subtype;
            return {
              kind: 'error',
              message: detail || 'Claude returned no structured output.',
              audit,
            };
          }
        }
        return { kind: 'error', message: 'Claude ended without a result.', audit };
      } catch (error) {
        if (input.signal.aborted) return { kind: 'error', message: 'aborted', audit };
        return {
          kind: 'error',
          message: error instanceof Error ? error.message : String(error),
          audit,
        };
      } finally {
        input.signal.removeEventListener('abort', onAbort);
        await rm(cwd, { recursive: true, force: true });
      }
    },
  };
}
