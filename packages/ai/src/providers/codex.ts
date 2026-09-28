import { execFile } from 'node:child_process';
import { mkdir, mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { promisify } from 'node:util';
import { buildChildEnv } from '../env.js';
import type { PinStore } from '../executable.js';
import { callTool, toolJsonSchema } from '../tools.js';
import type {
  AdapterRunInput,
  AdapterRunOutput,
  PlanUsage,
  ProviderAdapter,
  ProviderStatus,
  SignInFlow,
  RunUsage,
  ToolAudit,
  UsageWindow,
} from '../types.js';
import { JsonRpcStdio } from './jsonRpcStdio.js';
import { verifyBinary } from './verifyBinary.js';

const execFileAsync = promisify(execFile);

/** The Codex version these settings were checked against. */
export const CODEX_TESTED_VERSION = '0.157.1';

const SIGN_IN_TIMEOUT_MS = 10 * 60_000;

/**
 * Codex features that give the agent hands or pull in outside configuration.
 * All off. An unknown name makes Codex refuse to start, which fails closed.
 */
export const CODEX_DISABLED_FEATURES = [
  'shell_tool',
  'unified_exec',
  'code_mode_host',
  'apps',
  'plugins',
  'remote_plugin',
  'browser_use',
  'browser_use_external',
  'in_app_browser',
  'computer_use',
  'multi_agent',
  'multi_agent_v2',
  'code_mode',
  'code_mode_only',
  'default_mode_request_user_input',
  'request_permissions_tool',
  'sleep_tool',
  'realtime_conversation',
  'hooks',
  'image_generation',
  'view_image',
  'memories',
  'skill_search',
  'skill_mcp_dependency_install',
  'tool_suggest',
  'goals',
  'worktrees',
  'workspace_dependencies',
] as const;

/**
 * The model Vigil asks Codex for. Codex runs its newer models (GPT-6, GPT-5.6) in "code mode":
 * every tool, Vigil's included, sits behind a JavaScript runner alongside agent and question
 * tools, and in Vigil's runs the model answered without calling any of them. This model gets
 * Vigil's tools directly and nothing else. Recheck on Codex upgrades.
 */
export const CODEX_MODEL = 'gpt-5.5';

export function codexAppServerArgs(): string[] {
  const args = [
    'app-server',
    '-c',
    'web_search="disabled"',
    '-c',
    'history.persistence="none"',
    // Otherwise the model is offered a tool to ask the user questions mid-run.
    '-c',
    'tools.experimental_request_user_input.enabled=false',
  ];
  for (const feature of CODEX_DISABLED_FEATURES) args.push('--disable', feature);
  return args;
}

export function codexThreadStartParams(params: {
  cwd: string;
  systemPrompt: string;
  tools: AdapterRunInput['tools'];
}): Record<string, unknown> {
  return {
    cwd: params.cwd,
    model: CODEX_MODEL,
    approvalPolicy: 'untrusted',
    sandbox: 'read-only',
    ephemeral: true,
    // No execution environment at all, so there is nothing for a command to run in.
    environments: [],
    baseInstructions: params.systemPrompt,
    dynamicTools: params.tools.map((t) => ({
      type: 'function',
      name: t.name,
      description: t.description,
      inputSchema: toolJsonSchema(t),
    })),
  };
}

export function codexTurnStartParams(params: {
  threadId: string;
  userPrompt: string;
  jsonSchema: Record<string, unknown>;
}): Record<string, unknown> {
  return {
    threadId: params.threadId,
    input: [{ type: 'text', text: params.userPrompt, text_elements: [] }],
    outputSchema: params.jsonSchema,
    approvalPolicy: 'untrusted',
    sandboxPolicy: { type: 'readOnly', networkAccess: false },
  };
}

/** Thread items that mean the agent did something other than talk or call a Vigil tool. */
const FORBIDDEN_ITEMS = new Set([
  'commandExecution',
  'fileChange',
  'webSearch',
  'mcpToolCall',
  'imageView',
  'imageGeneration',
  'collabAgentToolCall',
]);

interface RateLimitWindow {
  usedPercent: number;
  resetsAt: number | null;
}

function usageFromSnapshot(snapshot: {
  limitId?: string | null;
  primary?: RateLimitWindow | null;
  secondary?: RateLimitWindow | null;
}): UsageWindow[] {
  const prefix = snapshot.limitId ?? 'codex';
  const out: UsageWindow[] = [];
  for (const [name, w] of [
    ['primary', snapshot.primary],
    ['secondary', snapshot.secondary],
  ] as const) {
    if (!w) continue;
    out.push({
      provider: 'codex',
      windowId: `${prefix}:${name}`,
      usedPercent: w.usedPercent,
      ...(w.resetsAt ? { resetsAt: w.resetsAt * 1000 } : {}),
    });
  }
  return out;
}

/** The fields Vigil reads from the notifications it handles. */
interface CodexNotificationParams {
  item?: { type: string; text?: string };
  rateLimits?: Parameters<typeof usageFromSnapshot>[0];
  error?: { codexErrorInfo?: unknown };
  willRetry?: boolean;
  turn?: { status: string; error: { message: string; codexErrorInfo: unknown } | null };
  tokenUsage?: {
    total: {
      inputTokens: number;
      cachedInputTokens: number;
      cacheWriteInputTokens?: number;
      outputTokens: number;
    };
  };
}

/** Codex reports cached input inside inputTokens; Vigil keeps the two apart. */
function runUsageFromCodex(
  total: NonNullable<CodexNotificationParams['tokenUsage']>['total'],
): RunUsage {
  return {
    inputTokens: Math.max(0, total.inputTokens - total.cachedInputTokens),
    cachedInputTokens: total.cachedInputTokens,
    outputTokens: total.outputTokens,
    // A ChatGPT plan has no per-token price.
    costUsd: null,
    model: CODEX_MODEL,
  };
}

export interface CodexAdapterOptions {
  readonly executablePath?: string;
  readonly codexHome: string;
  readonly pins: PinStore;
}

export function createCodexAdapter(options: CodexAdapterOptions): ProviderAdapter {
  const env = () => buildChildEnv({ CODEX_HOME: options.codexHome });

  async function connect(
    binaryPath: string,
    cwd: string,
    handlers: ConstructorParameters<typeof JsonRpcStdio>[4],
  ) {
    await mkdir(options.codexHome, { recursive: true, mode: 0o700 });
    const rpc = new JsonRpcStdio(binaryPath, codexAppServerArgs(), env(), cwd, handlers);
    await rpc.request('initialize', {
      clientInfo: { name: 'vigil_at_home', title: 'Vigil at Home', version: '0.1.0' },
      // Dynamic tools, which keep Vigil's tools in Vigil's process, are an experimental API.
      capabilities: { experimentalApi: true, requestAttestation: false },
    });
    rpc.notify('initialized');
    return rpc;
  }

  return {
    id: 'codex',

    async probe(): Promise<ProviderStatus> {
      const binary = await verifyBinary('codex', 'codex', options.pins, options.executablePath);
      if (binary.state !== 'ok') return { provider: 'codex', state: binary.state };
      let rpc: JsonRpcStdio | undefined;
      try {
        const { stdout } = await execFileAsync(binary.path, ['--version'], {
          env: env(),
          timeout: 15_000,
        });
        rpc = await connect(binary.path, tmpdir(), {
          onRequest: async () => {
            throw new Error('not expected during probe');
          },
          onNotification: () => {},
        });
        const account = await rpc.request<{
          account: { type: string; email?: string | null } | null;
        }>('account/read', {});
        return {
          provider: 'codex',
          state: account.account ? 'ready' : 'needs_sign_in',
          version: stdout.trim(),
          ...(account.account ? { account: account.account.email ?? account.account.type } : {}),
          ...(account.account ? {} : { detail: 'Sign in with ChatGPT from Vigil to use Codex.' }),
        };
      } catch (error) {
        return {
          provider: 'codex',
          state: 'error',
          detail: error instanceof Error ? error.message : String(error),
        };
      } finally {
        rpc?.close();
      }
    },

    /**
     * Codex's own ChatGPT sign-in for Vigil's Codex home. Codex opens a local
     * callback and stores the login itself; Vigil only opens the page. The
     * user's everyday Codex home isn't reused because Codex would also load
     * its config there, including the user's MCP servers, which the agent
     * could then call.
     */
    async signIn(): Promise<SignInFlow> {
      const binary = await verifyBinary('codex', 'codex', options.pins, options.executablePath);
      if (binary.state !== 'ok') throw new Error(`Codex: ${binary.state}`);
      let settle!: (ok: boolean) => void;
      const completed = new Promise<boolean>((resolve) => (settle = resolve));
      let loginId: string | undefined;
      const rpc = await connect(binary.path, tmpdir(), {
        onRequest: async () => {
          throw new Error('Vigil does not allow this.');
        },
        onNotification(method, params) {
          const p = params as { success?: boolean; loginId?: string | null };
          if (method === 'account/login/completed' && (!p.loginId || p.loginId === loginId))
            settle(p.success === true);
        },
      });
      const timer = setTimeout(() => settle(false), SIGN_IN_TIMEOUT_MS);
      void completed.then(() => {
        clearTimeout(timer);
        rpc.close();
      });
      try {
        const started = await rpc.request<{ type: string; loginId: string; authUrl: string }>(
          'account/login/start',
          { type: 'chatgpt' },
        );
        loginId = started.loginId;
        return {
          url: started.authUrl,
          completed,
          cancel: () => {
            void rpc.request('account/login/cancel', { loginId }).catch(() => {});
            settle(false);
          },
        };
      } catch (error) {
        settle(false);
        throw error;
      }
    },

    /** The plan's windows, from Codex's own documented account calls. No model is called. */
    async readUsage(): Promise<PlanUsage | undefined> {
      const binary = await verifyBinary('codex', 'codex', options.pins, options.executablePath);
      if (binary.state !== 'ok') return undefined;
      let rpc: JsonRpcStdio | undefined;
      try {
        rpc = await connect(binary.path, tmpdir(), {
          onRequest: async () => {
            throw new Error('Vigil does not allow this.');
          },
          onNotification: () => {},
        });
        const { account } = await rpc.request<{
          account: { type: string; planType?: string } | null;
        }>('account/read', {});
        if (account?.type !== 'chatgpt') return undefined;
        const limits = await rpc.request<{
          rateLimits: Parameters<typeof usageFromSnapshot>[0] | null;
        }>('account/rateLimits/read', {});
        return {
          ...(account.planType ? { plan: account.planType } : {}),
          windows: limits.rateLimits ? usageFromSnapshot(limits.rateLimits) : [],
        };
      } catch {
        return undefined;
      } finally {
        rpc?.close();
      }
    },

    async run(input: AdapterRunInput): Promise<AdapterRunOutput> {
      const audit: ToolAudit = { called: [], denied: [] };
      const binary = await verifyBinary('codex', 'codex', options.pins, options.executablePath);
      if (binary.state !== 'ok') return { kind: 'error', message: `Codex: ${binary.state}`, audit };

      const cwd = await mkdtemp(join(tmpdir(), 'vigil-codex-'));
      const tools = new Map(input.tools.map((t) => [t.name, t]));
      let lastMessage: string | undefined;
      let usage: RunUsage | undefined;
      let settle!: (out: AdapterRunOutput) => void;
      const done = new Promise<AdapterRunOutput>((resolve) => (settle = resolve));
      const finish = (out: AdapterRunOutput) => settle(usage ? { ...out, usage } : out);
      let rpc: JsonRpcStdio | undefined;
      const onAbort = () => finish({ kind: 'error', message: 'aborted', audit });
      input.signal.addEventListener('abort', onAbort, { once: true });

      try {
        rpc = await connect(binary.path, cwd, {
          async onRequest(method, params) {
            const p = params as Record<string, unknown>;
            switch (method) {
              case 'item/commandExecution/requestApproval':
                audit.denied.push(`command: ${String(p.command ?? '')}`.trim());
                return { decision: 'decline' };
              case 'item/fileChange/requestApproval':
                audit.denied.push('fileChange');
                return { decision: 'decline' };
              case 'item/tool/call': {
                const name = String(p.tool);
                const tool = p.namespace ? undefined : tools.get(name);
                if (!tool) {
                  audit.denied.push(`tool: ${name}`);
                  return {
                    success: false,
                    contentItems: [{ type: 'inputText', text: 'Not allowed.' }],
                  };
                }
                audit.called.push(name);
                const result = await callTool(tool, p.arguments);
                return {
                  success: result.ok,
                  contentItems: [{ type: 'inputText', text: result.text }],
                };
              }
              default:
                audit.denied.push(method);
                throw new Error('Vigil does not allow this.');
            }
          },
          onNotification(method, params) {
            const p = params as CodexNotificationParams;
            if (method === 'item/completed') {
              const item = p.item ?? { type: '' };
              if (item.type === 'agentMessage' && typeof item.text === 'string')
                lastMessage = item.text;
              else if (FORBIDDEN_ITEMS.has(item.type)) audit.denied.push(`item: ${item.type}`);
            } else if (method === 'thread/tokenUsage/updated' && p.tokenUsage) {
              usage = runUsageFromCodex(p.tokenUsage.total);
            } else if (method === 'account/rateLimits/updated') {
              usageFromSnapshot(p.rateLimits ?? {}).forEach(input.onUsage);
            } else if (method === 'error') {
              const info = p.error?.codexErrorInfo;
              if (!p.willRetry && (info === 'usageLimitExceeded' || info === 'rateLimitExceeded')) {
                finish({ kind: 'quota', audit });
              }
            } else if (method === 'turn/completed') {
              const turn = p.turn ?? { status: 'failed', error: null };
              if (turn.status !== 'completed') {
                const info = turn.error?.codexErrorInfo;
                if (info === 'usageLimitExceeded' || info === 'rateLimitExceeded')
                  finish({ kind: 'quota', audit });
                else
                  finish({
                    kind: 'error',
                    message: turn.error?.message ?? `turn ${turn.status}`,
                    audit,
                  });
              } else if (lastMessage === undefined) {
                finish({ kind: 'error', message: 'Codex returned no answer.', audit });
              } else {
                try {
                  finish({ kind: 'ok', json: JSON.parse(lastMessage), audit });
                } catch {
                  finish({ kind: 'error', message: 'Codex answer was not JSON.', audit });
                }
              }
            }
          },
        });
        const thread = await rpc.request<{ thread: { id: string } }>(
          'thread/start',
          codexThreadStartParams({ cwd, systemPrompt: input.systemPrompt, tools: input.tools }),
        );
        await rpc.request(
          'turn/start',
          codexTurnStartParams({
            threadId: thread.thread.id,
            userPrompt: input.userPrompt,
            jsonSchema: input.jsonSchema,
          }),
        );
        return await done;
      } catch (error) {
        const stderr = rpc?.stderr.join('').trim().split('\n').slice(-3).join(' ');
        const message = error instanceof Error ? error.message : String(error);
        return { kind: 'error', message: stderr ? `${message}: ${stderr}` : message, audit };
      } finally {
        input.signal.removeEventListener('abort', onAbort);
        rpc?.close();
        await rm(cwd, { recursive: true, force: true });
      }
    },
  };
}
