import { execFile } from 'node:child_process';
import { mkdir, mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { promisify } from 'node:util';
import { buildChildEnv } from '../env.js';
import {
  canShareCodexSignIn,
  DEFAULT_USER_CODEX_HOME,
  isCodexSignInLinkBroken,
  isCodexSignInShared,
} from './codexSignIn.js';
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
import { isSafeBaseUrl } from './openaiCompatible.js';
import { verifyBinary } from './verifyBinary.js';

/**
 * A quick question to `codex app-server` (start-up, the account, plan limits).
 * A server that doesn't answer in this time is killed, so none lingers.
 */
const RPC_QUICK_TIMEOUT_MS = 15_000;

const execFileAsync = promisify(execFile);

/** The Codex version these settings were checked against. */
export const CODEX_TESTED_VERSION = '0.157.1';

const SIGN_IN_TIMEOUT_MS = 10 * 60_000;
const SIGN_IN_CONFIRM_TRIES = 10;
const SIGN_IN_CONFIRM_DELAY_MS = 500;

const NO_API_KEY = 'Add an OpenAI API key in Setup.';
const LINK_BROKEN =
  "Codex replaced Vigil's link to your Codex sign-in. Use your Codex sign-in again, or sign in from Vigil.";

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

/** The only address an OpenAI API key is sent to in apiKey mode. */
export const CODEX_OPENAI_BASE_URL = 'https://api.openai.com/v1';
/** The variable the key travels in, from Vigil to Codex's process only. */
export const CODEX_API_KEY_ENV = 'VIGIL_OPENAI_API_KEY';

export function codexAppServerArgs(
  opts: { sharedSignIn?: boolean; apiKey?: boolean; apiBaseUrl?: string } = {},
): string[] {
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
  // A shared sign-in lives in the linked auth.json, so read it from there
  // rather than from a Keychain entry for Vigil's own folder.
  if (opts.sharedSignIn) args.push('-c', 'cli_auth_credentials_store="file"');
  // An API key goes to OpenAI through a provider of Vigil's own, read from the
  // environment Vigil gives Codex. Codex never stores it, and no sign-in is used.
  if (opts.apiKey)
    args.push(
      '-c',
      'model_provider="vigil_openai"',
      '-c',
      `model_providers.vigil_openai={ name = "OpenAI", base_url = "${opts.apiBaseUrl ?? CODEX_OPENAI_BASE_URL}", env_key = "${CODEX_API_KEY_ENV}", wire_api = "responses" }`,
    );
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

/**
 * OpenAI's published standard price for CODEX_MODEL, in US dollars per million
 * tokens (developers.openai.com/api/docs/models/gpt-5.5, 2026-09-28). Prompts
 * over 272K input tokens cost 2x input and 1.5x output. Recheck with CODEX_MODEL.
 */
export const CODEX_API_PRICE_PER_MTOK = { input: 5, cachedInput: 0.5, output: 30 } as const;
const LONG_PROMPT_TOKENS = 272_000;

/** What an API-key run cost, from the token counts Codex reports. */
export function codexApiCostUsd(u: {
  inputTokens: number;
  cachedInputTokens: number;
  outputTokens: number;
}): number {
  const long = u.inputTokens + u.cachedInputTokens > LONG_PROMPT_TOKENS;
  const p = CODEX_API_PRICE_PER_MTOK;
  return (
    ((u.inputTokens * p.input + u.cachedInputTokens * p.cachedInput) * (long ? 2 : 1) +
      u.outputTokens * p.output * (long ? 1.5 : 1)) /
    1_000_000
  );
}

/** Codex reports cached input inside inputTokens; Vigil keeps the two apart. */
function runUsageFromCodex(
  total: NonNullable<CodexNotificationParams['tokenUsage']>['total'],
  apiKey: boolean,
): RunUsage {
  const tokens = {
    inputTokens: Math.max(0, total.inputTokens - total.cachedInputTokens),
    cachedInputTokens: total.cachedInputTokens,
    outputTokens: total.outputTokens,
  };
  return {
    ...tokens,
    // A ChatGPT plan has no per-token price; an API key pays OpenAI's list price.
    costUsd: apiKey ? codexApiCostUsd(tokens) : null,
    model: CODEX_MODEL,
  };
}

export interface CodexAdapterOptions {
  readonly executablePath?: string;
  readonly codexHome: string;
  readonly pins: PinStore;
  /** The user's everyday Codex folder, for offering its sign-in. Default ~/.codex. */
  readonly userCodexHome?: string;
  /** "subscription" (default) uses a ChatGPT sign-in. "apiKey" uses an OpenAI API key. */
  readonly mode?: 'subscription' | 'apiKey';
  /** Only used in apiKey mode. Reads the OpenAI key from the Keychain at run time. */
  readonly getApiKey?: () => Promise<string | undefined>;
  /** Tests only: a local stand-in for api.openai.com. Settings never set this. */
  readonly apiBaseUrl?: string;
}

export function createCodexAdapter(options: CodexAdapterOptions): ProviderAdapter {
  if (options.apiBaseUrl && !isSafeBaseUrl(options.apiBaseUrl))
    throw new Error('The API address must be https or on this Mac.');
  const apiKeyMode = options.mode === 'apiKey';
  const env = () => buildChildEnv({ CODEX_HOME: options.codexHome });
  /** The environment for the app server; undefined in apiKey mode when no key is saved. */
  async function serverEnv(): Promise<Record<string, string> | undefined> {
    if (!apiKeyMode) return env();
    const key = await options.getApiKey?.();
    return key
      ? buildChildEnv({ CODEX_HOME: options.codexHome, [CODEX_API_KEY_ENV]: key })
      : undefined;
  }

  async function connect(
    binaryPath: string,
    cwd: string,
    handlers: ConstructorParameters<typeof JsonRpcStdio>[4],
  ) {
    await mkdir(options.codexHome, { recursive: true, mode: 0o700 });
    const sharedSignIn = !apiKeyMode && (await isCodexSignInShared(options.codexHome));
    const childEnv = await serverEnv();
    if (!childEnv) throw new Error(NO_API_KEY);
    const rpc = new JsonRpcStdio(
      binaryPath,
      codexAppServerArgs({
        sharedSignIn,
        apiKey: apiKeyMode,
        ...(options.apiBaseUrl ? { apiBaseUrl: options.apiBaseUrl } : {}),
      }),
      childEnv,
      cwd,
      handlers,
    );
    await rpc.request(
      'initialize',
      {
        clientInfo: { name: 'vigil_at_home', title: 'Vigil at Home', version: '0.1.0' },
        // Dynamic tools, which keep Vigil's tools in Vigil's process, are an experimental API.
        capabilities: { experimentalApi: true, requestAttestation: false },
      },
      RPC_QUICK_TIMEOUT_MS,
    );
    rpc.notify('initialized');
    return rpc;
  }

  return {
    id: 'codex',

    async probe(): Promise<ProviderStatus> {
      const binary = await verifyBinary('codex', 'codex', options.pins, options.executablePath);
      if (binary.state !== 'ok') return { provider: 'codex', state: binary.state };
      if (apiKeyMode) {
        if (!(await serverEnv()))
          return { provider: 'codex', state: 'needs_setup', detail: NO_API_KEY };
        try {
          const { stdout } = await execFileAsync(binary.path, ['--version'], {
            env: env(),
            timeout: 15_000,
          });
          return {
            provider: 'codex',
            state: 'ready',
            version: stdout.trim(),
            account: 'OpenAI API key',
          };
        } catch (error) {
          return {
            provider: 'codex',
            state: 'error',
            detail: error instanceof Error ? error.message : String(error),
          };
        }
      }
      if (await isCodexSignInLinkBroken(options.codexHome))
        return {
          provider: 'codex',
          state: 'needs_sign_in',
          detail: LINK_BROKEN,
          ...((await canShareCodexSignIn(options.userCodexHome ?? DEFAULT_USER_CODEX_HOME))
            ? { canShareSignIn: true }
            : {}),
        };
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
        }>('account/read', {}, RPC_QUICK_TIMEOUT_MS);
        const canShare =
          !account.account &&
          (await canShareCodexSignIn(options.userCodexHome ?? DEFAULT_USER_CODEX_HOME));
        return {
          provider: 'codex',
          state: account.account ? 'ready' : 'needs_sign_in',
          version: stdout.trim(),
          ...(account.account ? { account: account.account.email ?? account.account.type } : {}),
          ...(account.account
            ? {}
            : {
                detail: canShare
                  ? 'Use the Codex sign-in you already have, or sign in with ChatGPT from Vigil.'
                  : 'Sign in with ChatGPT from Vigil to use Codex.',
              }),
          ...(canShare ? { canShareSignIn: true } : {}),
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
      if (apiKeyMode) throw new Error('Codex is set to use an OpenAI API key.');
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
            void (p.success === true ? confirmSignedIn() : Promise.resolve(false)).then(settle);
        },
      });
      /**
       * The browser saying "Signed in" isn't enough: report success only once
       * this Codex home reads back an account, so the app never shows a sign-in
       * that didn't stick. Waits a little for Codex to finish saving it.
       */
      async function confirmSignedIn(): Promise<boolean> {
        for (let i = 0; i < SIGN_IN_CONFIRM_TRIES; i++) {
          try {
            const { account } = await rpc.request<{ account: unknown }>('account/read', {});
            if (account) return true;
          } catch {
            // Try again below.
          }
          await new Promise((r) => setTimeout(r, SIGN_IN_CONFIRM_DELAY_MS));
        }
        return false;
      }
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
      // An API key has no plan windows.
      if (apiKeyMode) return undefined;
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
        }>('account/read', {}, RPC_QUICK_TIMEOUT_MS);
        if (account?.type !== 'chatgpt') return undefined;
        const limits = await rpc.request<{
          rateLimits: Parameters<typeof usageFromSnapshot>[0] | null;
        }>('account/rateLimits/read', {}, RPC_QUICK_TIMEOUT_MS);
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
      if (apiKeyMode && !(await serverEnv())) return { kind: 'error', message: NO_API_KEY, audit };
      if (!apiKeyMode && (await isCodexSignInLinkBroken(options.codexHome)))
        return { kind: 'error', message: LINK_BROKEN, audit };
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
              usage = runUsageFromCodex(p.tokenUsage.total, apiKeyMode);
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
