import { mkdtemp, rm } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { query } from '@anthropic-ai/claude-agent-sdk';
import { afterAll, describe, expect, it } from 'vitest';
import { z } from 'zod';
import { buildChildEnv } from '../env.js';
import {
  claudeQueryOptions,
  createClaudeAdapter,
  makeCanUseTool,
  vigilToolName,
} from './claude.js';
import { memoryPinStore } from '../executable.js';
import {
  CODEX_DISABLED_FEATURES,
  codexAppServerArgs,
  createCodexAdapter,
  codexThreadStartParams,
  codexTurnStartParams,
} from './codex.js';
import { JsonRpcStdio } from './jsonRpcStdio.js';
import { createOllamaAdapter } from './ollama.js';
import { readTool } from '../tools.js';

const require = createRequire(import.meta.url);
const getFinding = readTool({
  name: 'get_finding',
  description: 'Read one finding',
  input: { id: z.string() },
  run: async ({ id }) => ({ id, title: 'New login item' }),
});
const schema = {
  type: 'object',
  properties: { summary: { type: 'string' } },
  required: ['summary'],
  additionalProperties: false,
};
const cleanup: string[] = [];
afterAll(async () => {
  for (const dir of cleanup) await rm(dir, { recursive: true, force: true });
});
async function tempDir(prefix: string) {
  const dir = await mkdtemp(join(tmpdir(), prefix));
  cleanup.push(dir);
  return dir;
}

describe('Claude adapter settings', () => {
  const opts = claudeQueryOptions({
    executablePath: '/usr/local/bin/claude',
    cwd: '/tmp/empty',
    env: { PATH: '/bin' },
    systemPrompt: 's',
    jsonSchema: schema,
    tools: [getFinding],
    canUseTool: makeCanUseTool([getFinding], []),
    abortController: new AbortController(),
  });

  it('switches off every built-in tool and all outside configuration', () => {
    expect(opts.tools).toEqual([]);
    expect(opts.settingSources).toEqual([]);
    expect(opts.strictMcpConfig).toBe(true);
    expect(opts.plugins).toEqual([]);
    expect(opts.skills).toEqual([]);
    expect(opts.persistSession).toBe(false);
    expect(opts.permissionMode).toBe('default');
    expect(opts.allowDangerouslySkipPermissions).toBeUndefined();
    expect(opts.allowedTools).toBeUndefined();
    expect(Object.keys(opts.mcpServers ?? {})).toEqual(['vigil']);
    expect(opts.env).toEqual({ PATH: '/bin' });
  });

  it("allows only Vigil's in-process tools", async () => {
    const denied: string[] = [];
    const canUse = makeCanUseTool([getFinding], denied);
    const signal = new AbortController().signal;
    expect(
      await canUse(vigilToolName('get_finding'), {}, {
        signal,
        mcpServer: { name: 'vigil', source: 'sdk' },
      } as never),
    ).toMatchObject({ behavior: 'allow' });
    for (const name of ['Bash', 'Read', 'Write', 'WebFetch', 'mcp__vigil__delete_everything']) {
      expect(await canUse(name, {}, { signal } as never)).toMatchObject({ behavior: 'deny' });
    }
    // A server from the user's own config that happens to be named "vigil" is not trusted.
    expect(
      await canUse(vigilToolName('get_finding'), {}, {
        signal,
        mcpServer: { name: 'vigil', source: 'user' },
      } as never),
    ).toMatchObject({ behavior: 'deny' });
    expect(denied).toHaveLength(6);
  });
});

function bundledClaude(): string | undefined {
  try {
    return require.resolve(
      `@anthropic-ai/claude-agent-sdk-${process.platform}-${process.arch}/claude`,
    );
  } catch {
    return undefined;
  }
}

describe.skipIf(!bundledClaude())('Claude session as launched', () => {
  it("starts with no tools except structured output and Vigil's", async () => {
    const configDir = await tempDir('vigil-claude-config-');
    const abortController = new AbortController();
    const q = query({
      prompt: 'Say hi.',
      options: claudeQueryOptions({
        executablePath: bundledClaude()!,
        cwd: await tempDir('vigil-claude-cwd-'),
        env: buildChildEnv({ CLAUDE_CONFIG_DIR: configDir }),
        systemPrompt: 's',
        jsonSchema: schema,
        tools: [getFinding],
        canUseTool: makeCanUseTool([getFinding], []),
        abortController,
      }),
    });
    let init:
      { tools: string[]; mcp_servers: Array<{ name: string; source?: string }> } | undefined;
    try {
      for await (const message of q) {
        if (message.type === 'system' && message.subtype === 'init') {
          init = message as never;
          break;
        }
      }
    } finally {
      abortController.abort();
    }
    expect(init?.tools.sort()).toEqual(['StructuredOutput', 'mcp__vigil__get_finding']);
    expect(init?.mcp_servers.map((s) => s.name)).toEqual(['vigil']);
  }, 60_000);
});

function bundledCodex(): string | undefined {
  try {
    return join(require.resolve('@openai/codex/package.json'), '..', 'bin', 'codex.js');
  } catch {
    return undefined;
  }
}

describe('Codex adapter settings', () => {
  it('turns off shell, web search and outside configuration', () => {
    const args = codexAppServerArgs();
    expect(args).toContain('web_search="disabled"');
    for (const feature of [
      'shell_tool',
      'unified_exec',
      'code_mode_host',
      'apps',
      'plugins',
      'hooks',
      'computer_use',
      'browser_use',
    ]) {
      expect(args.join(' ')).toContain(`--disable ${feature}`);
    }
    expect(
      codexThreadStartParams({ cwd: '/tmp/e', systemPrompt: 's', tools: [getFinding] }),
    ).toMatchObject({
      approvalPolicy: 'untrusted',
      sandbox: 'read-only',
      ephemeral: true,
      dynamicTools: [{ type: 'function', name: 'get_finding' }],
    });
    expect(
      codexTurnStartParams({ threadId: 't', userPrompt: 'u', jsonSchema: schema }),
    ).toMatchObject({
      sandboxPolicy: { type: 'readOnly', networkAccess: false },
      outputSchema: schema,
    });
  });
});

describe.skipIf(!bundledCodex())('Codex app-server as launched', () => {
  it('really has shell, web search, plugins and hooks off, with a read-only sandbox', async () => {
    const codexHome = await tempDir('vigil-codex-home-');
    const cwd = await tempDir('vigil-codex-cwd-');
    const rpc = new JsonRpcStdio(
      process.execPath,
      [bundledCodex()!, ...codexAppServerArgs()],
      buildChildEnv({ CODEX_HOME: codexHome }),
      cwd,
      {
        onRequest: async () => {
          throw new Error('unexpected');
        },
        onNotification: () => {},
      },
    );
    try {
      await rpc.request('initialize', {
        clientInfo: { name: 'vigil_test', title: null, version: '0' },
        capabilities: { experimentalApi: true, requestAttestation: false },
      });
      rpc.notify('initialized');
      const { config } = await rpc.request<{
        config: {
          web_search: string;
          features: Record<string, boolean | null>;
          mcp_servers: object;
        };
      }>('config/read', {});
      expect(config.web_search).toBe('disabled');
      expect(config.mcp_servers).toEqual({});
      for (const feature of CODEX_DISABLED_FEATURES) {
        if (feature in config.features) expect(config.features[feature], feature).toBe(false);
      }
      for (const feature of ['shell_tool', 'unified_exec', 'code_mode_host', 'plugins', 'hooks']) {
        expect(config.features[feature], feature).toBe(false);
      }
      const started = await rpc.request<{
        sandbox: { type: string; networkAccess: boolean };
        approvalPolicy: string;
        thread: { environments: unknown[]; ephemeral: boolean };
      }>('thread/start', codexThreadStartParams({ cwd, systemPrompt: 's', tools: [getFinding] }));
      expect(started.sandbox).toEqual({ type: 'readOnly', networkAccess: false });
      expect(started.approvalPolicy).toBe('untrusted');
      expect(started.thread.environments).toEqual([]);
      expect(started.thread.ephemeral).toBe(true);
    } finally {
      rpc.close();
    }
  }, 60_000);
});

describe.skipIf(!bundledClaude() || !bundledCodex())('Plan usage from the real CLIs', () => {
  it('asks each CLI for its plan without calling a model or hanging', async () => {
    const claude = createClaudeAdapter({
      mode: 'subscription',
      pins: memoryPinStore(),
      executablePath: bundledClaude()!,
    });
    const codex = createCodexAdapter({
      codexHome: await tempDir('vigil-codex-usage-'),
      pins: memoryPinStore(),
      executablePath: bundledCodex()!,
    });
    const started = Date.now();
    // Neither is signed in here, so both report no plan rather than failing.
    expect(await claude.readUsage!()).toBeUndefined();
    expect(await codex.readUsage!()).toBeUndefined();
    expect(Date.now() - started).toBeLessThan(40_000);
  }, 60_000);
});

describe.skipIf(!bundledCodex())('Codex sign-in from Vigil', () => {
  it("hands back ChatGPT's own sign-in page and can be cancelled", async () => {
    const adapter = createCodexAdapter({
      codexHome: await tempDir('vigil-codex-signin-'),
      pins: memoryPinStore(),
      executablePath: bundledCodex()!,
    });
    const status = await adapter.probe();
    expect(status.state).toBe('needs_sign_in');
    const flow = await adapter.signIn!();
    expect(new URL(flow.url).origin).toBe('https://auth.openai.com');
    flow.cancel();
    expect(await flow.completed).toBe(false);
  }, 60_000);
});

describe('Ollama adapter', () => {
  it('picks the largest installed model that supports tools when none is set', async () => {
    const shown: string[] = [];
    const adapter = createOllamaAdapter({
      baseUrl: 'http://127.0.0.1:11434',
      fetch: (async (url: string, init?: RequestInit) => {
        if (url.endsWith('/api/tags'))
          return Response.json({
            models: [
              { name: 'small-tools:1b', size: 1 },
              { name: 'big-no-tools:70b', size: 70 },
              { name: 'mid-tools:8b', size: 8 },
            ],
          });
        const model = (JSON.parse(String(init?.body)) as { model: string }).model;
        shown.push(model);
        return Response.json({
          capabilities: model.includes('no-tools') ? ['completion'] : ['completion', 'tools'],
        });
      }) as typeof fetch,
    });
    expect(await adapter.probe()).toMatchObject({ state: 'ready', version: 'mid-tools:8b' });
    expect(shown).toEqual(['big-no-tools:70b', 'mid-tools:8b']);
  });

  it('reports a set model that is not installed', async () => {
    const adapter = createOllamaAdapter({
      baseUrl: 'http://127.0.0.1:11434',
      model: 'gpt-oss:20b',
      fetch: (async () => Response.json({ models: [{ name: 'other:1b' }] })) as typeof fetch,
    });
    expect(await adapter.probe()).toMatchObject({
      state: 'not_installed',
      detail: 'Run: ollama pull gpt-oss:20b',
    });
  });

  it("runs Vigil's tools itself and refuses any other tool", async () => {
    const replies = [
      {
        message: {
          role: 'assistant',
          content: '',
          tool_calls: [
            { function: { name: 'run_shell', arguments: { cmd: 'id' } } },
            { function: { name: 'get_finding', arguments: { id: 'f1' } } },
          ],
        },
      },
      { message: { role: 'assistant', content: '{"summary":"done"}' } },
    ];
    const bodies: Array<{ messages: Array<{ role: string; content: string }> }> = [];
    const adapter = createOllamaAdapter({
      baseUrl: 'http://127.0.0.1:11434',
      model: 'm',
      fetch: (async (_url: string, init: RequestInit) => {
        bodies.push(JSON.parse(String(init.body)));
        return new Response(JSON.stringify(replies.shift()));
      }) as typeof fetch,
    });
    const out = await adapter.run({
      systemPrompt: 's',
      userPrompt: 'u',
      jsonSchema: schema,
      tools: [getFinding],
      signal: new AbortController().signal,
      onUsage: () => {},
    });
    expect(out).toMatchObject({
      kind: 'ok',
      json: { summary: 'done' },
      audit: { called: ['get_finding'], denied: ['tool: run_shell'] },
    });
    const toolMessages = bodies[1]!.messages.filter((m) => m.role === 'tool');
    expect(toolMessages[0]?.content).toBe('Not allowed.');
    expect(JSON.parse(toolMessages[1]?.content ?? '')).toEqual({
      id: 'f1',
      title: 'New login item',
    });
  });
});
