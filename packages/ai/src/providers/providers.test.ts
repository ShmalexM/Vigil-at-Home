import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { mkdtemp, readFile, readlink, rm, writeFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
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
import {
  canShareCodexSignIn,
  isCodexSignInLinkBroken,
  isCodexSignInShared,
  shareCodexSignIn,
  stopSharingCodexSignIn,
} from './codexSignIn.js';
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

describe.skipIf(!bundledCodex())('What Codex offers the model', () => {
  it("sends only Vigil's own tools, with no exec, agents or questions to the user", async () => {
    // A stand-in model server records the request Codex would send to OpenAI.
    const requests: Array<{ url?: string; tools?: Array<{ name?: string; type: string }> }> = [];
    const server = createServer((req, res) => {
      let body = '';
      req.on('data', (c) => (body += c));
      req.on('end', () => {
        requests.push({ ...(body ? JSON.parse(body) : {}), url: req.url });
        res.writeHead(400, { 'content-type': 'application/json' });
        res.end('{"error":{"message":"test server"}}');
      });
    });
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
    const { port } = server.address() as AddressInfo;
    const codexHome = await tempDir('vigil-codex-tools-');
    await writeFile(
      join(codexHome, 'config.toml'),
      [
        // A model Codex knows, so it builds the full tool list it would send.
        'model = "gpt-5.5"',
        'model_provider = "test"',
        '[model_providers.test]',
        'name = "test"',
        `base_url = "http://127.0.0.1:${port}/v1"`,
        'wire_api = "responses"',
        'experimental_bearer_token = "x"',
        'request_max_retries = 0',
        'stream_max_retries = 0',
      ].join('\n'),
    );
    try {
      const out = await createCodexAdapter({
        codexHome,
        pins: memoryPinStore(),
        executablePath: bundledCodex()!,
      }).run({
        systemPrompt: 's',
        userPrompt: 'u',
        jsonSchema: schema,
        tools: [getFinding],
        signal: AbortSignal.timeout(60_000),
        onUsage: () => {},
      });
      expect(out.kind).toBe('error');
      expect(requests.filter((r) => r.url === '/v1/responses').length).toBeGreaterThan(0);
      for (const r of requests.filter((r) => r.url === '/v1/responses'))
        expect((r.tools ?? []).map((t) => t.name ?? t.type)).toEqual(['get_finding']);
    } finally {
      server.close();
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

describe('Sharing the Codex sign-in the user already has', () => {
  it('links only auth.json, and only when the user has one', async () => {
    const user = await tempDir('vigil-user-codex-');
    const vigil = await tempDir('vigil-codex-shared-');
    expect(await canShareCodexSignIn(user)).toBe(false);
    expect(await shareCodexSignIn(vigil, user)).toEqual({ ok: false, reason: 'no_sign_in_file' });

    await writeFile(join(user, 'auth.json'), '{}', { mode: 0o600 });
    // Vigil's own earlier sign-in is replaced by the link.
    await writeFile(join(vigil, 'auth.json'), '{"vigil":true}');
    expect(await shareCodexSignIn(vigil, user)).toEqual({ ok: true });
    expect(await isCodexSignInShared(vigil)).toBe(true);
    expect(await readlink(join(vigil, 'auth.json'))).toBe(join(user, 'auth.json'));
    expect(codexAppServerArgs({ sharedSignIn: true }).join(' ')).toContain(
      'cli_auth_credentials_store="file"',
    );

    // If a Codex update ever saved by replacing the link with a copy, Vigil notices.
    expect(await isCodexSignInLinkBroken(vigil)).toBe(false);
    await rm(join(vigil, 'auth.json'));
    await writeFile(join(vigil, 'auth.json'), '{"copy":true}');
    expect(await isCodexSignInLinkBroken(vigil)).toBe(true);
    expect(
      await createCodexAdapter({
        codexHome: vigil,
        pins: memoryPinStore(),
        executablePath: '/bin/true',
      }).run({
        systemPrompt: 's',
        userPrompt: 'u',
        jsonSchema: schema,
        tools: [],
        signal: AbortSignal.timeout(5000),
        onUsage: () => {},
      }),
    ).toMatchObject({ kind: 'error', message: expect.stringContaining('replaced') });
    await shareCodexSignIn(vigil, user);
    expect(await isCodexSignInLinkBroken(vigil)).toBe(false);

    await stopSharingCodexSignIn(vigil);
    expect(await isCodexSignInShared(vigil)).toBe(false);
    expect(await isCodexSignInLinkBroken(vigil)).toBe(false);
    expect(await readFile(join(user, 'auth.json'), 'utf8')).toBe('{}');
  });

  it.skipIf(!bundledCodex())(
    "runs on the shared sign-in without the user's MCP servers or instructions",
    async () => {
      const user = await tempDir('vigil-user-codex-');
      const vigil = await tempDir('vigil-codex-shared-');
      const marker = join(user, 'mcp-server-started');
      const requests: Array<{
        instructions?: string;
        input?: unknown;
        tools?: Array<{ name?: string; type: string }>;
      }> = [];
      const server = createServer((req, res) => {
        let body = '';
        req.on('data', (c) => (body += c));
        req.on('end', () => {
          if (req.url === '/v1/responses') requests.push(JSON.parse(body));
          res.writeHead(400, { 'content-type': 'application/json' });
          res.end('{"error":{"message":"test server"}}');
        });
      });
      await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
      const { port } = server.address() as AddressInfo;
      const provider = [
        'model = "gpt-5.5"',
        'model_provider = "test"',
        '[model_providers.test]',
        'name = "test"',
        `base_url = "http://127.0.0.1:${port}/v1"`,
        'wire_api = "responses"',
        'experimental_bearer_token = "x"',
        'request_max_retries = 0',
        'stream_max_retries = 0',
      ];
      // The user's own Codex: signed in, with instructions and an MCP server that leaves a marker.
      await writeFile(
        join(user, 'config.toml'),
        [
          'developer_instructions = "USER-INSTRUCTIONS"',
          ...provider,
          '[mcp_servers.home]',
          'command = "/bin/sh"',
          `args = ["-c", "touch ${marker}; sleep 5"]`,
        ].join('\n'),
      );
      await new Promise<void>((resolve, reject) => {
        const child = spawn(process.execPath, [bundledCodex()!, 'login', '--with-api-key'], {
          env: buildChildEnv({ CODEX_HOME: user }),
        });
        child.stdin.end('sk-vigil-test');
        child.on('exit', (code) => (code === 0 ? resolve() : reject(new Error(`login ${code}`))));
      });
      const adapter = (codexHome: string) =>
        createCodexAdapter({
          codexHome,
          pins: memoryPinStore(),
          executablePath: bundledCodex()!,
          userCodexHome: user,
        });
      const run = (codexHome: string) =>
        adapter(codexHome).run({
          systemPrompt: 's',
          userPrompt: 'u',
          jsonSchema: schema,
          tools: [getFinding],
          signal: AbortSignal.timeout(60_000),
          onUsage: () => {},
        });
      try {
        expect(await adapter(vigil).probe()).toMatchObject({
          state: 'needs_sign_in',
          canShareSignIn: true,
        });
        await shareCodexSignIn(vigil, user);
        expect(await adapter(vigil).probe()).toMatchObject({ state: 'ready' });
        // A stand-in model server, so the run needs no network.
        await writeFile(join(vigil, 'config.toml'), provider.join('\n'));

        await run(vigil);
        expect(requests.length).toBeGreaterThan(0);
        expect(JSON.stringify(requests)).not.toContain('USER-INSTRUCTIONS');
        expect(requests[0]!.tools?.map((t) => t.name ?? t.type)).toEqual(['get_finding']);
        expect(existsSync(marker)).toBe(false);

        // Control: the user's own folder does bring both in, so the checks above can fail.
        requests.length = 0;
        await run(user);
        expect(JSON.stringify(requests)).toContain('USER-INSTRUCTIONS');
        expect(existsSync(marker)).toBe(true);
      } finally {
        server.close();
      }
    },
    90_000,
  );
});
