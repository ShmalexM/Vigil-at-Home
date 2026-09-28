/**
 * Shows what a signed-in Codex actually runs with under Vigil's settings: the
 * effective feature flags, and every event of one turn that is asked to call
 * Vigil's get_finding tool. For finding out why a run calls no tools. Reads
 * no credentials; it only talks to the app server. Run on request:
 *
 *   VIGIL_CODEX_DIAGNOSE=1 VIGIL_CODEX_HOME=<signed-in dir> pnpm --filter @vigil/ai test:live
 */
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { z } from 'zod';
import { buildChildEnv } from '../env.js';
import { findExecutable } from '../executable.js';
import {
  CODEX_DISABLED_FEATURES,
  codexAppServerArgs,
  codexThreadStartParams,
  codexTurnStartParams,
} from '../providers/codex.js';
import { JsonRpcStdio } from '../providers/jsonRpcStdio.js';
import { readTool } from '../tools.js';

const home = process.env.VIGIL_CODEX_HOME;

describe.skipIf(!process.env.VIGIL_CODEX_DIAGNOSE || !home)('Codex diagnosis', () => {
  it('prints effective features and one turn of events', async () => {
    const binary = await findExecutable('codex');
    expect(binary).toBeTruthy();
    const cwd = await mkdtemp(join(tmpdir(), 'vigil-codex-diag-'));
    const lines: string[] = [];
    const say = (s: string) => {
      lines.push(s);
      console.log(`codex-diag: ${s}`);
    };
    let settle!: () => void;
    const done = new Promise<void>((r) => (settle = r));
    const rpc = new JsonRpcStdio(
      binary!,
      codexAppServerArgs(),
      buildChildEnv({ CODEX_HOME: home }),
      cwd,
      {
        async onRequest(method, params) {
          const p = params as Record<string, unknown>;
          say(`request ${method} ${JSON.stringify({ tool: p.tool, namespace: p.namespace })}`);
          if (method === 'item/tool/call' && p.tool === 'get_finding' && !p.namespace)
            return {
              success: true,
              contentItems: [{ type: 'inputText', text: '{"id":"f-1","signed":false}' }],
            };
          return { success: false, contentItems: [{ type: 'inputText', text: 'Not allowed.' }] };
        },
        onNotification(method, params) {
          const p = params as {
            item?: { type?: string; tool?: string; name?: string; text?: string };
            turn?: { status?: string };
          };
          if (method.endsWith('/delta')) return;
          const item = p.item
            ? ` item=${p.item.type}${p.item.tool ? `:${p.item.tool}` : ''}${p.item.name ? `:${p.item.name}` : ''}`
            : '';
          say(`${method}${item}${p.turn ? ` turn=${p.turn.status}` : ''}`);
          if (method === 'item/completed' && p.item?.type === 'agentMessage')
            say(`answer ${String(p.item.text).slice(0, 300)}`);
          if (method === 'turn/completed') settle();
        },
      },
    );
    try {
      const init = await rpc.request<Record<string, unknown>>('initialize', {
        clientInfo: { name: 'vigil_diag', title: null, version: '0' },
        capabilities: { experimentalApi: true, requestAttestation: false },
      });
      say(`initialize ${JSON.stringify(init).slice(0, 300)}`);
      rpc.notify('initialized');
      const { account } = await rpc.request<{ account: { type: string } | null }>(
        'account/read',
        {},
      );
      say(`account type ${account?.type ?? 'none'}`);
      const { config } = await rpc.request<{
        config: Record<string, unknown> & { features?: Record<string, unknown> };
      }>('config/read', {});
      const on = Object.entries(config.features ?? {})
        .filter(([, v]) => v === true)
        .map(([k]) => k);
      say(`features on: ${on.join(', ')}`);
      const notOff = CODEX_DISABLED_FEATURES.filter((f) => config.features?.[f] !== false);
      say(`disabled list not off: ${notOff.join(', ') || 'none'}`);
      say(`model ${String(config.model)} provider ${String(config.model_provider)}`);
      const tool = readTool({
        name: 'get_finding',
        description: 'Read one finding by id.',
        input: { id: z.string() },
        run: async () => ({}),
      });
      const thread = await rpc.request<Record<string, unknown> & { thread: { id: string } }>(
        'thread/start',
        codexThreadStartParams({
          cwd,
          systemPrompt: 'You help Vigil explain findings.',
          tools: [tool],
        }),
      );
      say(`thread/start ${JSON.stringify({ ...thread, thread: undefined }).slice(0, 400)}`);
      await rpc.request(
        'turn/start',
        codexTurnStartParams({
          threadId: thread.thread.id,
          userPrompt:
            'Call the get_finding tool with id "f-1", then list every tool you can call, by exact name, in tools.',
          jsonSchema: {
            type: 'object',
            properties: { tools: { type: 'array', items: { type: 'string' } } },
            required: ['tools'],
            additionalProperties: false,
          },
        }),
      );
      await Promise.race([done, new Promise((r) => setTimeout(r, 120_000))]);
    } finally {
      rpc.close();
    }
  }, 180_000);
});
