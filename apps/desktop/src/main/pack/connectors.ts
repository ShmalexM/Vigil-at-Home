// Connectors: the user's own MCP servers, added on the Pack page, that pack
// dogs may call through the tool gate (gate.ts). Vigil is the MCP client;
// the model never talks to a server directly, and never sees a token.
//
// Secrets (environment values and bearer tokens) are encrypted with the
// Keychain-backed cipher the API keys use, in a file only the user can read.
// Nothing here reads another app's MCP settings (~/.claude, ~/.codex, …).
//
// A server Vigil starts runs the user's program, not Vigil's: its pid goes to
// the agent tracker (`spawned`) so Agent watch rules see it as a connector,
// and a command inside Vigil's own app is refused, because the safety floor
// never blocks Vigil's own binaries.

import {
  chmodSync,
  existsSync,
  readFileSync,
  realpathSync,
  renameSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { delimiter, isAbsolute, join, resolve } from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import {
  getDefaultEnvironment,
  StdioClientTransport,
} from '@modelcontextprotocol/sdk/client/stdio.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import type { Transport } from '@modelcontextprotocol/sdk/shared/transport.js';
import { newId } from '@vigil/core';
import { z } from 'zod';
import { ConnectorInput, type ConnectorView } from '../../shared/pack.js';
import type { Cipher } from '../onboarding/keys.js';

/** A connection with no calls for this long is closed; the next call reopens it. */
const IDLE_MS = 5 * 60_000;
const CONNECT_MS = 20_000;
const CALL_MS = 60_000;
/** Tools kept per connector. */
const MAX_TOOLS = 64;
/** A tool result longer than this is cut before the model sees it. */
const MAX_RESULT_CHARS = 32_000;

export const ConnectorRecord = z.object({
  id: z.string().regex(/^[a-z0-9-]{1,40}$/),
  name: z.string(),
  kind: z.enum(['stdio', 'http']),
  command: z.string().optional(),
  args: z.array(z.string()).optional(),
  url: z.string().optional(),
  /** Names only. Values live in the secret file. */
  secrets: z.array(z.string()),
  enabled: z.boolean(),
});
export type ConnectorRecord = z.infer<typeof ConnectorRecord>;

export interface RemoteTool {
  name: string;
  title: string;
  description: string;
  inputSchema: Record<string, unknown>;
  /** The server says the tool only reads. MCP hints are untrusted: shown, never used to skip a check. */
  readOnlyHint: boolean;
}

/** What the rest of the pack needs; tests use a fake. */
export interface ConnectorHub {
  list(): ConnectorRecord[];
  view(): ConnectorView[];
  tools(id: string): Promise<RemoteTool[]>;
  /** Tools already known, without connecting. */
  knownTools(id: string): RemoteTool[];
  call(id: string, tool: string, args: Record<string, unknown>): Promise<string>;
}

interface Live {
  client?: Client;
  connecting?: Promise<Client>;
  tools: RemoteTool[];
  state: ConnectorView['state'];
  error?: string;
  idle?: NodeJS.Timeout;
  /** The server process, for a stdio connector. */
  pid?: number;
}

const Secrets = z.record(z.string(), z.string());

/** Connectors saved in Vigil's settings, with their secrets in an encrypted file. */
export class Connectors implements ConnectorHub {
  private readonly live = new Map<string, Live>();

  constructor(
    private readonly o: {
      load: () => ConnectorRecord[];
      save: (records: ConnectorRecord[]) => void;
      secretsPath: string;
      cipher: Cipher;
      onChange: () => void;
      /** Vigil's own app (the safety floor's self paths): no connector may run a program in it. */
      selfPaths?: string[];
      /** A stdio server started (true) or was closed (false), for the agent tracker. */
      spawned?: (pid: number, running: boolean) => void;
      /** For tests. */
      connect?: (
        record: ConnectorRecord,
        secrets: Record<string, string>,
        onPid: (pid: number) => void,
      ) => Promise<Client>;
    },
  ) {}

  list(): ConnectorRecord[] {
    return this.o.load();
  }

  view(): ConnectorView[] {
    return this.list().map((r) => {
      const l = this.live.get(r.id);
      return {
        id: r.id,
        name: r.name,
        kind: r.kind,
        target: r.kind === 'stdio' ? [r.command, ...(r.args ?? [])].join(' ') : (r.url ?? ''),
        secrets: r.secrets,
        state: !r.enabled ? 'off' : (l?.state ?? 'off'),
        ...(l?.error ? { error: l.error } : {}),
        tools: l?.tools.length ?? 0,
        enabled: r.enabled,
      };
    });
  }

  add(raw: ConnectorInput): ConnectorView {
    const input = ConnectorInput.parse(raw);
    if (input.kind === 'stdio') this.assertNotVigil(input.command);
    const records = this.list();
    if (records.length >= 20) throw new Error('Twenty connectors is the most Vigil keeps');
    const id = newConnectorId(input.name, new Set(records.map((r) => r.id)));
    const secrets =
      input.kind === 'stdio' ? (input.env ?? {}) : input.token ? { token: input.token } : {};
    if (Object.keys(secrets).length > 0) {
      if (!this.o.cipher.available()) throw new Error('The macOS Keychain isn’t available');
      this.writeSecrets({ ...this.readSecrets(), [id]: JSON.stringify(secrets) });
    }
    const record: ConnectorRecord =
      input.kind === 'stdio'
        ? {
            id,
            name: input.name,
            kind: 'stdio',
            command: input.command,
            args: input.args,
            secrets: Object.keys(secrets),
            enabled: true,
          }
        : {
            id,
            name: input.name,
            kind: 'http',
            url: input.url,
            secrets: Object.keys(secrets),
            enabled: true,
          };
    this.o.save([...records, record]);
    this.o.onChange();
    return this.view().find((v) => v.id === id)!;
  }

  setEnabled(id: string, enabled: boolean): void {
    this.o.save(this.list().map((r) => (r.id === id ? { ...r, enabled } : r)));
    if (!enabled) void this.close(id);
    this.o.onChange();
  }

  remove(id: string): void {
    void this.close(id);
    this.live.delete(id);
    this.o.save(this.list().filter((r) => r.id !== id));
    const s = this.readSecrets();
    if (id in s) {
      delete s[id];
      this.writeSecrets(s);
    }
    this.o.onChange();
  }

  knownTools(id: string): RemoteTool[] {
    return this.live.get(id)?.tools ?? [];
  }

  /** Connects if needed and lists the server's tools. */
  async tools(id: string): Promise<RemoteTool[]> {
    const client = await this.client(id);
    const out: RemoteTool[] = [];
    let cursor: string | undefined;
    do {
      const page = await client.listTools(cursor ? { cursor } : {}, { timeout: CONNECT_MS });
      for (const t of page.tools) {
        if (out.length >= MAX_TOOLS) break;
        if (!/^[A-Za-z0-9_.-]{1,64}$/.test(t.name)) continue;
        out.push({
          name: t.name,
          title: t.title ?? t.annotations?.title ?? t.name,
          description: (t.description ?? '').slice(0, 1000),
          inputSchema: t.inputSchema as Record<string, unknown>,
          readOnlyHint: t.annotations?.readOnlyHint === true,
        });
      }
      cursor = page.nextCursor;
    } while (cursor && out.length < MAX_TOOLS);
    const l = this.live.get(id)!;
    l.tools = out;
    this.o.onChange();
    return out;
  }

  async call(id: string, tool: string, args: Record<string, unknown>): Promise<string> {
    const client = await this.client(id);
    const result = await client.callTool({ name: tool, arguments: args }, undefined, {
      timeout: CALL_MS,
    });
    const parts = Array.isArray(result.content) ? result.content : [];
    const text = parts
      .map((p: { type: string; text?: string }) =>
        p.type === 'text' ? (p.text ?? '') : `[${p.type} content not shown]`,
      )
      .join('\n');
    const body = text || JSON.stringify(result.structuredContent ?? {});
    const clipped = body.length > MAX_RESULT_CHARS ? `${body.slice(0, MAX_RESULT_CHARS)}…` : body;
    return result.isError ? `The tool reported an error: ${clipped}` : clipped;
  }

  async closeAll(): Promise<void> {
    await Promise.all([...this.live.keys()].map((id) => this.close(id)));
  }

  private async client(id: string): Promise<Client> {
    const record = this.list().find((r) => r.id === id);
    if (!record) throw new Error('No such connector');
    if (!record.enabled) throw new Error(`${record.name} is switched off`);
    let l = this.live.get(id);
    if (!l) {
      l = { tools: [], state: 'off' };
      this.live.set(id, l);
    }
    const live = l;
    if (live.idle) clearTimeout(live.idle);
    live.idle = setTimeout(() => void this.close(id), IDLE_MS);
    live.idle.unref?.();
    if (live.client) return live.client;
    live.connecting ??= (async () => {
      live.state = 'connecting';
      this.o.onChange();
      try {
        if (record.kind === 'stdio') this.assertNotVigil(record.command!);
        const secrets = this.secretsFor(id);
        const onPid = (pid: number) => {
          live.pid = pid;
          this.o.spawned?.(pid, true);
        };
        const client = await withTimeout(
          (this.o.connect ?? connectTo)(record, secrets, onPid),
          CONNECT_MS,
          `${record.name} didn’t answer`,
        );
        live.client = client;
        live.state = 'connected';
        delete live.error;
        return client;
      } catch (err) {
        this.stopped(live);
        live.state = 'error';
        live.error = err instanceof Error ? err.message.slice(0, 300) : String(err);
        throw err;
      } finally {
        delete live.connecting;
        this.o.onChange();
      }
    })();
    return live.connecting;
  }

  private async close(id: string): Promise<void> {
    const l = this.live.get(id);
    if (!l) return;
    if (l.idle) clearTimeout(l.idle);
    const c = l.client;
    delete l.client;
    l.state = 'off';
    try {
      await c?.close();
    } catch {
      // Already gone.
    }
    this.stopped(l);
  }

  private stopped(l: Live): void {
    if (l.pid === undefined) return;
    this.o.spawned?.(l.pid, false);
    delete l.pid;
  }

  /** Refuse a command that is part of Vigil, which the safety floor would never block. */
  private assertNotVigil(command: string): void {
    const selfPaths = (this.o.selfPaths ?? []).map((p) => p.toLowerCase().replace(/\/+$/, ''));
    if (selfPaths.length === 0) return;
    const path = whereIs(command);
    for (const candidate of path ? [path, realOr(path)] : []) {
      const p = candidate.toLowerCase();
      if (selfPaths.some((s) => p === s || p.startsWith(`${s}/`))) {
        throw new Error('That program is part of Vigil. A connector has to run its own program.');
      }
    }
  }

  private secretsFor(id: string): Record<string, string> {
    const enc = this.readSecrets()[id];
    if (!enc) return {};
    try {
      return Secrets.parse(JSON.parse(this.o.cipher.decrypt(Buffer.from(enc, 'base64'))));
    } catch {
      return {};
    }
  }

  private readSecrets(): Record<string, string> {
    if (!existsSync(this.o.secretsPath)) return {};
    try {
      const raw = Secrets.parse(JSON.parse(readFileSync(this.o.secretsPath, 'utf8')));
      return raw;
    } catch {
      return {};
    }
  }

  /** Values arrive as plain JSON per connector and are stored encrypted. */
  private writeSecrets(plain: Record<string, string>): void {
    const out: Record<string, string> = {};
    const current = this.readSecrets();
    for (const [id, v] of Object.entries(plain)) {
      out[id] = current[id] === v ? v : this.o.cipher.encrypt(v).toString('base64');
    }
    const tmp = `${this.o.secretsPath}.tmp`;
    writeFileSync(tmp, JSON.stringify(out), { mode: 0o600 });
    chmodSync(tmp, 0o600);
    renameSync(tmp, this.o.secretsPath);
  }
}

async function connectTo(
  record: ConnectorRecord,
  secrets: Record<string, string>,
  onPid: (pid: number) => void,
): Promise<Client> {
  const client = new Client({ name: 'vigil-at-home-pack', version: '1' });
  if (record.kind === 'stdio') {
    const transport = new StdioClientTransport({
      command: record.command!,
      args: record.args ?? [],
      // Only the basics (PATH, HOME…) and the user's own values for this server.
      env: { ...getDefaultEnvironment(), ...secrets },
      stderr: 'ignore',
    });
    // Report the pid as soon as the process exists, before the MCP handshake,
    // so the tracker tags the server before it can start anything.
    const start = transport.start.bind(transport);
    transport.start = async () => {
      await start();
      if (transport.pid) onPid(transport.pid);
    };
    await client.connect(transport);
  } else {
    const token = secrets['token'];
    await client.connect(
      new StreamableHTTPClientTransport(new URL(record.url!), {
        ...(token ? { requestInit: { headers: { Authorization: `Bearer ${token}` } } } : {}),
      }) as Transport,
    );
  }
  return client;
}

/** Where `command` runs from: itself when it has a slash, else the first match on PATH. */
function whereIs(command: string): string | undefined {
  if (command.includes('/')) return isAbsolute(command) ? command : resolve(command);
  const dirs = (getDefaultEnvironment()['PATH'] ?? '').split(delimiter).filter(Boolean);
  for (const dir of dirs) {
    const p = join(dir, command);
    try {
      if (statSync(p).isFile()) return p;
    } catch {
      // Not here.
    }
  }
  return undefined;
}

function realOr(path: string): string {
  try {
    return realpathSync(path);
  } catch {
    return path;
  }
}

/**
 * A connector's name as a slug: the id connectors were given before ids got
 * a part of their own, and the name rules written then use
 * (`mcp__<slug>__<tool>`). Never an identity: names repeat.
 */
export function connectorSlug(name: string): string {
  return (
    name
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-|-$/g, '')
      .slice(0, 30) || 'connector'
  );
}

/**
 * A new connector's id: its name as a slug, then a part that is new each
 * time (the time in hex and random hex from newId), so an id is never given
 * twice, even to a connector removed and added again under the same name.
 * Connectors saved before keep the ids they have.
 */
function newConnectorId(name: string, taken: Set<string>): string {
  const base = connectorSlug(name).slice(0, 19).replace(/-$/, '');
  for (;;) {
    const n = newId().toLowerCase();
    const id = `${base}-${n.slice(0, 12)}${n.slice(16, 24)}`;
    if (!taken.has(id)) return id;
  }
}

function withTimeout<T>(p: Promise<T>, ms: number, message: string): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const t = setTimeout(() => reject(new Error(message)), ms);
    p.then(
      (v) => {
        clearTimeout(t);
        resolve(v);
      },
      (e: unknown) => {
        clearTimeout(t);
        reject(e instanceof Error ? e : new Error(String(e)));
      },
    );
  });
}
