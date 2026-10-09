import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { createInterface } from 'node:readline';

type Json = unknown;

interface RpcMessage {
  id?: number | string;
  method?: string;
  params?: Json;
  result?: Json;
  error?: { code: number; message: string };
}

export interface JsonRpcHandlers {
  /** A request from the server. Throw to answer with an error. */
  onRequest(method: string, params: Json): Promise<Json>;
  onNotification(method: string, params: Json): void;
}

/** Newline-delimited JSON-RPC over a child process's stdio, as `codex app-server` speaks it. */
export class JsonRpcStdio {
  private readonly child: ChildProcessWithoutNullStreams;
  private nextId = 1;
  private readonly pending = new Map<number, { resolve(v: Json): void; reject(e: Error): void }>();
  private closedError: Error | undefined;
  readonly stderr: string[] = [];

  constructor(
    command: string,
    args: readonly string[],
    env: Record<string, string>,
    cwd: string,
    private readonly handlers: JsonRpcHandlers,
  ) {
    this.child = spawn(command, args, { env, cwd, stdio: ['pipe', 'pipe', 'pipe'] });
    this.child.stderr.on('data', (chunk: Buffer) => {
      if (this.stderr.length < 200) this.stderr.push(chunk.toString());
    });
    this.child.on('error', (error) => this.fail(error));
    this.child.on('exit', (code, signal) => this.fail(new Error(`exited (${code ?? signal})`)));
    createInterface({ input: this.child.stdout }).on('line', (line) => this.onLine(line));
  }

  private fail(error: Error): void {
    this.closedError ??= error;
    for (const { reject } of this.pending.values()) reject(error);
    this.pending.clear();
  }

  private send(message: RpcMessage): void {
    if (!this.child.stdin.writable) return;
    this.child.stdin.write(`${JSON.stringify(message)}\n`);
  }

  private onLine(line: string): void {
    let message: RpcMessage;
    try {
      message = JSON.parse(line) as RpcMessage;
    } catch {
      return;
    }
    if (message.method !== undefined && message.id !== undefined) {
      const id = message.id;
      this.handlers.onRequest(message.method, message.params).then(
        (result) => this.send({ id, result }),
        (error: unknown) =>
          this.send({
            id,
            error: {
              code: -32000,
              message: error instanceof Error ? error.message : String(error),
            },
          }),
      );
    } else if (message.method !== undefined) {
      this.handlers.onNotification(message.method, message.params);
    } else if (typeof message.id === 'number') {
      const waiter = this.pending.get(message.id);
      if (!waiter) return;
      this.pending.delete(message.id);
      if (message.error) waiter.reject(new Error(message.error.message));
      else waiter.resolve(message.result);
    }
  }

  /**
   * With `timeoutMs`, a server that hasn't answered by then is stopped (the
   * child is killed) and the request fails, so a hung server never lingers.
   */
  request<T = Json>(method: string, params: Json, timeoutMs?: number): Promise<T> {
    if (this.closedError) return Promise.reject(this.closedError);
    const id = this.nextId++;
    return new Promise<T>((resolve, reject) => {
      const timer =
        timeoutMs === undefined
          ? undefined
          : setTimeout(() => {
              this.fail(new Error(`${method} did not answer in time`));
              this.close();
            }, timeoutMs);
      timer?.unref?.();
      this.pending.set(id, {
        resolve: (v: Json) => (clearTimeout(timer), resolve(v as T)),
        reject: (e: Error) => (clearTimeout(timer), reject(e)),
      });
      this.send({ id, method, params });
    });
  }

  notify(method: string, params?: Json): void {
    this.send(params === undefined ? { method } : { method, params });
  }

  close(): void {
    this.child.stdin.end();
    this.child.kill();
  }
}
