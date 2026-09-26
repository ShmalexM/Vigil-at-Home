// Follows an append-only log file line by line, surviving rotation
// (newsyslog renames santa.log and starts a new file) and truncation.
// Polls rather than using fs.watch, which is unreliable across renames.

import { open, stat } from 'node:fs/promises';
import { StringDecoder } from 'node:string_decoder';

export interface TailPosition {
  ino: number;
  offset: number;
}

export interface TailOptions {
  path: string;
  onLine: (line: string) => void;
  onError?: (err: Error) => void;
  /** Resume from a saved position; by default starts at the current end of the file. */
  from?: TailPosition | 'start' | 'end';
  intervalMs?: number;
  /** Lines longer than this are dropped (a runaway line must not eat memory). */
  maxLineBytes?: number;
}

export class FileTailer {
  private pos: TailPosition | undefined;
  private partial = '';
  private decoder = new StringDecoder('utf8');
  private timer: NodeJS.Timeout | undefined;
  private running = false;
  private polling: Promise<void> | undefined;

  constructor(private readonly opts: TailOptions) {}

  get position(): TailPosition | undefined {
    return this.pos && { ...this.pos };
  }

  async start(): Promise<void> {
    if (this.running) return;
    this.running = true;
    const from = this.opts.from ?? 'end';
    try {
      const st = await stat(this.opts.path);
      if (from === 'end') this.pos = { ino: st.ino, offset: st.size };
      else if (from === 'start') this.pos = { ino: st.ino, offset: 0 };
      else
        this.pos =
          from.ino === st.ino && from.offset <= st.size ? { ...from } : { ino: st.ino, offset: 0 };
    } catch {
      // File not there yet (Santa not installed or not logging): start from
      // the beginning once it appears.
      this.pos = undefined;
    }
    this.schedule();
  }

  async stop(): Promise<void> {
    this.running = false;
    if (this.timer) clearTimeout(this.timer);
    await this.polling;
  }

  /** Read whatever is new right now. Exposed for tests. */
  async poll(): Promise<void> {
    let st;
    try {
      st = await stat(this.opts.path);
    } catch {
      return;
    }
    if (!this.pos || this.pos.ino !== st.ino) {
      // New file after rotation: flush any partial line from the old one.
      this.flushPartial();
      this.decoder = new StringDecoder('utf8');
      this.pos = { ino: st.ino, offset: 0 };
    } else if (st.size < this.pos.offset) {
      // Truncated in place.
      this.partial = '';
      this.decoder = new StringDecoder('utf8');
      this.pos.offset = 0;
    }
    if (st.size === this.pos.offset) return;

    const fh = await open(this.opts.path, 'r');
    try {
      const chunkSize = 256 * 1024;
      const buf = Buffer.alloc(chunkSize);
      while (this.pos.offset < st.size) {
        const { bytesRead } = await fh.read(
          buf,
          0,
          Math.min(chunkSize, st.size - this.pos.offset),
          this.pos.offset,
        );
        if (bytesRead === 0) break;
        this.pos.offset += bytesRead;
        this.consume(this.decoder.write(buf.subarray(0, bytesRead)));
      }
    } finally {
      await fh.close();
    }
  }

  private consume(text: string): void {
    const max = this.opts.maxLineBytes ?? 1024 * 1024;
    const data = this.partial + text;
    const lines = data.split('\n');
    this.partial = lines.pop() ?? '';
    if (this.partial.length > max) this.partial = '';
    for (const line of lines) {
      if (line.length === 0 || line.length > max) continue;
      this.emit(line);
    }
  }

  private flushPartial(): void {
    if (this.partial) this.emit(this.partial);
    this.partial = '';
  }

  private emit(line: string): void {
    try {
      this.opts.onLine(line);
    } catch (err) {
      this.opts.onError?.(err as Error);
    }
  }

  private schedule(): void {
    if (!this.running) return;
    this.timer = setTimeout(() => {
      this.polling = this.poll()
        .catch((err: Error) => this.opts.onError?.(err))
        .finally(() => this.schedule());
    }, this.opts.intervalMs ?? 200);
  }
}
