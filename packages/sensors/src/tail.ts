// Follows an append-only log file line by line, surviving rotation
// (newsyslog renames santa.log and starts a new file) and truncation.
//
// It watches the file's folder so new lines arrive at once without waking
// the CPU when nothing happens. A folder watch keeps working across rotation
// (a watch on the file itself follows the old file, and on macOS did not
// report appends at all). It also polls every couple of seconds in case the
// watch misses something or the folder does not exist yet.

import { watch, type FSWatcher } from 'node:fs';
import { open, stat } from 'node:fs/promises';
import { basename, dirname } from 'node:path';
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
  /** Fallback poll interval. Changes usually arrive through the file watch well before this. */
  intervalMs?: number;
  /** Watch the file for changes (default true). Without it, lines arrive on the fallback poll only. */
  watch?: boolean;
  /** Lines longer than this are dropped (a runaway line must not eat memory). */
  maxLineBytes?: number;
}

export class FileTailer {
  private pos: TailPosition | undefined;
  private partial = '';
  private partialBytes = 0;
  /** Skipping the rest of a line that grew too long, up to its newline. */
  private discarding = false;
  private decoder = new StringDecoder('utf8');
  private timer: NodeJS.Timeout | undefined;
  private running = false;
  private polling: Promise<void> | undefined;
  private pollAgain = false;
  private watcher: FSWatcher | undefined;

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
    this.arm();
    this.schedule();
  }

  async stop(): Promise<void> {
    this.running = false;
    if (this.timer) clearTimeout(this.timer);
    this.unwatch();
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
      this.discarding = false;
      this.decoder = new StringDecoder('utf8');
      this.pos = { ino: st.ino, offset: 0 };
    } else if (st.size < this.pos.offset) {
      // Truncated in place.
      this.partial = '';
      this.partialBytes = 0;
      this.discarding = false;
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
    let start = 0;
    for (;;) {
      const nl = text.indexOf('\n', start);
      if (nl === -1) break;
      const piece = text.slice(start, nl);
      start = nl + 1;
      if (this.discarding) {
        // The end of a line already dropped as too long: not a line of its own.
        this.discarding = false;
        continue;
      }
      const line = this.partial + piece;
      const bytes = this.partialBytes + Buffer.byteLength(piece);
      this.partial = '';
      this.partialBytes = 0;
      if (line.length === 0 || bytes > max) continue;
      this.emit(line);
    }
    if (this.discarding) return;
    const rest = text.slice(start);
    this.partial += rest;
    this.partialBytes += Buffer.byteLength(rest);
    if (this.partialBytes > max) {
      // A runaway line must not eat memory; drop it through its newline.
      this.partial = '';
      this.partialBytes = 0;
      this.discarding = true;
    }
  }

  private flushPartial(): void {
    if (this.partial) this.emit(this.partial);
    this.partial = '';
    this.partialBytes = 0;
  }

  private emit(line: string): void {
    try {
      this.opts.onLine(line);
    } catch (err) {
      this.opts.onError?.(err as Error);
    }
  }

  /** Poll now, or once more right after the poll in progress. */
  private kick(): void {
    if (!this.running) return;
    if (this.polling) {
      this.pollAgain = true;
      return;
    }
    this.polling = this.poll()
      .catch((err: Error) => this.opts.onError?.(err))
      .finally(() => {
        this.polling = undefined;
        this.arm();
        if (this.pollAgain) {
          this.pollAgain = false;
          this.kick();
        }
      });
  }

  /** Watch the file's folder; retried after each poll until the folder exists. */
  private arm(): void {
    if (!this.running || this.opts.watch === false || this.watcher) return;
    const name = basename(this.opts.path);
    try {
      const w = watch(dirname(this.opts.path), { persistent: false }, (_event, file) => {
        if (file == null || file.toString() === name) this.kick();
      });
      w.on('error', () => this.unwatch());
      this.watcher = w;
    } catch {
      // Folder not there yet; the fallback poll keeps trying.
    }
  }

  private unwatch(): void {
    this.watcher?.close();
    this.watcher = undefined;
  }

  private schedule(): void {
    if (!this.running) return;
    this.timer = setTimeout(() => {
      this.kick();
      this.schedule();
    }, this.opts.intervalMs ?? 2000);
  }
}
