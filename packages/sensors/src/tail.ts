// Follows an append-only log file line by line, surviving rotation
// (newsyslog renames santa.log and starts a new file) and truncation.
//
// It watches the file so new lines arrive at once without waking the CPU
// when nothing happens, and also polls every couple of seconds, because a
// watch follows the old file across a rename and can miss events. After a
// rotation the watch moves to the new file.

import { watch, type FSWatcher } from 'node:fs';
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
  private decoder = new StringDecoder('utf8');
  private timer: NodeJS.Timeout | undefined;
  private running = false;
  private polling: Promise<void> | undefined;
  private pollAgain = false;
  private watcher: FSWatcher | undefined;
  private watchedIno: number | undefined;
  private retry: NodeJS.Timeout | undefined;

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
    if (this.retry) clearTimeout(this.retry);
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

  /** Watch the file being followed, moving the watch to a new file after rotation. */
  private arm(): void {
    if (!this.running || this.opts.watch === false || !this.pos) return;
    if (this.watcher && this.watchedIno === this.pos.ino) return;
    this.unwatch();
    try {
      const w = watch(this.opts.path, { persistent: false }, (event) => {
        if (event === 'rename') {
          // Rotated or deleted: the watch now follows the old file. Drop it
          // and look again shortly, once the new file has been created.
          this.unwatch();
          if (this.retry) clearTimeout(this.retry);
          this.retry = setTimeout(() => this.kick(), 250);
        }
        this.kick();
      });
      w.on('error', () => this.unwatch());
      this.watcher = w;
      this.watchedIno = this.pos.ino;
    } catch {
      // File gone between polls; the fallback poll will pick it up.
    }
  }

  private unwatch(): void {
    this.watcher?.close();
    this.watcher = undefined;
    this.watchedIno = undefined;
  }

  private schedule(): void {
    if (!this.running) return;
    this.timer = setTimeout(() => {
      this.kick();
      this.schedule();
    }, this.opts.intervalMs ?? 2000);
  }
}
