import type { SensorEvent } from '@vigil/core';
import type { EventOutcome } from '../shared/ipc.js';
import type { Store } from './db/store.js';
import { slimForStorage } from './event-slim.js';

export interface EventLogOptions {
  /** Longest an event waits in memory before it is written. */
  flushMs?: number;
  /** Write as soon as this many events are waiting. */
  maxBatch?: number;
  /** Events waiting beyond this are dropped (the disk is stuck); blocking is unaffected. */
  maxPending?: number;
  onError?: (err: unknown) => void;
}

/**
 * The event history (what the activity feed shows and AI-drafted rules are
 * replayed against). Sensors can produce hundreds of events a second while
 * the user compiles, so events are written in batches: one transaction and
 * one disk flush per second instead of one per event. With per-event commits
 * the app wrote about 40 times more to disk than it stored.
 *
 * Detection never waits on this: rules see each event before it is stored.
 * Events an alert refers to are written straight away by AlertService.
 */
export class EventLog {
  private pending: { event: SensorEvent; outcome?: EventOutcome }[] = [];
  private timer: ReturnType<typeof setTimeout> | undefined;
  private dropped = 0;
  private invalid = 0;
  private readonly flushMs: number;
  private readonly maxBatch: number;
  private readonly maxPending: number;

  constructor(
    private readonly store: Store,
    private readonly opts: EventLogOptions = {},
  ) {
    this.flushMs = opts.flushMs ?? 1000;
    this.maxBatch = opts.maxBatch ?? 500;
    this.maxPending = opts.maxPending ?? 20_000;
  }

  add(event: SensorEvent, outcome?: EventOutcome): void {
    if (this.pending.length >= this.maxPending) {
      this.dropped++;
      return;
    }
    // No raw sensor record, and ancestry only where it is looked at (event-slim.ts).
    const slim = slimForStorage(event, (outcome?.matches.length ?? 0) > 0);
    this.pending.push({ event: slim, ...(outcome ? { outcome } : {}) });
    if (this.pending.length >= this.maxBatch) this.flush();
    else this.timer ??= setTimeout(() => this.flush(), this.flushMs);
  }

  /** Write everything waiting now. */
  flush(): void {
    if (this.timer) clearTimeout(this.timer);
    this.timer = undefined;
    const batch = this.pending;
    if (batch.length === 0) return;
    this.pending = [];
    try {
      this.invalid += this.store.insertEvents(batch);
    } catch (err) {
      this.opts.onError?.(err);
    }
  }

  stats(): { pending: number; dropped: number; invalid: number } {
    return { pending: this.pending.length, dropped: this.dropped, invalid: this.invalid };
  }
}
