// Runs every log-based sensor and hands one stream of SensorEvents to a sink.
// The Santa sync server is separate (it is an HTTP handler), but it can feed
// the same sink through `hub.emit`.

import { FileTailer, type TailPosition } from './tail.js';
import { santaLogLineToEvent } from './santa/logParser.js';
import { osqueryHealth, osqueryLineToEvents } from './osquery/resultParser.js';
import { DEFAULT_PATHS } from './santa/profile.js';
import { OSQUERY_RESULTS_LOG } from './osquery/config.js';
import type { SensorEvent, SensorEventSink } from './types.js';
import { ProcessEnricher } from './enrich.js';

export interface SensorHubOptions {
  sink: SensorEventSink;
  santaLogPath?: string | false;
  osqueryResultsPath?: string | false;
  /** Saved positions so a restart resumes where it stopped instead of skipping or replaying. */
  positions?: Record<string, TailPosition>;
  onError?: (source: string, err: Error) => void;
  /** Drop noisy event kinds before they reach the sink. */
  filter?: (event: SensorEvent) => boolean;
}

const DEDUPE_WINDOW = 5000;

/** When each sensor last delivered an event (ms since epoch), for health checks. */
export type SensorActivity = Record<'santa' | 'osquery', number | null>;

export class SensorHub {
  private readonly tailers = new Map<string, FileTailer>();
  private readonly seen = new Set<string>();
  private readonly activity: SensorActivity = { santa: null, osquery: null };
  private readonly enricher = new ProcessEnricher();

  constructor(private readonly opts: SensorHubOptions) {
    const santa = opts.santaLogPath ?? DEFAULT_PATHS.santaLog;
    if (santa)
      this.addTailer('santa', santa, (line) => {
        const e = santaLogLineToEvent(line);
        if (e) this.emit(e);
      });
    const osq = opts.osqueryResultsPath ?? OSQUERY_RESULTS_LOG;
    if (osq)
      this.addTailer('osquery', osq, (line) => {
        const health = osqueryHealth(line);
        if (health) {
          // Differential queries are silent when nothing changes; the health
          // query's rows are what show osquery is still running.
          this.activity.osquery = Date.now();
          if (health.denylisted.length > 0)
            opts.onError?.(
              'osquery',
              new Error(`osquery switched off ${health.denylisted.join(', ')}`),
            );
          return;
        }
        for (const e of osqueryLineToEvents(line)) this.emit(e);
      });
  }

  private addTailer(name: string, path: string, onLine: (line: string) => void): void {
    this.tailers.set(
      name,
      new FileTailer({
        path,
        onLine,
        from: this.opts.positions?.[name] ?? 'end',
        onError: (err) => this.opts.onError?.(name, err),
      }),
    );
  }

  /** When Santa and osquery last delivered an event, or null if they haven't since start. */
  lastEventAt(): SensorActivity {
    return { ...this.activity };
  }

  emit(incoming: SensorEvent): void {
    if (incoming.source === 'santa' || incoming.source === 'osquery')
      this.activity[incoming.source] = Date.now();
    if (this.seen.has(incoming.id)) return;
    const event = this.enricher.enrich(incoming);
    this.seen.add(event.id);
    if (this.seen.size > DEDUPE_WINDOW) {
      // Sets iterate in insertion order, so this drops the oldest id.
      const oldest = this.seen.values().next().value;
      if (oldest !== undefined) this.seen.delete(oldest);
    }
    if (this.opts.filter && !this.opts.filter(event)) return;
    this.opts.sink(event);
  }

  async start(): Promise<void> {
    await Promise.all([...this.tailers.values()].map((t) => t.start()));
  }

  async stop(): Promise<void> {
    await Promise.all([...this.tailers.values()].map((t) => t.stop()));
  }

  positions(): Record<string, TailPosition> {
    const out: Record<string, TailPosition> = {};
    for (const [name, t] of this.tailers) {
      const p = t.position;
      if (p) out[name] = p;
    }
    return out;
  }
}
