import { DetectionEngine } from '../engine.js';
import { macosCoreRules } from '../packs/macos-core.js';
import { RulePipeline } from '../proposals/pipeline.js';
import { memoryStores } from '../state/stores.js';
import type { DetectionEvent } from '../types.js';
import { chrome, DAY, HOUR, proc, T0 } from './fixtures.js';

export const NOW = T0 + 14 * DAY;
const devTool = proc({
  path: '/Users/alex/code/app/bin/server',
  signing: 'adhoc',
  sha256: '1'.repeat(64),
});
const node = proc({ path: '/opt/homebrew/bin/node', signing: 'adhoc', sha256: '2'.repeat(64) });
const stealer = proc({
  path: '/Users/alex/Library/.cache/upd',
  signing: 'adhoc',
  sha256: '9'.repeat(64),
});

/** Two weeks of ordinary activity with a little exfiltration near the end. */
export function twoWeeks(opts: { maxPerDay?: number } = {}) {
  const stores = memoryStores();
  let n = 0;
  const add = (ts: number, process: typeof chrome, remoteAddress: string, remoteHost: string) =>
    stores.history.append({
      id: `h${n++}`,
      ts,
      source: 'test',
      kind: 'network.connection',
      direction: 'outbound',
      protocol: 'tcp',
      remoteAddress,
      remoteHost,
      process,
    } satisfies DetectionEvent);
  for (let t = T0; t < NOW; t += HOUR) {
    add(t, chrome, '142.250.1.1', 'google.com');
    add(t + 60_000, devTool, '140.82.112.3', 'github.com');
  }
  add(NOW - 2 * DAY, node, '104.20.1.1', 'pastebin.com');
  add(NOW - 1 * DAY, stealer, '104.20.1.2', 'paste.ee');
  const engine = new DetectionEngine(macosCoreRules, stores, { recordHistory: false });
  const pipeline = new RulePipeline(engine, stores.history, undefined, {
    now: () => NOW,
    ...(opts.maxPerDay ? { maxPerDay: opts.maxPerDay } : {}),
  });
  return { stores, engine, pipeline };
}
