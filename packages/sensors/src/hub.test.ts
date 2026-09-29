import { afterEach, describe, expect, it } from 'vitest';
import { mkdtempSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { SensorHub } from './hub.js';
import { QUERY_NAMES } from './osquery/config.js';
import type { SensorEvent } from './types.js';

describe('sensor hub', () => {
  let dir: string;
  let hub: SensorHub | undefined;
  afterEach(async () => {
    await hub?.stop();
    rmSync(dir, { recursive: true, force: true });
  });

  it('counts osquery’s health snapshot as activity and reports switched-off queries', async () => {
    dir = mkdtempSync(join(tmpdir(), 'vigil-hub-'));
    const log = join(dir, 'osqueryd.results.log');
    writeFileSync(
      log,
      JSON.stringify({
        name: QUERY_NAMES.health,
        action: 'snapshot',
        snapshot: [{ name: QUERY_NAMES.networkConnections, denylisted: '1' }],
      }) + '\n',
    );
    const events: SensorEvent[] = [];
    const errors: string[] = [];
    hub = new SensorHub({
      sink: (e) => events.push(e),
      santaLogPath: false,
      osqueryResultsPath: log,
      positions: { osquery: { ino: statSync(log).ino, offset: 0 } },
      onError: (source, err) => errors.push(`${source}: ${err.message}`),
    });
    await hub.start();
    for (let i = 0; i < 50 && hub.lastEventAt().osquery === null; i++)
      await new Promise((r) => setTimeout(r, 100));
    expect(hub.lastEventAt().osquery).not.toBeNull();
    expect(errors).toEqual([`osquery: osquery switched off ${QUERY_NAMES.networkConnections}`]);
    expect(events).toEqual([]);
  });
});
