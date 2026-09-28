// Real-Mac check that the helper starts osquery the way it does on a user's
// Mac: Vigil's config, flags and launchd job, with results reaching the log
// the sensors read. Needs osquery installed (`brew install --cask osquery`),
// root and VIGIL_MAC_INTEGRATION=1 (`pnpm --filter @vigil/helper test:mac`).

import { afterAll, describe, expect, it } from 'vitest';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { OSQUERY_LABEL, defaultOsqueryPaths, ensureOsquery, removeOsquery } from './osquery.js';
import { realSystem } from './system.js';

const p = defaultOsqueryPaths();
const enabled =
  process.platform === 'darwin' &&
  process.env.VIGIL_MAC_INTEGRATION === '1' &&
  process.getuid?.() === 0 &&
  existsSync(p.osqueryd);
const sys = realSystem();
const results = join(p.logDir, 'osqueryd.results.log');
// osquery's package may ship its own job; removal must put that back instead.
const before = existsSync(p.plist) ? readFileSync(p.plist, 'utf8') : undefined;

describe.skipIf(!enabled)('osquery started by the helper', () => {
  afterAll(async () => {
    await removeOsquery(sys, p);
  });

  it('loads osqueryd under launchd and its results reach the log', async () => {
    const state = await ensureOsquery(sys, p);
    expect(['started', 'restarted']).toContain(state);
    expect((await sys.run('launchctl', ['print', `system/${OSQUERY_LABEL}`])).code).toBe(0);

    let seen = false;
    for (let i = 0; i < 90 && !seen; i++) {
      await new Promise((r) => setTimeout(r, 1000));
      seen = existsSync(results) && readFileSync(results, 'utf8').includes('"name":"vigil_');
    }
    const stderr = join(p.logDir, 'osqueryd.stderr');
    const err = existsSync(stderr) ? readFileSync(stderr, 'utf8') : '';
    expect(seen, `no Vigil results from osqueryd:\n${err.slice(-4000)}`).toBe(true);
    expect(err).not.toMatch(/CLI only flag/);

    expect(await ensureOsquery(sys, p)).toBe('unchanged');
  }, 120_000);

  it('removal takes out Vigil’s job and restores what was there before', async () => {
    await removeOsquery(sys, p);
    if (before === undefined) {
      expect((await sys.run('launchctl', ['print', `system/${OSQUERY_LABEL}`])).code).not.toBe(0);
      expect(existsSync(p.plist)).toBe(false);
    } else {
      expect(readFileSync(p.plist, 'utf8')).toBe(before);
    }
  });
});
