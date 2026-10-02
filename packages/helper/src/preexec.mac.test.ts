// Real-Mac check that the helper reads Apple programs' signing IDs the way
// Santa names them. Runs only on macOS with VIGIL_MAC_INTEGRATION=1
// (`pnpm --filter @vigil/helper test:mac`).

import { existsSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { DetectionRule, macosCoreRules } from '@vigil/detection';
import { RuleStore } from '@vigil/sensors';
import { PreexecSync, parsePlatformSigningId } from './preexec.js';
import { realSystem } from './system.js';

const enabled = process.platform === 'darwin' && process.env['VIGIL_MAC_INTEGRATION'] === '1';

describe.skipIf(!enabled)('pre-launch rules on a real Mac', () => {
  it('reads platform signing IDs from codesign', async () => {
    const sys = realSystem();
    for (const [path, id] of [
      ['/usr/bin/osascript', 'platform:com.apple.osascript'],
      ['/usr/sbin/spctl', 'platform:com.apple.spctl'],
    ] as const) {
      const r = await sys.run('codesign', ['-dv', path]);
      expect(parsePlatformSigningId(r.stderr + '\n' + r.stdout)).toBe(id);
    }
  });

  it('targets osascript for the fake password dialog rule (Santa or not)', async () => {
    const sync = new PreexecSync(realSystem(), new RuleStore(), existsSync);
    const fake = DetectionRule.parse(macosCoreRules.find((r) => r.id === 'fake-password-prompt')!);
    const out = await sync.apply([fake]);
    // Without Santa (or with one older than 2025.8) nothing is installed.
    if (out.santaSupportsCel)
      expect(out.installed.map((i) => i.identifier)).toEqual(['platform:com.apple.osascript']);
    else expect(out.installed).toEqual([]);
  });
});
