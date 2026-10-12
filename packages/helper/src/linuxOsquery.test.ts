import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { osqueryLinuxConfig } from '@vigil/sensors';
import { ensureLinuxOsquery, removeLinuxOsquery, type LinuxOsqueryPaths } from './linuxOsquery.js';
import { FakeLinuxSystem } from './testing/fakeLinuxSystem.js';

let root: string;
let p: LinuxOsqueryPaths;
let sys: FakeLinuxSystem;

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), 'vigil-osq-linux-'));
  p = {
    osqueryd: join(root, 'osqueryd'),
    config: join(root, 'etc', 'osquery.conf'),
    flags: join(root, 'etc', 'osquery.flags'),
    logDir: join(root, 'log'),
  };
  sys = new FakeLinuxSystem();
});
afterEach(() => rmSync(root, { recursive: true, force: true }));

describe('osquery service on Linux', () => {
  it('does nothing until osquery is installed', async () => {
    expect(await ensureLinuxOsquery(sys, p)).toBe('not-installed');
    expect(sys.runs).toEqual([]);
  });

  it('writes the config, starts the service, and restarts it only on change', async () => {
    writeFileSync(p.osqueryd, '');
    expect(await ensureLinuxOsquery(sys, p)).toBe('started');
    expect(readFileSync(p.config, 'utf8')).toBe(osqueryLinuxConfig());
    expect(sys.runs.at(-1)!.args).toEqual(['enable', '--now', 'osqueryd.service']);
    sys.active.add('system osqueryd.service');
    expect(await ensureLinuxOsquery(sys, p)).toBe('unchanged');
    writeFileSync(p.flags, '--old\n');
    expect(await ensureLinuxOsquery(sys, p)).toBe('restarted');
  });

  it("keeps the user's own config and puts it back on removal", async () => {
    writeFileSync(p.osqueryd, '');
    await ensureLinuxOsquery(sys, p); // creates the folder
    rmSync(p.config);
    rmSync(p.flags);
    writeFileSync(p.config, '{"schedule":{}}');
    writeFileSync(p.flags, '--mine\n');
    sys.active.add('system osqueryd.service');
    await ensureLinuxOsquery(sys, p);
    expect(existsSync(p.config + '.before-vigil')).toBe(true);
    await removeLinuxOsquery(sys, p);
    expect(readFileSync(p.config, 'utf8')).toBe('{"schedule":{}}');
    expect(readFileSync(p.flags, 'utf8')).toBe('--mine\n');
    expect(sys.runs.at(-1)!.args).toEqual(['restart', 'osqueryd.service']);
  });

  it('never replaces a backup another install made first', async () => {
    writeFileSync(p.osqueryd, '');
    await ensureLinuxOsquery(sys, p); // creates the folder
    writeFileSync(p.config, '{"schedule":{"mine":{}}}');
    // Another install, running at the same time, already backed up the original.
    writeFileSync(p.config + '.before-vigil', '{"schedule":{}}');
    sys.active.add('system osqueryd.service');
    await ensureLinuxOsquery(sys, p);
    expect(readFileSync(p.config + '.before-vigil', 'utf8')).toBe('{"schedule":{}}');
    expect(readFileSync(p.config, 'utf8')).toBe(osqueryLinuxConfig());
  });

  it('stops the service it started when there was nothing before', async () => {
    writeFileSync(p.osqueryd, '');
    await ensureLinuxOsquery(sys, p);
    await removeLinuxOsquery(sys, p);
    expect(existsSync(p.config)).toBe(false);
    expect(sys.runs.at(-1)!.args).toEqual(['disable', '--now', 'osqueryd.service']);
  });
});
