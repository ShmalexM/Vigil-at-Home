import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { osqueryConfig, osqueryFlags } from '@vigil/sensors';
import { OSQUERY_LABEL, ensureOsquery, removeOsquery, type OsqueryPaths } from './osquery.js';
import { FakeSystem } from './testing/fakeSystem.js';

const TARGET = `system/${OSQUERY_LABEL}`;

describe('osquery setup', () => {
  let root: string;
  let p: OsqueryPaths;
  let sys: FakeSystem;

  beforeEach(() => {
    root = mkdtempSync(join(tmpdir(), 'vigil-osq-'));
    p = {
      osqueryd: join(root, 'osqueryd'),
      config: join(root, 'var/osquery/osquery.conf'),
      flags: join(root, 'var/osquery/osquery.flags'),
      logDir: join(root, 'var/log/osquery'),
      plist: join(root, `${OSQUERY_LABEL}.plist`),
    };
    sys = new FakeSystem();
    sys.labels.set(p.plist, OSQUERY_LABEL);
  });
  afterEach(() => rmSync(root, { recursive: true, force: true }));

  const launchctl = () =>
    sys.runs.filter((r) => r.bin === 'launchctl' && r.args[0] !== 'print').map((r) => r.args[0]);

  it('does nothing while osquery is not installed', async () => {
    expect(await ensureOsquery(sys, p)).toBe('not-installed');
    expect(existsSync(p.config)).toBe(false);
    expect(sys.runs).toEqual([]);
  });

  it('writes the config, flags and launchd job, starts osquery, then leaves it alone', async () => {
    writeFileSync(p.osqueryd, '');
    expect(await ensureOsquery(sys, p)).toBe('started');
    expect(readFileSync(p.config, 'utf8')).toBe(osqueryConfig());
    expect(readFileSync(p.flags, 'utf8')).toBe(osqueryFlags());
    const plist = readFileSync(p.plist, 'utf8');
    expect(plist).toContain(`<string>--flagfile=${p.flags}</string>`);
    expect(plist).toContain(`<string>--config_path=${p.config}</string>`);
    expect(plist).toContain('<string>Background</string>');
    expect(statSync(p.plist).mode & 0o777).toBe(0o644);
    expect(existsSync(p.logDir)).toBe(true);
    expect(sys.loaded.has(TARGET)).toBe(true);

    sys.runs.length = 0;
    expect(await ensureOsquery(sys, p)).toBe('unchanged');
    expect(launchctl()).toEqual([]);
  });

  it('restarts osquery when its config drifts', async () => {
    writeFileSync(p.osqueryd, '');
    await ensureOsquery(sys, p);
    writeFileSync(p.flags, '--logger_plugin=tls\n');
    sys.runs.length = 0;
    expect(await ensureOsquery(sys, p)).toBe('restarted');
    expect(readFileSync(p.flags, 'utf8')).toBe(osqueryFlags());
    expect(launchctl()).toEqual(['kickstart']);
  });

  it("keeps osquery's own config and job and puts them back on removal", async () => {
    writeFileSync(p.osqueryd, '');
    await ensureOsquery(sys, p); // creates the folders
    await removeOsquery(sys, p);
    writeFileSync(p.config, '{"schedule":{"mine":{}}}');
    writeFileSync(p.flags, '--mine\n');
    writeFileSync(p.plist, '<plist>theirs</plist>');
    sys.loaded.add(TARGET);
    sys.runs.length = 0;

    expect(await ensureOsquery(sys, p)).toBe('started');
    expect(launchctl()).toEqual(['bootout', 'bootstrap']);
    expect(readFileSync(p.config + '.before-vigil', 'utf8')).toBe('{"schedule":{"mine":{}}}');
    expect(readFileSync(p.plist + '.before-vigil', 'utf8')).toBe('<plist>theirs</plist>');

    // A second pass must not overwrite the backups with Vigil's files.
    await ensureOsquery(sys, p);
    expect(readFileSync(p.flags + '.before-vigil', 'utf8')).toBe('--mine\n');

    await removeOsquery(sys, p);
    expect(readFileSync(p.config, 'utf8')).toBe('{"schedule":{"mine":{}}}');
    expect(readFileSync(p.flags, 'utf8')).toBe('--mine\n');
    expect(readFileSync(p.plist, 'utf8')).toBe('<plist>theirs</plist>');
    expect(existsSync(p.config + '.before-vigil')).toBe(false);
  });

  it('removes only what Vigil wrote', async () => {
    writeFileSync(p.osqueryd, '');
    await ensureOsquery(sys, p);
    await removeOsquery(sys, p);
    expect(sys.loaded.has(TARGET)).toBe(false);
    expect(existsSync(p.plist)).toBe(false);
    expect(existsSync(p.config)).toBe(false);
    expect(existsSync(p.flags)).toBe(false);
    // An unrelated job at the same path is not Vigil's to remove.
    writeFileSync(p.plist, '<plist>theirs</plist>');
    await removeOsquery(sys, p);
    expect(existsSync(p.plist)).toBe(true);
  });
});
