import { describe, expect, it } from 'vitest';
import { SensorEvent } from '@vigil/core';
import { osqueryConfig, QUERY_NAMES } from './osquery/config.js';
import { osqueryHealth, osqueryLineToEvents } from './osquery/resultParser.js';

describe('osquery', () => {
  it('generates a config with every query Vigil parses', () => {
    const cfg = JSON.parse(osqueryConfig());
    for (const name of Object.values(QUERY_NAMES)) {
      expect(cfg.schedule[name].query).toMatch(/^SELECT/);
      // A watchdog kill must not silence a query for a day.
      expect(cfg.schedule[name].denylist).toBe(false);
    }
    expect(cfg.options.logger_event_type).toBe(true);
  });

  it('reads the health snapshot, naming any query osquery switched off', () => {
    const line = (rows: Record<string, string>[]) =>
      JSON.stringify({ name: QUERY_NAMES.health, action: 'snapshot', snapshot: rows });
    expect(
      osqueryHealth(
        line([
          { name: QUERY_NAMES.networkConnections, denylisted: '1', executions: '40' },
          { name: QUERY_NAMES.launchd, denylisted: '0', executions: '7' },
        ]),
      ),
    ).toEqual({ denylisted: [QUERY_NAMES.networkConnections] });
    expect(osqueryHealth(line([]))).toEqual({ denylisted: [] });
    expect(osqueryHealth(JSON.stringify({ name: QUERY_NAMES.launchd, columns: {} }))).toBe(
      undefined,
    );
    expect(osqueryHealth('not json')).toBeUndefined();
    // Not a sensor event.
    expect(osqueryLineToEvents(line([]))).toEqual([]);
  });

  it('parses connection rows into the shared schema', () => {
    const line = JSON.stringify({
      name: QUERY_NAMES.networkConnections,
      unixTime: 1790000000,
      counter: 3,
      action: 'added',
      columns: {
        pid: '4242',
        path: '/tmp/beacon',
        name: 'beacon',
        uid: '501',
        remote_address: '203.0.113.9',
        remote_port: '443',
        local_address: '192.168.1.5',
        local_port: '51000',
        protocol: '6',
      },
    });
    const [e] = osqueryLineToEvents(line);
    expect(SensorEvent.parse(e)).toMatchObject({
      kind: 'network.connection',
      direction: 'outbound',
      protocol: 'tcp',
      ts: 1790000000000,
      remoteAddress: '203.0.113.9',
      remotePort: 443,
      localPort: 51000,
      process: { pid: 4242, path: '/tmp/beacon', uid: 501 },
    });
  });

  it('drops first-run baseline rows unless asked, and maps launchd removals', () => {
    const first = JSON.stringify({
      name: QUERY_NAMES.launchd,
      unixTime: 1,
      counter: 0,
      action: 'added',
      columns: {
        path: '/Library/LaunchDaemons/com.x.plist',
        label: 'com.x',
        program: '',
        program_arguments: '/usr/local/bin/x --run',
      },
    });
    expect(osqueryLineToEvents(first)).toEqual([]);
    const [add] = osqueryLineToEvents(first, { includeBaseline: true });
    expect(SensorEvent.parse(add)).toMatchObject({
      kind: 'persistence',
      change: 'added',
      mechanism: 'launch_daemon',
      label: 'com.x',
      program: '/usr/local/bin/x',
      programArgs: ['/usr/local/bin/x', '--run'],
    });

    const [rm] = osqueryLineToEvents(
      JSON.stringify({
        name: QUERY_NAMES.launchd,
        unixTime: 2,
        counter: 4,
        action: 'removed',
        columns: { path: '/Users/a/Library/LaunchAgents/y.plist' },
      }),
    );
    expect(SensorEvent.parse(rm)).toMatchObject({ change: 'removed', mechanism: 'launch_agent' });
  });

  it('parses listening ports and browser extensions', () => {
    const [listen] = osqueryLineToEvents(
      JSON.stringify({
        name: QUERY_NAMES.listeningPorts,
        unixTime: 5,
        counter: 2,
        action: 'added',
        columns: {
          pid: '99',
          path: '/tmp/backdoor',
          uid: '501',
          port: '4444',
          address: '0.0.0.0',
          protocol: '6',
        },
      }),
    );
    expect(SensorEvent.parse(listen)).toMatchObject({
      kind: 'network.listen',
      protocol: 'tcp',
      localPort: 4444,
      localAddress: '0.0.0.0',
      process: { pid: 99, path: '/tmp/backdoor' },
    });
    expect(listen!.kind === 'network.listen' && listen!.process?.signing).toBeUndefined();
    const signed = (columns: Record<string, string>) => {
      const [e] = osqueryLineToEvents(
        JSON.stringify({
          name: QUERY_NAMES.listeningPorts,
          counter: 2,
          action: 'added',
          columns: { pid: '1', path: '/x', port: '80', protocol: '6', ...columns },
        }),
      );
      return e?.kind === 'network.listen' ? e.process : undefined;
    };
    expect(
      signed({ signed: '1', authority: 'Software Signing', identifier: 'com.apple.rapportd' }),
    ).toMatchObject({ signing: 'apple', signingId: 'com.apple.rapportd' });
    expect(
      signed({
        signed: '1',
        authority: 'Developer ID Application: Spotify (2FNC3A47ZF)',
        team_identifier: '2FNC3A47ZF',
      }),
    ).toMatchObject({ signing: 'developer_id', teamId: '2FNC3A47ZF' });
    expect(signed({ signed: '1', authority: '', identifier: 'backdoor-55554944' })?.signing).toBe(
      'adhoc',
    );
    expect(signed({ signed: '0', authority: '', identifier: '' })?.signing).toBe('unsigned');
    expect(signed({ signed: '0', identifier: 'com.tampered' })?.signing).toBe('invalid');
    const [ext] = osqueryLineToEvents(
      JSON.stringify({
        name: QUERY_NAMES.browserExtensions,
        unixTime: 6,
        counter: 2,
        action: 'added',
        columns: {
          browser_type: 'chrome',
          identifier: 'abcdefghijklmnopabcdefghijklmnop',
          name: 'Helper',
          permissions: 'tabs, cookies, <all_urls>',
        },
      }),
    );
    expect(SensorEvent.parse(ext)).toMatchObject({
      kind: 'browser.extension',
      change: 'added',
      browser: 'chrome',
      name: 'Helper',
      permissions: ['tabs', 'cookies', '<all_urls>'],
    });
  });

  it('ignores removed connections, unknown queries and bad JSON', () => {
    expect(
      osqueryLineToEvents(
        JSON.stringify({
          name: QUERY_NAMES.networkConnections,
          action: 'removed',
          counter: 2,
          columns: {},
        }),
      ),
    ).toEqual([]);
    expect(
      osqueryLineToEvents(
        JSON.stringify({ name: 'other', action: 'added', counter: 2, columns: {} }),
      ),
    ).toEqual([]);
    expect(osqueryLineToEvents('{nope')).toEqual([]);
  });
});
