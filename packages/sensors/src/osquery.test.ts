import { describe, expect, it } from 'vitest';
import { SensorEvent } from '@vigil/core';
import { osqueryConfig, QUERY_NAMES } from './osquery/config.js';
import { osqueryLineToEvents } from './osquery/resultParser.js';

describe('osquery', () => {
  it('generates a config with every query Vigil parses', () => {
    const cfg = JSON.parse(osqueryConfig());
    for (const name of Object.values(QUERY_NAMES))
      expect(cfg.schedule[name].query).toMatch(/^SELECT/);
    expect(cfg.options.logger_event_type).toBe(true);
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
