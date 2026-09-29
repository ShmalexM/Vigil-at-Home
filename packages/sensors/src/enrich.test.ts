import { describe, expect, it } from 'vitest';
import type { SensorEvent } from '@vigil/core';
import { ProcessEnricher } from './enrich.js';

const exec = (pid: number, path: string, extra: object = {}): SensorEvent => ({
  id: `exec-${pid}-${path}`,
  ts: 1,
  source: 'santa',
  kind: 'process.exec',
  process: { pid, path, ...extra },
});
const open = (pid: number, path: string): SensorEvent => ({
  id: `open-${pid}`,
  ts: 2,
  source: 'santa',
  kind: 'file',
  op: 'open',
  path: '/Users/a/.ssh/id_ed25519',
  process: { pid, path },
});
const proc = (e: SensorEvent) => ('process' in e ? e.process : undefined);

describe('process enrichment', () => {
  it('copies a launch’s signature onto later events from the same process', () => {
    const x = new ProcessEnricher();
    x.enrich(
      exec(40, '/tmp/stealer', {
        signing: 'unsigned',
        sha256: 'ab',
        quarantine: { originUrl: 'https://evil.example/a.dmg' },
      }),
    );
    expect(proc(x.enrich(open(40, '/tmp/stealer')))).toEqual({
      pid: 40,
      path: '/tmp/stealer',
      signing: 'unsigned',
      sha256: 'ab',
      quarantine: { originUrl: 'https://evil.example/a.dmg' },
    });
  });

  it('never trusts a reused pid, and falls back to what the program is signed with', () => {
    const x = new ProcessEnricher();
    x.enrich(exec(40, '/usr/bin/ssh', { signing: 'apple', sha256: 'aa' }));
    x.enrich(exec(41, '/tmp/stealer', { signing: 'unsigned', sha256: 'bb' }));
    // pid 40 now runs something else that was also launched as 41.
    expect(proc(x.enrich(open(40, '/tmp/stealer')))).toEqual({
      pid: 40,
      path: '/tmp/stealer',
      signing: 'unsigned',
    });
    // Unknown program: left as it was.
    expect(proc(x.enrich(open(42, '/tmp/other')))).toEqual({ pid: 42, path: '/tmp/other' });
  });

  it('forgets a pid when its process exits and keeps what a sensor already said', () => {
    const x = new ProcessEnricher();
    x.enrich(exec(40, '/tmp/a', { signing: 'unsigned' }));
    x.enrich({
      id: 'exit',
      ts: 3,
      source: 'santa',
      kind: 'process.exit',
      process: { pid: 40, path: '' },
    });
    const e: SensorEvent = {
      id: 'c',
      ts: 4,
      source: 'osquery',
      kind: 'network.connection',
      direction: 'outbound',
      protocol: 'tcp',
      remoteAddress: '1.2.3.4',
      process: { pid: 40, path: '' },
    };
    expect(proc(x.enrich(e))).toEqual({ pid: 40, path: '' });
    const signed = exec(50, '/tmp/a', { signing: 'developer_id' });
    expect(x.enrich(signed)).toBe(signed);
  });
});
