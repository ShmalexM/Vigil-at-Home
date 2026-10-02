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

describe('process tree', () => {
  it('names the parent and ancestors, nearest first, on the launch and later events', () => {
    const x = new ProcessEnricher();
    x.enrich(exec(10, '/Applications/Safari.app/Contents/MacOS/Safari', { signing: 'apple' }));
    x.enrich(
      exec(20, '/Volumes/Setup/Installer.app/Contents/MacOS/Installer', {
        ppid: 10,
        signing: 'unsigned',
        quarantine: { originUrl: 'https://evil.example/setup.dmg' },
      }),
    );
    x.enrich(exec(30, '/bin/sh', { ppid: 20, signing: 'apple' }));
    const curl = proc(x.enrich(exec(40, '/usr/bin/curl', { ppid: 30, signing: 'apple' })));
    expect(curl?.parentPath).toBe('/bin/sh');
    expect(curl?.ancestors).toEqual(['sh', 'Installer', 'Safari']);
    expect(curl?.downloadedAncestor).toEqual({
      path: '/Volumes/Setup/Installer.app/Contents/MacOS/Installer',
      originUrl: 'https://evil.example/setup.dmg',
      signing: 'unsigned',
    });
    // A later file read by curl carries the same context.
    const read = proc(x.enrich(open(40, '/usr/bin/curl')));
    expect(read?.ancestors).toEqual(['sh', 'Installer', 'Safari']);
    expect(read?.downloadedAncestor?.originUrl).toBe('https://evil.example/setup.dmg');
  });

  it('keeps at most four ancestors and nothing for a parent it never saw', () => {
    const x = new ProcessEnricher();
    let ppid: number | undefined;
    for (let pid = 1; pid <= 6; pid++) {
      x.enrich(exec(100 + pid, `/bin/p${pid}`, { signing: 'apple', ...(ppid ? { ppid } : {}) }));
      ppid = 100 + pid;
    }
    expect(proc(x.enrich(exec(200, '/bin/leaf', { ppid, signing: 'apple' })))?.ancestors).toEqual([
      'p6',
      'p5',
      'p4',
      'p3',
    ]);
    expect(proc(x.enrich(exec(300, '/bin/orphan', { ppid: 999, signing: 'apple' })))).toEqual({
      pid: 300,
      path: '/bin/orphan',
      ppid: 999,
      signing: 'apple',
    });
  });
});

describe('signature lookup', () => {
  it('asks once per unknown program and fills later events from the answer', () => {
    const asked: string[] = [];
    const x = new ProcessEnricher({ onUnknownSignature: (p) => asked.push(p) });
    expect(proc(x.enrich(open(70, '/usr/local/bin/old')))?.signing).toBeUndefined();
    x.enrich(open(70, '/usr/local/bin/old'));
    expect(asked).toEqual(['/usr/local/bin/old']);
    x.learnSignature('/usr/local/bin/old', { signing: 'adhoc' });
    expect(proc(x.enrich(open(70, '/usr/local/bin/old')))?.signing).toBe('adhoc');
  });

  it('never asks about a program whose launch it saw', () => {
    const asked: string[] = [];
    const x = new ProcessEnricher({ onUnknownSignature: (p) => asked.push(p) });
    x.enrich(exec(80, '/tmp/x', { signing: 'unsigned' }));
    x.enrich(open(80, '/tmp/x'));
    expect(asked).toEqual([]);
  });
});
