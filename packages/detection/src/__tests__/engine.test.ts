import { Alert, RuleMatch } from '@vigil/core';
import { describe, expect, it } from 'vitest';
import { DetectionEngine } from '../engine.js';
import { memoryStores } from '../state/stores.js';
import { chrome, connect, DAY, ev, exec, fileOpen, proc, T0, testRule } from './fixtures.js';

const evil = proc({
  path: '/Users/alex/Downloads/evil',
  pid: 900,
  sha256: 'e'.repeat(64),
  signing: 'unsigned',
});
const isEvil = { field: 'process.name', op: 'eq', value: 'evil' };
const suspend = [{ kind: 'process.suspend', pid: '{{process.pid}}' }];

describe('modes', () => {
  it('shadow only matches, alert proposes, block executes', () => {
    for (const mode of ['shadow', 'alert', 'block'] as const) {
      const eng = new DetectionEngine(
        [testRule({ id: 'r-test', mode, condition: isEvil, response: suspend })],
        memoryStores(),
      );
      const [d] = eng.evaluate(exec(evil));
      expect(d!.mode).toBe(mode);
      expect(RuleMatch.parse(d!.match).mode).toBe(mode);
      expect(d!.alert === undefined).toBe(mode === 'shadow');
      expect(d!.propose).toEqual(mode === 'alert' ? [{ kind: 'process.suspend', pid: 900 }] : []);
      expect(d!.execute).toEqual(mode === 'block' ? [{ kind: 'process.suspend', pid: 900 }] : []);
    }
  });
  it('produces alerts that satisfy the core schema', () => {
    const eng = new DetectionEngine(
      [testRule({ id: 'r-test', mode: 'block', condition: isEvil, response: suspend })],
      memoryStores(),
    );
    const d = eng.evaluate(exec(evil))[0]!;
    const alert = Alert.parse(d.alert);
    expect(alert).toMatchObject({
      ruleId: 'r-test',
      notify: 'popup',
      containment: 'active',
      subject: { kind: 'process', label: 'evil' },
      summary: 'evil matched',
    });
    expect(d.match.alertId).toBe(alert.id);
  });
  it('disabled rules do nothing', () => {
    const eng = new DetectionEngine(
      [testRule({ id: 'r-off', mode: 'disabled', condition: isEvil })],
      memoryStores(),
    );
    expect(eng.evaluate(exec(evil))).toEqual([]);
  });
  it('only indexes rules for their event kinds', () => {
    const eng = new DetectionEngine(
      [testRule({ id: 'r-test', mode: 'block', condition: isEvil })],
      memoryStores(),
    );
    expect(eng.evaluate(fileOpen(evil, '/x'))).toEqual([]);
  });
});

describe('safety floor', () => {
  const any = testRule({
    id: 'r-any',
    mode: 'block',
    condition: { field: 'process.path', op: 'exists' },
    response: [{ kind: 'process.kill', pid: '{{process.pid}}' }],
  });
  const run = (p: ReturnType<typeof proc>, cfg = {}) =>
    new DetectionEngine([any], memoryStores(), cfg).evaluate(exec(p))[0]!;

  it('never kills Apple services and falls back to alerting', () => {
    const d = run(
      proc({
        path: '/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder',
        signing: 'apple',
      }),
    );
    expect(d.mode).toBe('alert');
    expect(d.execute).toEqual([]);
    expect(d.downgrades.join()).toMatch(/part of macOS/);
    expect(run(proc({ path: '/usr/libexec/xpcproxy', signing: 'apple' })).execute).toEqual([]);
    expect(run(proc({ path: '/sbin/launchd', pid: 1 })).execute).toEqual([]);
  });
  it('may stop an Apple CLI tool started by something else, not one started by launchd', () => {
    expect(run(proc({ path: '/usr/bin/osascript', ppid: 900, signing: 'apple' })).mode).toBe(
      'block',
    );
    expect(run(proc({ path: '/usr/bin/osascript', ppid: 1, signing: 'apple' })).mode).toBe('alert');
  });
  it('never acts on Vigil itself or user-protected paths', () => {
    const cfg = {
      safety: { selfPaths: ['/Applications/Vigil.app'], protectedPathGlobs: ['/opt/work/**'] },
    };
    expect(run(proc({ path: '/Applications/Vigil.app/Contents/MacOS/Vigil' }), cfg).mode).toBe(
      'alert',
    );
    expect(run(proc({ path: '/opt/work/tool' }), cfg).mode).toBe('alert');
    expect(run(proc({ path: '/opt/other/tool' }), cfg).mode).toBe('block');
  });
  it('never firewalls loopback or link-local addresses', () => {
    const net = testRule({
      id: 'r-net',
      mode: 'block',
      eventKinds: ['network.connection'],
      condition: { field: 'remotePort', op: 'eq', value: 443 },
      response: [{ kind: 'network.block', address: '{{remoteAddress}}' }],
    });
    const eng = new DetectionEngine([net], memoryStores(), { defaultDedupeWindowSec: 0 });
    const mk = (addr: string) => eng.evaluate(connect(chrome, addr))[0]!;
    expect(mk('127.0.0.1').execute).toEqual([]);
    expect(mk('169.254.10.10').execute).toEqual([]);
    expect(mk('203.0.113.9').execute).toEqual([{ kind: 'network.block', address: '203.0.113.9' }]);
  });
  it('drops release actions and actions it cannot fill in', () => {
    const eng = new DetectionEngine(
      [
        testRule({
          id: 'r-rel',
          mode: 'block',
          condition: isEvil,
          response: [
            { kind: 'process.resume', pid: '{{process.pid}}' },
            { kind: 'network.block', address: '{{remoteAddress}}' },
            { kind: 'process.suspend', pid: '{{process.pid}}' },
          ],
        }),
      ],
      memoryStores(),
    );
    const d = eng.evaluate(exec(evil))[0]!;
    expect(d.execute).toEqual([{ kind: 'process.suspend', pid: 900 }]);
    expect(d.downgrades).toHaveLength(2);
  });
});

describe('first seen and learning', () => {
  const rule = (id: string, kinds = ['process.exec']) =>
    testRule({ id, eventKinds: kinds, condition: { firstSeen: { key: ['process.path'] } } });

  it('fires once per new key and learns after evaluating', () => {
    const eng = new DetectionEngine([rule('r-new'), rule('r-new2')], memoryStores());
    expect(eng.evaluate(exec(evil)).map((d) => d.match.ruleId)).toEqual(['r-new', 'r-new2']);
    expect(eng.evaluate(exec(evil))).toEqual([]);
  });
  it('keeps baselines separate per event kind', () => {
    const eng = new DetectionEngine(
      [rule('r-new'), rule('r-net', ['network.connection'])],
      memoryStores(),
    );
    eng.evaluate(exec(evil));
    expect(eng.evaluate(connect(evil, '203.0.113.1'))).toHaveLength(1);
  });
  it('only records during the learning period', () => {
    const eng = new DetectionEngine([rule('r-new')], memoryStores(), {
      learningUntil: T0 + 7 * DAY,
    });
    const d = eng.evaluate(exec(evil))[0]!;
    expect(d.mode).toBe('shadow');
    expect(d.alert).toBeUndefined();
    expect(d.downgrades.join()).toMatch(/learning/);
  });
});

describe('dedupe, thresholds, exceptions, lists', () => {
  it('alerts once per subject per window', () => {
    const eng = new DetectionEngine([testRule({ id: 'r-a', condition: isEvil })], memoryStores());
    expect(eng.evaluate(exec(evil))[0]!.alert).toBeDefined();
    const second = eng.evaluate(exec(evil))[0]!;
    expect(second.deduped).toBe(true);
    expect(second.alert).toBeUndefined();
  });
  it('keeps containing on repeats (a known-bad program is stopped every time)', () => {
    const eng = new DetectionEngine(
      [testRule({ id: 'r-b', mode: 'block', condition: isEvil, response: suspend })],
      memoryStores(),
    );
    eng.evaluate(exec(evil));
    const again = eng.evaluate(exec(evil))[0]!;
    expect(again.deduped).toBe(true);
    expect(again.execute).toHaveLength(1);
  });
  it('fires a threshold rule once per burst', () => {
    const eng = new DetectionEngine(
      [
        testRule({
          id: 'r-t',
          eventKinds: ['file'],
          condition: isEvil,
          threshold: { count: 3, windowSec: 60, groupBy: ['process.pid'] },
        }),
      ],
      memoryStores(),
    );
    const fire = () => eng.evaluate(fileOpen(evil, '/x')).length;
    expect([fire(), fire(), fire(), fire(), fire(), fire()]).toEqual([0, 0, 1, 0, 0, 1]);
  });
  it('respects user exceptions (all fields must match) and rule exclusions', () => {
    const stores = memoryStores();
    const eng = new DetectionEngine(
      [
        testRule({ id: 'r-x', condition: isEvil }),
        testRule({
          id: 'r-y',
          condition: isEvil,
          exclusions: [{ field: 'process.sha256', op: 'eq', value: 'e'.repeat(64) }],
        }),
      ],
      stores,
    );
    stores.exceptions.add({
      id: 'x1',
      ruleId: 'r-x',
      match: { 'process.path': '/users/alex/downloads/EVIL', 'process.signing': 'unsigned' },
      createdAt: 0,
    });
    expect(eng.evaluate(exec(evil))).toEqual([]);
    stores.exceptions.add({
      id: 'x1',
      ruleId: 'r-x',
      match: { 'process.path': '/users/alex/downloads/EVIL', 'process.signing': 'adhoc' },
      createdAt: 0,
    });
    expect(eng.evaluate(exec(evil)).map((d) => d.match.ruleId)).toEqual(['r-x']);
  });
  it('matches lists by exact value, subnet and parent domain', () => {
    const stores = memoryStores();
    stores.lists.replace('bad', ['evil.test', '198.51.100.0/24', '# comment', '1.2.3.4'], {
      source: 't',
      updatedAt: 0,
    });
    const eng = new DetectionEngine(
      [
        testRule({
          id: 'r-l',
          eventKinds: ['network.connection'],
          dedupe: { key: ['remoteAddress'], windowSec: 0 },
          condition: {
            any: [
              { inList: { list: 'bad', field: 'remoteHost' } },
              { inList: { list: 'bad', field: 'remoteAddress' } },
            ],
          },
        }),
      ],
      stores,
    );
    const hit = (addr: string, host?: string) => eng.evaluate(connect(chrome, addr, host)).length;
    expect(hit('203.0.113.5', 'cdn.evil.test')).toBe(1);
    expect(hit('203.0.113.6', 'notevil.test')).toBe(0);
    expect(hit('198.51.100.77')).toBe(1);
    expect(hit('1.2.3.4')).toBe(1);
    expect(stores.lists.size('bad')).toBe(3);
  });
  it('suggests a Santa rule, except for Apple programs', () => {
    const r = testRule({
      id: 'r-s',
      condition: { field: 'process.path', op: 'exists' },
      santa: { ruleType: 'binary', from: 'process.sha256' },
    });
    const eng = new DetectionEngine([r], memoryStores());
    expect(eng.evaluate(exec(evil))[0]!.santa).toEqual({
      kind: 'santa.rule.set',
      ruleType: 'binary',
      identifier: 'e'.repeat(64),
      policy: 'block',
      message: 'Test rule',
    });
    const apple = proc({
      path: '/usr/bin/python3',
      ppid: 9,
      signing: 'apple',
      sha256: '3'.repeat(64),
    });
    expect(eng.evaluate(exec(apple))[0]!.santa).toBeUndefined();
  });
  it('rejects bad rule sets before changing anything', () => {
    const eng = new DetectionEngine([testRule({ id: 'r-ok', condition: isEvil })], memoryStores());
    expect(() =>
      eng.loadRules([
        testRule({
          id: 'r-bad',
          condition: { field: 'process.path', op: 'regex', value: '(a+)+' },
        }),
      ]),
    ).toThrow(/nested/);
    expect(() =>
      eng.loadRules([
        testRule({ id: 'r-d', condition: isEvil }),
        testRule({ id: 'r-d', condition: isEvil }),
      ]),
    ).toThrow(/duplicate/);
    expect(eng.getRule('r-ok')).toBeDefined();
  });
  it('can evaluate an event built by the ev helper', () => {
    const eng = new DetectionEngine(
      [
        testRule({
          id: 'r-p',
          eventKinds: ['persistence'],
          condition: { field: 'path', op: 'endsWith', value: '.plist' },
        }),
      ],
      memoryStores(),
    );
    const d = eng.evaluate(
      ev({
        kind: 'persistence',
        change: 'added',
        mechanism: 'launch_agent',
        path: '/Users/a/Library/LaunchAgents/x.plist',
      }),
    )[0]!;
    expect(d.alert?.subject).toEqual({
      kind: 'persistence',
      label: 'x.plist',
      path: '/Users/a/Library/LaunchAgents/x.plist',
    });
  });
});
