import { describe, expect, it } from 'vitest';
import { SafetyFloor, selfRoots } from '../safety.js';

const proc = (path: string) => ({ pid: 4242, ppid: 900, path });

describe('safety floor: Vigil’s own paths', () => {
  it('ignores a self path that would cover the whole machine', () => {
    expect(selfRoots(['/', '', '/opt', '/opt/', '/x/..'])).toEqual([]);
    const floor = new SafetyFloor({ selfPaths: ['/'] });
    expect(floor.processProtection(proc('/tmp/payload'))).toBeUndefined();
  });

  it('protects only what is inside a real install folder', () => {
    const floor = new SafetyFloor({ selfPaths: ['/opt/Vigil at Home/'] });
    expect(floor.processProtection(proc('/opt/Vigil at Home/vigil-at-home'))).toBe(
      'it is Vigil itself',
    );
    expect(floor.processProtection(proc('/opt/Vigil at Home2/x'))).toBeUndefined();
  });
});
