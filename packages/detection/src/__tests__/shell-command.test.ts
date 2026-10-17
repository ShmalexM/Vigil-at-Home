import { describe, expect, it } from 'vitest';
import { shellCommand } from '../safety.js';

describe('shellCommand', () => {
  it('finds the command after -c or a short-option cluster holding c', () => {
    expect(shellCommand({ path: '/bin/sh', args: ['/bin/sh', '-c', 'echo hi'] })).toBe('echo hi');
    expect(shellCommand({ path: '/bin/zsh', args: ['zsh', '-lc', 'ls', '-la'] })).toBe('ls -la');
    expect(shellCommand({ path: '/bin/bash', args: ['bash', '-x', 'script.sh'] })).toBeUndefined();
    expect(shellCommand({ path: '/bin/bash', args: ['bash', '--rcfile', 'x'] })).toBeUndefined();
    expect(shellCommand({ path: '/usr/bin/env', args: ['env', '-c', 'x'] })).toBeUndefined();
  });

  it('stays fast on a long run of option letters', () => {
    const arg = `-${'c'.repeat(100_000)}x!`;
    const t = performance.now();
    expect(shellCommand({ path: '/bin/sh', args: ['sh', arg] })).toBeUndefined();
    expect(performance.now() - t).toBeLessThan(200);
  });
});
