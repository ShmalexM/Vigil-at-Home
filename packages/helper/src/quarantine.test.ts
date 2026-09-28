import { describe, expect, it } from 'vitest';
import { vetPath } from './commands/quarantine.js';

const opts = { quarantineDir: '/Library/Application Support/Vigil/Quarantine' };

describe('vetPath', () => {
  it("refuses Vigil's own helper, its runtime and the app", () => {
    for (const path of [
      '/Library/PrivilegedHelperTools/vigil-helper',
      '/Library/PrivilegedHelperTools/vigil-helper.d/node',
      '/Library/PrivilegedHelperTools/vigil-helper.d/helper.mjs',
      '/Applications/Vigil at Home.app/Contents/MacOS/Vigil at Home',
    ]) {
      expect(() => vetPath(path, opts), path).toThrow(expect.objectContaining({ code: 'refused' }));
    }
  });

  it('still allows ordinary files next to them', () => {
    expect(vetPath('/Applications/Vigil at Home Evil.app', opts)).toBe(
      '/Applications/Vigil at Home Evil.app',
    );
    expect(vetPath('/Users/you/Downloads/evil', opts)).toBe('/Users/you/Downloads/evil');
  });
});
