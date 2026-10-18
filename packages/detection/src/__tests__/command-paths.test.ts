import { describe, expect, it } from 'vitest';
import { commandPaths, MAX_CHARS } from '../rules/command-paths.js';

describe('commandPaths', () => {
  it('writes each path one way', () => {
    const cases: [string, string][] = [
      ['rm "$HOME"/Library/x', 'rm ~/Library/x'],
      ['rm ${HOME}/Library/x', 'rm ~/Library/x'],
      ['rm /Users/alex/Library/x', 'rm ~/Library/x'],
      ['rm /home/alex/.config', 'rm ~/.config'],
      [
        'rm //Library/./PrivilegedHelperTools//vigil-helper',
        'rm /Library/PrivilegedHelperTools/vigil-helper',
      ],
      [
        'rm /Library/Logs/../PrivilegedHelperTools/vigil-helper',
        'rm /Library/PrivilegedHelperTools/vigil-helper',
      ],
      ['rm /private/var/db/santa/rules.db', 'rm /var/db/santa/rules.db'],
      ["rm 'Vigil at Home/'", 'rm Vigil at Home/'],
      ['rm Vigil\\ at\\ Home/', 'rm Vigil at Home/'],
      [
        'rm /Library/PrivilegedHelperTools/{x,vigil-helper}',
        'rm /Library/PrivilegedHelperTools/x /Library/PrivilegedHelperTools/vigil-helper',
      ],
      ['cp a >/Users/alex//x', 'cp a >~/x'],
      ["sqlite3 'file:/Users/alex/a.db?mode=ro'", 'sqlite3 file:~/a.db?mode=ro'],
      ['echo $HOMEDIR', 'echo $HOMEDIR'],
      ['rm /a/{b,c}/d{e,f}', 'rm /a/b/de /a/b/df /a/c/de /a/c/df'],
      ['rm /System/Volumes/Data/Library/x', 'rm /Library/x'],
      ['rm /System/Volumes/Data/private/var/db/x', 'rm /var/db/x'],
      ['rm /System/Volumes/Data/Users/alex/x', 'rm ~/x'],
      ['rm ~alex/Library/x', 'rm ~/Library/x'],
      ['echo ~', 'echo ~'],
      ['a\nb  c', 'a\nb  c'],
    ];
    for (const [cmd, want] of cases) expect(commandPaths(cmd), cmd).toBe(want);
    expect(commandPaths(undefined)).toBeUndefined();
  });

  it('stays bounded on long or odd input', () => {
    expect(commandPaths('x'.repeat(MAX_CHARS * 2))!.length).toBe(MAX_CHARS);
    const braces = `{${Array.from({ length: 100 }, (_, i) => i).join(',')}}`;
    expect(commandPaths(braces)!.split(' ')).toHaveLength(16);
    const t = performance.now();
    commandPaths('/a/'.repeat(5000) + '{'.repeat(3000) + '\\'.repeat(3000));
    expect(performance.now() - t).toBeLessThan(200);
  });
});
