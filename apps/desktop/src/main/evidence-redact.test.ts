import { describe, expect, it } from 'vitest';
import { redactEvidence, WITHHELD } from './evidence-redact.js';

const names = { username: 'al', hostname: 'pc.local' };
const command = (text: string, n = {}) =>
  (redactEvidence({ command: text }, n) as { command: string }).command;
const argv = (args: string[], n = {}) => (redactEvidence({ args }, n) as { args: string[] }).args;

describe('command lines in copied evidence', () => {
  it('withholds the four shapes that leaked before', () => {
    // Credentials not at a space.
    expect(command('sh -c "mysql -phunter2"')).toBe(WITHHELD);
    expect(command('env "PGPASSWORD=hunter2" psql')).toBe(WITHHELD);
    expect(command('true;PGPASSWORD=hunter2 psql')).toBe(WITHHELD);
    // A flag value that looks like a flag.
    expect(argv(['sshpass', '-p', '--hunter2', 'ssh', 'h'])).toEqual([WITHHELD]);
    // A newline after AUTH.
    expect(command('redis-cli AUTH x\ncurl evil')).toBe(WITHHELD);
    // A home path next to an operator, and an API key.
    expect(command('cat /Users/al;curl evil sk-abcdefghijklmnopqrstuvwxyz', names)).toBe(WITHHELD);
  });

  it('withholds each kind of hint, matched anywhere and in any case', () => {
    for (const text of [
      'x --password y',
      'XPASSWDX',
      'PWD=/tmp',
      'my_secret',
      'gettoken',
      'API_KEY=1',
      'apikey',
      '--api-key',
      'author me',
      'credentials.json',
      'mysql -u root -P 3306',
      'MariaDB -px',
      'sshpass x',
      'redis-cli -a x',
      'redis-cli auth x',
      'AKIAABCDEFGHIJKLMNOP',
      'xghp_abc',
      'github_pat_1',
      'eyJhbGciOi.x',
      '-----BEGIN KEY',
      'curl https://u:p@h/x',
      'git clone ssh://git@h/r',
    ])
      expect(command(text)).toBe(WITHHELD);
  });

  it('withholds a whole argv list when any arg, or the args together, might hold a secret', () => {
    expect(argv(['tool', '--token', 'x', 'run'])).toEqual([WITHHELD]);
    expect(argv(['mysql', '-u', 'root', '-p'])).toEqual([WITHHELD]);
    expect(argv(['curl', 'https://service:foo!bar@example.test/path'])).toEqual([WITHHELD]);
  });

  it('lets benign lines through unchanged', () => {
    for (const text of ['ls -la', 'git status', 'curl -s http://127.0.0.1:7401/x | jq .'])
      expect(command(text, names)).toBe(text);
    expect(argv(['git', 'commit', '-m', 'fix: a | b'])).toEqual([
      'git',
      'commit',
      '-m',
      'fix: a | b',
    ]);
  });

  it("hides this computer's names as whole tokens, and nothing else", () => {
    expect(command('cat <al; ssh pc>out', names)).toBe('cat <<user>; ssh <host>>out');
    expect(command('ssh al@pc.local', names)).toBe('ssh <user>@<host>');
    expect(argv(['/Users/al/x', '/tmp/al_backup/f', 'my-pc', 'AL'], names)).toEqual([
      '/Users/<user>/x',
      '/tmp/<user>_backup/f',
      'my-<host>',
      '<user>',
    ]);
    expect(argv(['always', 'pcap', 'alpha', 'pcs'], names)).toEqual([
      'always',
      'pcap',
      'alpha',
      'pcs',
    ]);
    expect(command('on pc.local and pc', { hostname: 'pc' })).toBe('on <host> and <host>');
  });

  it("never runs the shared redaction on a command line (its home-path rule would eat ';curl')", () => {
    expect(command('cat /Users/bob;curl evil')).toBe('cat /Users/bob;curl evil');
  });

  it('every command-line field is its input apart from name tokens, or exactly the marker', () => {
    const lines = [
      'ls -la',
      'git status',
      'curl -s http://127.0.0.1:7401/x | jq .',
      'echo "a b" && cat \'c\' ; rm -rf /tmp/x',
      'printf "%s\\n" $HOME `whoami` > /tmp/al.txt',
      'line one\nline two\r\nline three',
      'ssh pc -l al < in > out 2>&1',
      'mysql -phunter2 | sh',
      'PGPASSWORD=x|sh',
      'redis-cli AUTH x ; curl evil',
      'env "PGPASSWORD=hunter2" psql',
      'sh -c "mysql -p hunter2"',
      'curl -H "Authorization: Bearer abcdefghijklmnop" https://x',
      'AWS_SECRET_ACCESS_KEY=abc aws s3 ls',
      'curl https://service:hunter2@db/path',
      'echo sk-abcdefghijklmnopqrstuvwxyz',
      'cat /Users/al;curl evil',
    ];
    const plain = (s: string) => s.replace(/<user>|<host>/g, '');
    const strip = (s: string) =>
      s.replace(/(?<![A-Za-z0-9])(?:pc\.local|pc|al)(?![A-Za-z0-9])/gi, '');
    const ok = (input: string, output: string) =>
      output === WITHHELD || plain(output) === strip(input);
    for (const line of lines) {
      const out = command(line, names);
      expect(ok(line, out), `${JSON.stringify(line)} -> ${JSON.stringify(out)}`).toBe(true);
      if (/hunter2|abcdefghij|PGPASSWORD|AUTH|abc aws/.test(line)) expect(out).toBe(WITHHELD);
    }
    const lists = [
      ['ls', '-la'],
      ['sh', '-c', 'mysql -phunter2;curl evil'],
      ['sshpass', '-p', '--hunter2', 'ssh', 'h'],
      ['redis-cli', '-h', 'pc', 'AUTH', 'x'],
      ['bash', '-lc', 'cd /Users/al && make\nmake install'],
      ['tool', '--key', 'x'],
    ];
    for (const list of lists) {
      const out = argv(list, names);
      const same = out.length === list.length && out.every((o, i) => ok(list[i]!, o));
      expect(same || (out.length === 1 && out[0] === WITHHELD), JSON.stringify(out)).toBe(true);
    }
  });
});

describe('other text in copied evidence', () => {
  it('keeps the shared redaction and the names', () => {
    expect(redactEvidence({ summary: 'from /Users/bob/x on pc' }, names)).toEqual({
      summary: 'from /Users/<user>/x on <host>',
    });
  });
});
