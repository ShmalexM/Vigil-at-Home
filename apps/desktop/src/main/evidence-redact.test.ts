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

  it('withholds each kind of hint, in any case', () => {
    for (const text of [
      'x --password y',
      'x -PASS y',
      'PWD=/tmp',
      'my_secret=1',
      "printf 'gettoken: abc'",
      'API_KEY=1',
      'ENCRYPTION_KEY=hunter2 backup',
      'curl "https://h/?apikey=1"',
      'tool --api-key x',
      'X-Auth: abc',
      'cred=1',
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
      'PASS=hunter2 tool',
      'openssl enc -aes-256-cbc -pass pass:hunter2',
      "docker run --env-file <(printf 'PASS=hunter2') image",
      'curl -u user:hunter2 https://h',
    ];
    const plain = (s: string) => s.replace(/<user>|<host>/g, '');
    const strip = (s: string) =>
      s.replace(/(?<![A-Za-z0-9])(?:pc\.local|pc|al)(?![A-Za-z0-9])/gi, '');
    const ok = (input: string, output: string) =>
      output === WITHHELD || plain(output) === strip(input);
    for (const line of lines) {
      for (const field of ['command', 'summary', 'program']) {
        const out = (redactEvidence({ [field]: line }, names) as Record<string, string>)[field]!;
        const what = `${field}: ${JSON.stringify(line)} -> ${JSON.stringify(out)}`;
        expect(ok(line, out), what).toBe(true);
        if (/hunter2|abcdefghij|PGPASSWORD|AUTH|abc aws/.test(line))
          expect(out, what).toBe(WITHHELD);
      }
    }
    const lists = [
      ['ls', '-la'],
      ['sh', '-c', 'mysql -phunter2;curl evil'],
      ['sshpass', '-p', '--hunter2', 'ssh', 'h'],
      ['redis-cli', '-h', 'pc', 'AUTH', 'x'],
      ['bash', '-lc', 'cd /Users/al && make\nmake install'],
      ['tool', '--key', 'x'],
      ['tool', '--pass=hunter2'],
      ['unzip', '-P', 'hunter2', 'a.zip'],
    ];
    for (const list of lists) {
      const out = argv(list, names);
      const same = out.length === list.length && out.every((o, i) => ok(list[i]!, o));
      expect(same || (out.length === 1 && out[0] === WITHHELD), JSON.stringify(out)).toBe(true);
    }
  });
});

describe('round 7 shapes', () => {
  it('withholds a credential value whatever its first character', () => {
    expect(command('PASSWORD=:hunter2 app')).toBe(WITHHELD);
    expect(command('PGPASSWORD==hunter2 psql')).toBe(WITHHELD);
    expect(redactEvidence({ args: ['tool', '--password', '-hunter2'] }, {})).toEqual({
      args: [WITHHELD],
    });
  });

  it('withholds a persistence label that repeats a withheld command', () => {
    const out = redactEvidence(
      {
        events: [
          { item: { label: 'tool --token=hunter2', programArgs: ['tool', '--token=hunter2'] } },
          { item: { label: 'com.example.agent', programArgs: ['/bin/true'] } },
        ],
      },
      {},
    );
    expect(out).toEqual({
      events: [
        { item: { label: WITHHELD, programArgs: [WITHHELD] } },
        { item: { label: 'com.example.agent', programArgs: ['/bin/true'] } },
      ],
    });
  });

  it('counts auth only as its own word', () => {
    expect(command('git log --author Alice')).toBe('git log --author Alice');
    expect(command('curl --user-agent myapp https://h/')).toBe(
      'curl --user-agent myapp https://h/',
    );
    for (const c of ['x --auth y', 'X-Auth: y', 'Authorization: y', 'OAUTH_TOKEN=y', 'auth=y'])
      expect(command(c), c).toBe(WITHHELD);
  });
});

describe('plain words and paths', () => {
  it('pass through when no value is given to a secret-sounding name', () => {
    for (const text of [
      'cat /etc/passwd',
      'ls /opt/compass',
      'XPASSWDX',
      'gettoken',
      'author me',
      'cat credentials.json',
      'rm -rf ./node_modules/.cache/keys',
    ])
      expect(command(text), text).toBe(text);
  });
});

describe('other text in copied evidence', () => {
  it("hides home folder names and this computer's names, and nothing else", () => {
    expect(redactEvidence({ path: '/Users/bob/x on pc' }, names)).toEqual({
      path: '/Users/<user>/x on <host>',
    });
    expect(redactEvidence({ path: '/Users/al;curl evil' }, names)).toEqual({
      path: '/Users/<user>;curl evil',
    });
  });

  it('treats a decision note as a command line', () => {
    const note = (n: string) =>
      (
        redactEvidence({ alert: { decision: { note: n } } }, names) as {
          alert: { decision: { note: string } };
        }
      ).alert.decision.note;
    expect(note('Ran mysql -phunter2')).toBe(WITHHELD);
    expect(note('password=x;curl evil')).toBe(WITHHELD);
    expect(note('Looks fine, it was me')).toBe('Looks fine, it was me');
  });
});

describe('round 5 shapes', () => {
  const field = (key: string, value: unknown) =>
    (redactEvidence({ [key]: value }, {}) as Record<string, unknown>)[key];

  it('withholds PASS, pass: and --pass', () => {
    expect(command('PASS=hunter2 tool')).toBe(WITHHELD);
    expect(command('openssl enc -aes-256-cbc -pass pass:hunter2')).toBe(WITHHELD);
    expect(command("docker run --env-file <(printf 'PASS=hunter2') image")).toBe(WITHHELD);
    expect(argv(['tool', '--pass=hunter2'])).toEqual([WITHHELD]);
  });

  it('withholds a --key value in programArgs', () => {
    expect(field('programArgs', ['tool', '--key', 'hunter2'])).toEqual([WITHHELD]);
  });

  it('withholds curl -u, --user, -K and --config', () => {
    for (const line of [
      'curl -u user:x https://h',
      'curl -su user:x https://h',
      'curl --user user:x https://h',
      'curl -K cfg',
      'curl --config cfg',
    ])
      expect(command(line)).toBe(WITHHELD);
    expect(command('curl -s https://h')).toBe('curl -s https://h');
  });

  it('withholds unzip -P and an attached 7z or rar -p', () => {
    expect(command('unzip -P x a.zip')).toBe(WITHHELD);
    expect(argv(['7z', 'x', '-px', 'a.7z'])).toEqual([WITHHELD]);
    expect(command('rar x -px a.rar')).toBe(WITHHELD);
    expect(command('unzip a.zip')).toBe('unzip a.zip');
  });

  it('withholds a URL holding a newline or control character', () => {
    expect(field('url', 'https://u:hun\nter2@h/')).toBe(WITHHELD);
    expect(field('url', 'https://h/x\u0007')).toBe(WITHHELD);
    expect(field('url', 'https://h/x')).toBe('https://h/x');
  });

  it("treats a cron item's program as a command line", () => {
    expect(field('program', 'mysql -phunter2')).toBe(WITHHELD);
    expect(redactEvidence({ program: 'cat /Users/al;curl evil' }, names)).toEqual({
      program: 'cat /Users/<user>;curl evil',
    });
  });

  it('treats alert text as a command line', () => {
    expect(field('summary', 'Ran mysql -phunter2 in Terminal')).toBe(WITHHELD);
    expect(redactEvidence({ summary: 'Ran cat /Users/al;curl evil' }, names)).toEqual({
      summary: 'Ran cat /Users/<user>;curl evil',
    });
  });

  it("withholds an alert's summary, and a title or subject repeating it, when its command is", () => {
    const out = redactEvidence(
      {
        alert: {
          title: 'Ran tool --flag ok',
          summary: 'Claude Code ran a download',
          subject: { kind: 'process', label: 'tool --flag ok' },
        },
        events: [{ process: { args: ['tool', '--flag', 'ok', '--key', 'x'] } }],
      },
      {},
    ) as { alert: Record<string, unknown> };
    expect(out.alert).toEqual({
      title: WITHHELD,
      summary: WITHHELD,
      subject: { kind: 'process', label: WITHHELD },
    });
    const kept = redactEvidence(
      {
        alert: { title: 'Downloaded script run directly', summary: 'ran a script' },
        events: [{ process: { args: ['curl', '-u', 'u:p', 'h'] } }],
      },
      {},
    ) as { alert: Record<string, unknown> };
    expect(kept.alert).toEqual({ title: 'Downloaded script run directly', summary: WITHHELD });
  });

  it("keeps a rule's own title even when it names credentials", () => {
    const out = redactEvidence(
      { alert: { title: 'Credentials file read', summary: 'ls -la' } },
      {},
    ) as { alert: Record<string, unknown> };
    expect(out.alert).toEqual({ title: 'Credentials file read', summary: 'ls -la' });
  });
});
