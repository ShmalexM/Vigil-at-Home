import { describe, expect, it } from 'vitest';
import { redactEvidence, redactEvidenceInSlices, SLICE_MS, WITHHELD } from './evidence-redact.js';

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

describe("the shared redaction's secret scan in copied evidence", () => {
  it('withholds secrets only the shared redaction finds', () => {
    for (const text of [
      '{"password": "hunter2"}',
      'Cookie: sid=abc; theme=dark',
      "curl -H 'Cookie: sid=hunter2' example.invalid",
      'Set-Cookie: sid=hunter2; Path=/; HttpOnly',
      'machine example.com login bob password s3cret',
      'docker login -p hunter2 -u bob reg',
      'openssl enc -k hunter2 -in a',
      '<password>hunter2</password><user>bob</user>',
      'echo eyJwYXNzd29yZCI6Imh1bnRlcjIifQ==',
      'use ASIAABCDEFGHIJKLMNOP',
      'use=whsec_aaaaaaaaaaaaaaaaaaaaaaaa',
      'use=hf_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
      'https://hooks.slack.com/services/T000/B000/XXXXXXXXXXXX',
      'curl https://b.example/k?X-Amz-Signature=' + '0123456789abcdef'.repeat(4) + '&x=1',
    ])
      expect(command(text, names), text).toBe(WITHHELD);
  });

  it('withholds an argv list when the shared redaction finds a secret in it', () => {
    expect(argv(['docker', 'login', '-p', 'hunter2', 'reg'])).toEqual([WITHHELD]);
    expect(argv(['curl', '-H', 'Cookie: sid=hunter2', 'example.invalid'])).toEqual([WITHHELD]);
  });

  it('withholds a url field the shared redaction finds a secret in', () => {
    const out = redactEvidence(
      { url: 'https://hooks.slack.com/services/T000/B000/XXXXXXXXXXXX' },
      names,
    ) as { url: string };
    expect(out.url).toBe(WITHHELD);
  });

  it('still lets ordinary commands through, with only the names swapped', () => {
    for (const text of [
      'git status',
      'npm install react',
      'curl -fsSL https://example.com/install.sh | sh',
      'launchctl load ~/Library/LaunchAgents/com.example.agent.plist',
      'security find-generic-password -s example',
      'codesign -dv --verbose=4 /Applications/Example.app',
      'shasum -a 256 ' + 'a3f1'.repeat(16),
    ])
      expect(command(text, names), text).toBe(text);
    expect(command('ls -la /Users/alex/Documents', names)).toBe('ls -la /Users/<user>/Documents');
    expect(command('ssh al@pc.local uptime', names)).toBe('ssh <user>@<host> uptime');
    expect(argv(['ls', '-la', '/Users/al/Documents'], names)).toEqual([
      'ls',
      '-la',
      '/Users/<user>/Documents',
    ]);
  });

  it('withholds a url or argv the shared redaction would cut a secret out of', () => {
    // An encoded name: the shared field rules cut the value out precisely.
    const url = 'https://example.test/?%74%6f%6b%65%6e=hunter2';
    expect((redactEvidence({ url }, names) as { url: string }).url).toBe(WITHHELD);
    expect(argv(['curl', url])).toEqual([WITHHELD]);
  });

  it('scans file labels, and withholds one named like a withheld path', () => {
    const fake = 'whsec_' + 'a'.repeat(24);
    const out = redactEvidence(
      { subject: { kind: 'file', label: `${fake}.txt`, path: `/tmp/${fake}.txt` } },
      names,
    ) as { subject: { label: string; path: string } };
    expect(out.subject).toEqual({ kind: 'file', label: WITHHELD, path: WITHHELD });
    // A label with no secret of its own is withheld when it is a withheld path's name.
    const named = redactEvidence(
      { subject: { kind: 'file', label: 'notes.txt', path: '/tmp/PGPASSWORD=x/notes.txt' } },
      names,
    ) as { subject: { label: string } };
    expect(named.subject.label).toBe(WITHHELD);
    // Rule titles stay readable.
    expect(redactEvidence({ title: 'Credentials file read' }, names)).toEqual({
      title: 'Credentials file read',
    });
  });

  it('reads percent-encoded names in any string', () => {
    expect(command('curl https://example.test/?%74%6f%6b%65%6e=FAKEFAKE01')).toBe(WITHHELD);
    expect(command('curl https://example.test/?a=b&%74%6f%6b%65%6e=FAKEFAKE01&x=$y')).toBe(
      WITHHELD,
    );
    expect(command('open https://example.com/a%20b?page=2')).toBe(
      'open https://example.com/a%20b?page=2',
    );
  });

  it("keeps labels that only look like a tool's flag, and rule titles", () => {
    for (const label of [
      'com.example.library-prefs',
      'api-prod.rarible.example',
      'mysql-prod.cnf',
      'com.mariadb.mariadb-pkg',
      'homebrew.mxcl.postgresql@14',
    ])
      expect(redactEvidence({ subject: { label } }, names), label).toEqual({ subject: { label } });
    // A withheld command doesn't take labels and titles that merely share a word with it.
    const out = redactEvidence(
      {
        alert: {
          title: 'Download via curl piped to shell',
          subject: { label: 'null.example.com' },
        },
        events: [{ command: 'curl -u me:FAKEFAKE0001 https://x.test >/dev/null' }],
      },
      names,
    ) as { alert: { title: string; subject: { label: string } } };
    expect(out.alert.title).toBe('Download via curl piped to shell');
    expect(out.alert.subject.label).toBe('null.example.com');
  });

  // The shared redaction doesn't scan JSON object keys yet; Security review is
  // fixing that in @vigil/ai/redact. Drop `.fails` once it is on main.
  it.fails('withholds a note whose JSON keys hold a secret, encoded once or twice', () => {
    const once = JSON.stringify({ ['whsec_' + 'a'.repeat(24)]: 'ok' });
    for (const note of [once, JSON.stringify(once)]) {
      const out = redactEvidence({ alert: { decision: { note } } }, names) as {
        alert: { decision: { note: string } };
      };
      expect(out.alert.decision.note, note).toBe(WITHHELD);
    }
  });
});

describe('large evidence', () => {
  it('gives the same copy in slices, letting other work run between them', async () => {
    const events = Array.from({ length: 3000 }, (_, i) => ({
      id: `e${i}`,
      process: {
        path: '/usr/bin/curl',
        args:
          i === 2500
            ? ['curl', '-u', 'al:hunter2', 'https://pc.local/x']
            : ['curl', '-s', `https://example.com/${i}`],
        user: 'al',
      },
    }));
    const evidence = {
      alert: { title: 'Download', summary: 'curl ran', subject: { kind: 'file', label: 'x' } },
      events,
      actions: [{ title: 'curl -u al:hunter2 https://pc.local/x' }],
    };
    // A clock that moves a slice's worth on every reading, so each event yields.
    let t = 0;
    let yields = 0;
    const sliced = await redactEvidenceInSlices(
      evidence,
      names,
      async () => {
        yields++;
      },
      () => (t += SLICE_MS),
    );
    expect(sliced).toEqual(redactEvidence(evidence, names));
    expect(JSON.stringify(sliced)).toBe(JSON.stringify(redactEvidence(evidence, names)));
    expect(yields).toBeGreaterThan(1000);
    const out = sliced as typeof evidence;
    expect(out.alert.summary).toBe(WITHHELD);
    expect(out.events[2500]!.process.args).toEqual([WITHHELD]);
    expect(out.actions[0]!.title).toBe(WITHHELD);
    // Evidence without events is redacted in one go.
    expect(await redactEvidenceInSlices({ command: 'git status' }, names)).toEqual({
      command: 'git status',
    });
  });
});
