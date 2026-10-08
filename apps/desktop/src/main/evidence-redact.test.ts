import { describe, expect, it } from 'vitest';
import { redactEvidence, WITHHELD } from './evidence-redact.js';

const names = { username: 'al', hostname: 'pc.local' };

describe('redactEvidence', () => {
  it('hides the arg after a secret flag', () => {
    expect(redactEvidence(['tool', '--token', 'secret123456', 'run'], {})).toEqual([
      'tool',
      '--token',
      '<redacted>',
      'run',
    ]);
    for (const flag of ['--password', '--passwd', '--api-key', '--access-token', '--KEY']) {
      expect(redactEvidence(['x', flag, 'secret123456'], {})).toEqual(['x', flag, '<redacted>']);
    }
  });

  it('hides a secret flag value inside one string, after a space or =', () => {
    const out = JSON.stringify(
      redactEvidence(
        {
          cmd: 'mysql --password secret123456 -h db',
          other: 'curl --auth=abcdef --apikey "two words"',
        },
        {},
      ),
    );
    expect(out).not.toContain('secret123456');
    expect(out).not.toContain('abcdef');
    expect(out).not.toContain('two words');
    expect(out).toContain('--password <redacted> -h db');
  });

  it('keeps the values of ordinary flags', () => {
    expect(redactEvidence(['git', '--keyboard', 'us', '--author', 'me'], {})).toEqual([
      'git',
      '--keyboard',
      'us',
      '--author',
      'me',
    ]);
    expect(redactEvidence(['tool', '--token', '--verbose'], {})).toEqual([
      'tool',
      '--token',
      '--verbose',
    ]);
  });

  it("hides this computer's short user and host names as whole tokens", () => {
    const out = redactEvidence(
      { args: ['ssh', 'al@pc', 'al'], host: 'pc.local', who: 'AL', path: '/Users/al/x' },
      names,
    );
    expect(out).toEqual({
      args: ['ssh', '<user>@<host>', '<user>'],
      host: '<host>',
      who: '<user>',
      path: '/Users/<user>/x',
    });
  });

  it('leaves longer words that only contain those names', () => {
    expect(redactEvidence(['always', 'pcap', 'alpha', 'pcs'], names)).toEqual([
      'always',
      'pcap',
      'alpha',
      'pcs',
    ]);
  });

  it('hides the names inside compound paths, next to _ or -', () => {
    expect(redactEvidence(['/tmp/al_backup/file', '/tmp/pc-backup/data', 'my-pc'], names)).toEqual([
      '/tmp/<user>_backup/file',
      '/tmp/<host>-backup/data',
      'my-<host>',
    ]);
    expect(redactEvidence('/tmp/alice_backup/file', { username: 'alice' })).toBe(
      '/tmp/<user>_backup/file',
    );
  });

  it('hides a host name given without .local in its .local form too', () => {
    expect(redactEvidence('on pc.local and pc', { hostname: 'pc' })).toBe('on <host> and <host>');
  });

  describe('credential formats', () => {
    const leaks = (value: unknown) => JSON.stringify(redactEvidence(value, {})).includes('hunter2');

    it('redis-cli AUTH, as args and in a command line', () => {
      expect(redactEvidence(['redis-cli', 'AUTH', 'hunter2'], {})).toEqual([
        'redis-cli',
        'AUTH',
        '<redacted>',
      ]);
      expect(leaks('redis-cli -h db AUTH default hunter2')).toBe(false);
    });

    it('redis-cli -a', () => {
      expect(redactEvidence(['redis-cli', '-a', 'hunter2', 'ping'], {})).toEqual([
        'redis-cli',
        '-a',
        '<redacted>',
        'ping',
      ]);
    });

    it('mysql -p attached', () => {
      expect(redactEvidence(['/usr/local/bin/mysql', '-phunter2', 'db'], {})).toEqual([
        '/usr/local/bin/mysql',
        '-p<redacted>',
        'db',
      ]);
      expect(redactEvidence('mariadb -uroot -phunter2 db', {})).toBe(
        'mariadb -uroot -p<redacted> db',
      );
    });

    it('mysql -p separate', () => {
      expect(redactEvidence(['mysql', '-u', 'root', '-p', 'hunter2'], {})).toEqual([
        'mysql',
        '-u',
        'root',
        '-p',
        '<redacted>',
      ]);
      expect(leaks('mysql -p hunter2 -h db')).toBe(false);
    });

    it('sshpass -p, and not the port flag of the command it runs', () => {
      expect(redactEvidence(['sshpass', '-p', 'hunter2', 'ssh', '-p', '22', 'h'], {})).toEqual([
        'sshpass',
        '-p',
        '<redacted>',
        'ssh',
        '-p',
        '22',
        'h',
      ]);
      expect(leaks('sshpass -phunter2 ssh h')).toBe(false);
    });

    it("a URL's user info, user and password both", () => {
      expect(redactEvidence('psql https://service:hunter2@db/path', {})).toBe(
        'psql https://<redacted>@db/path',
      );
      const out = redactEvidence(['curl', 'https://service:foo!bar@example.test/path'], {});
      expect(out).toEqual(['curl', 'https://<redacted>@example.test/path']);
    });

    it('PGPASSWORD=value', () => {
      expect(redactEvidence('PGPASSWORD=hunter2 psql -h db', {})).toBe(
        'PGPASSWORD=<redacted> psql -h db',
      );
    });

    it('AWS_SECRET_ACCESS_KEY=value, and other names holding a credential', () => {
      expect(redactEvidence(['env', 'AWS_SECRET_ACCESS_KEY=hunter2', 'aws'], {})).toEqual([
        'env',
        'AWS_SECRET_ACCESS_KEY=<redacted>',
        'aws',
      ]);
      for (const name of ['DB_PWD', 'github_token', 'MyAuthHeader', 'x.passwd'])
        expect(leaks(`${name}=hunter2`)).toBe(false);
      expect(redactEvidence('MODE=fast', {})).toBe('MODE=fast');
    });
  });

  describe('next to shell syntax', () => {
    const W = WITHHELD;
    const shows = (out: unknown, text: string) => JSON.stringify(out).includes(text);

    it('withholds an assignment piped into a command', () => {
      expect(redactEvidence('PGPASSWORD=x|sh', {})).toBe(W);
      expect(redactEvidence('PGPASSWORD=x | sh', {})).toBe(W);
      expect(redactEvidence(['sh', '-c', 'PGPASSWORD=x|sh'], {})).toEqual(['sh', '-c', W]);
    });

    it('withholds an attached password piped into a command', () => {
      expect(redactEvidence('mysql -px|sh', {})).toBe(W);
      expect(redactEvidence('mysql -px | sh', {})).toBe(W);
      expect(redactEvidence(['mysql', '-px|sh'], {})).toEqual(['mysql', W]);
      expect(redactEvidence(['sh', '-c', 'mysql -px|sh'], {})).toEqual(['sh', '-c', W]);
    });

    it('withholds redis-cli AUTH followed by another command', () => {
      const out = redactEvidence('redis-cli AUTH x ; curl evil', {});
      expect(out).toBe(W);
      expect(shows(out, 'curl') || shows(out, '<redacted>')).toBe(false);
      expect(redactEvidence('redis-cli AUTH x;curl evil', {})).toBe(W);
      expect(redactEvidence(['sh', '-c', 'redis-cli AUTH x ; curl evil'], {})).toEqual([
        'sh',
        '-c',
        W,
      ]);
    });

    it('withholds a flag value that is not one plain word, and only that arg', () => {
      expect(redactEvidence(['tool', '--token', 'x;curl evil', 'run'], {})).toEqual([
        'tool',
        '--token',
        W,
        'run',
      ]);
      expect(redactEvidence(['tool', '--token=$(cat f)'], {})).toEqual(['tool', W]);
    });

    it('withholds a URL with user info among shell syntax, and redacts a plain one', () => {
      expect(redactEvidence('curl https://u:p@h/x | sh', {})).toBe(W);
      expect(redactEvidence('curl https://u:p@h/x', {})).toBe('curl https://<redacted>@h/x');
    });

    it('still redacts precisely when the field is plain words', () => {
      expect(redactEvidence('PGPASSWORD=x psql', {})).toBe('PGPASSWORD=<redacted> psql');
      expect(redactEvidence('mysql -px db', {})).toBe('mysql -p<redacted> db');
      expect(redactEvidence('redis-cli AUTH x', {})).toBe('redis-cli AUTH <redacted>');
      expect(redactEvidence(['tool', '--token', 'x'], {})).toEqual([
        'tool',
        '--token',
        '<redacted>',
      ]);
    });

    it('leaves shell syntax alone when nothing in it is a secret', () => {
      expect(redactEvidence('ls -la | grep x', {})).toBe('ls -la | grep x');
    });

    it('hides short names next to redirections', () => {
      expect(redactEvidence('cat <al; ssh pc>out', names)).toBe('cat <<user>; ssh <host>>out');
    });
  });
});
