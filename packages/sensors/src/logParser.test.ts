import { describe, expect, it } from 'vitest';
import { SensorEvent } from '@vigil/core';
import { parseSantaLogLine, santaLogLineToEvent } from './santa/logParser.js';

// Sample lines copied from Santa's own serializer tests (BasicStringTest.mm),
// with the timestamp prefix the file logger adds.
const P = '[2026-09-26T21:00:00.123Z] I santad: ';

/** Parse and check the result against the shared schema. */
function ev(line: string) {
  const e = santaLogLineToEvent(line);
  if (!e) throw new Error('no event');
  return SensorEvent.parse(e);
}

describe('Santa log parser', () => {
  it('parses an EXEC line, unescaping <pipe> and control characters', () => {
    const e = ev(
      P +
        'action=EXEC|decision=ALLOW|reason=BINARY|explain=extra!|sha256=1234_hash|' +
        'cert_sha256=5678_hash|cert_cn=|quarantine_url=google.com|pid=12|pidversion=' +
        '89|ppid=56|uid=-2|user=nobody|gid=-1|group=nogroup|mode=L|path=execpath<pipe>|' +
        'args=exec<pipe>path -l\\n-t -v\\r--foo|machineid=my_id',
    );
    expect(e.kind).toBe('process.exec');
    expect(e.ts).toBe(Date.parse('2026-09-26T21:00:00.123Z'));
    if (e.kind !== 'process.exec') throw new Error();
    expect(e.process).toEqual({
      pid: 12,
      ppid: 56,
      uid: -2,
      user: 'nobody',
      path: 'execpath|',
      sha256: '1234_hash',
      args: ['exec|path', '-l\n-t', '-v\r--foo'],
      // A certificate without a common name says nothing Gatekeeper would trust.
      signing: 'unknown',
      quarantine: { originUrl: 'google.com' },
    });
  });

  it('works out the signature from the certificate Santa logs', () => {
    const exec = (fields: string) =>
      ev(
        P +
          `action=EXEC|decision=ALLOW|reason=UNKNOWN|sha256=ab|${fields}pid=7|ppid=1|uid=501|user=a|mode=M|path=/x|args=x|machineid=m`,
      );
    const signing = (fields: string) => {
      const e = exec(fields);
      if (e.kind !== 'process.exec') throw new Error();
      return e.process.signing;
    };
    expect(signing('cert_sha256=c|cert_cn=Software Signing|')).toBe('apple');
    expect(signing('cert_sha256=c|cert_cn=Apple Mac OS Application Signing|teamid=T1|')).toBe(
      'app_store',
    );
    expect(
      signing(
        'cert_sha256=c|cert_cn=Developer ID Application: Google LLC (EQHXZ8M8AV)|teamid=EQHXZ8M8AV|',
      ),
    ).toBe('developer_id');
    expect(signing('cert_sha256=c|cert_cn=Apple Development: Sam (X)|teamid=X|')).toBe('unknown');
    // No certificate: unsigned or ad hoc, which Santa's log doesn't tell apart.
    expect(signing('')).toBe('unsigned');
    expect(signing('quarantine_url=https://evil.example/a.dmg|')).toBe('unsigned');
    const q = exec('quarantine_url=https://evil.example/a.dmg|');
    if (q.kind !== 'process.exec') throw new Error();
    expect(q.process.quarantine).toEqual({ originUrl: 'https://evil.example/a.dmg' });
    expect(exec('')).not.toHaveProperty('process.quarantine');
  });

  it('maps DENY to a Santa block decision', () => {
    const e = ev(
      P +
        'action=EXEC|decision=DENY|reason=TEAMID|teamid=ABCDE12345|sha256=' +
        'a'.repeat(64) +
        '|pid=5|ppid=1|uid=501|user=alex|mode=M|path=/tmp/evil|args=/tmp/evil|machineid=x',
    );
    expect(e).toMatchObject({
      kind: 'santa.decision',
      target: 'execution',
      decision: 'block',
      reason: 'BLOCK_TEAMID',
      process: { pid: 5, path: '/tmp/evil', teamId: 'ABCDE12345' },
    });
  });

  it('keeps the first value when a key repeats', () => {
    const r = parseSantaLogLine(P + 'action=EXEC|decision=DENY|decision=ALLOW');
    expect(r!.fields.decision).toBe('DENY');
  });

  it('parses launch item additions with the installing process', () => {
    const e = ev(
      P +
        'action=LAUNCH_ITEM_ADD|item_type=USER_ITEM|legacy=true|managed=false' +
        '|item_user=nobody|item_uid=-2|exec_path=/absolute/path/app/exec_path' +
        '|item_path=/absolute/path/item|app_path=/absolute/path/app' +
        '|event_pid=21|event_ppid=65|event_process=fooInst|event_processpath=fooInst' +
        '|event_uid=-2|event_user=nobody|event_gid=-1|event_group=nogroup|pid=12|ppid=56' +
        '|process=foo|processpath=foo|uid=-2|user=nobody|gid=-1|group=nogroup|machineid=my_id',
    );
    expect(e).toMatchObject({
      kind: 'persistence',
      change: 'added',
      mechanism: 'login_item',
      path: '/absolute/path/item',
      program: '/absolute/path/app/exec_path',
      process: { pid: 21, path: 'fooInst' },
    });
  });

  it('parses a launch daemon added without an instigator', () => {
    const e = ev(
      P +
        'action=LAUNCH_ITEM_ADD|item_type=DAEMON|legacy=true|managed=false' +
        '|item_user=nobody|item_uid=-2|exec_path=/path/url/exec_path' +
        '|item_path=/path/url/relative/path|app_path=/path/url' +
        '|pid=12|ppid=56|process=foo|processpath=foo' +
        '|uid=-2|user=nobody|gid=-1|group=nogroup|machineid=my_id',
    );
    expect(e).toMatchObject({
      kind: 'persistence',
      mechanism: 'launch_daemon',
      process: { pid: 12 },
    });
  });

  it('maps file changes', () => {
    expect(
      ev(
        P +
          'action=WRITE|path=/Users/a/.zshrc|pid=3|ppid=1|process=sh|processpath=/bin/sh|uid=501|user=a|machineid=m',
      ),
    ).toMatchObject({
      kind: 'file',
      op: 'write',
      path: '/Users/a/.zshrc',
      process: { pid: 3, path: '/bin/sh' },
    });
    expect(ev(P + 'action=RENAME|path=/tmp/a|newpath=/tmp/b|machineid=m')).toMatchObject({
      op: 'rename',
      newPath: '/tmp/b',
    });
  });

  it('reports blocked access as a decision and audited access as file activity', () => {
    const line = (d: string, type = 'OPEN', policy = 'ChromeCookies') =>
      P +
      `action=FILE_ACCESS|policy_version=v1|policy_name=${policy}|path=/Users/a/Cookies|access_type=${type}|decision=${d}|operation_id=1|pid=9|ppid=1|process=x|processpath=/tmp/x|uid=501|user=a|machineid=m`;
    expect(ev(line('DENIED'))).toMatchObject({
      kind: 'santa.decision',
      target: 'file_access',
      decision: 'block',
      reason: 'DENIED:ChromeCookies',
      path: '/Users/a/Cookies',
      process: { pid: 9, path: '/tmp/x' },
    });
    expect(ev(line('AUDIT_ONLY'))).toMatchObject({
      kind: 'file',
      op: 'open',
      path: '/Users/a/Cookies',
      process: { pid: 9, path: '/tmp/x' },
    });
    expect(ev(line('AUDIT_ONLY', 'RENAME'))).toMatchObject({ kind: 'file', op: 'rename' });
    expect(ev(line('AUDIT_ONLY', 'UNLINK'))).toMatchObject({ kind: 'file', op: 'delete' });
    expect(ev(line('AUDIT_ONLY', 'TRUNCATE'))).toMatchObject({ kind: 'file', op: 'write' });
    // Write-only watch items report write-mode opens.
    expect(ev(line('AUDIT_ONLY', 'OPEN', 'TCCDatabaseWrites'))).toMatchObject({ op: 'write' });
    expect(santaLogLineToEvent(line('ALLOWED'))).toBeUndefined();
  });

  it('gives the same line the same id and ignores junk', () => {
    const line =
      P +
      'action=DELETE|path=/tmp/x|pid=1|ppid=0|process=rm|processpath=/bin/rm|uid=0|user=root|machineid=m';
    expect(ev(line).id).toBe(ev(line).id);
    expect(santaLogLineToEvent('garbage')).toBeUndefined();
    expect(santaLogLineToEvent(P + 'action=FORK|pid=1')).toBeUndefined();
  });
});

describe('macOS security alerts from Santa', () => {
  it('parses XProtect detections', () => {
    const n = ev(
      P +
        'action=XPROTECT_DETECTED|signature_version=v1.0|malware_identifier=Eicar' +
        '|incident_identifier=C42221A2-7C14-4107-8B06-FB94D602187' +
        '|detected_path=/tmp/eicar|pid=12|ppid=56|process=foo|processpath=foo' +
        '|uid=-2|user=nobody|gid=-1|group=nogroup|machineid=my_id',
    );
    expect(n).toMatchObject({
      subtype: 'xprotect_detected',
      path: '/tmp/eicar',
      details: { malware: 'Eicar' },
    });
  });

  it('parses TCC changes', () => {
    const n = ev(
      P +
        'action=TCC_MODIFICATION|event_type=CREATE|service=SystemPolicyDocumentsFolder' +
        '|identity=security.northpole.santa|identity_type=POLICY_ID|auth_right=ALLOWED' +
        '|auth_reason=PROMPT_TIMEOUT|event_pid=654|event_pidver=321|pid=12|ppid=56' +
        '|process=foo|processpath=foo|uid=-2|user=nobody|gid=-1|group=nogroup|machineid=my_id',
    );
    expect(n).toMatchObject({
      subtype: 'tcc_modified',
      details: { service: 'SystemPolicyDocumentsFolder', authRight: 'ALLOWED' },
    });
  });
});
