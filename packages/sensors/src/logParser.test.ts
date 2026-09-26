import { describe, expect, it } from 'vitest';
import { SensorEvent } from '@vigil/core';
import { parseSantaLogLine, santaLogLineToEvent, santaLogLineToNotice } from './santa/logParser.js';

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
    });
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

  it('reports denied and audited file access but not allowed access', () => {
    const line = (d: string) =>
      P +
      `action=FILE_ACCESS|policy_version=v1|policy_name=ChromeCookies|path=/Users/a/Cookies|access_type=OPEN|decision=${d}|operation_id=1|pid=9|ppid=1|process=x|processpath=/tmp/x|uid=501|user=a|machineid=m`;
    expect(ev(line('DENIED'))).toMatchObject({
      kind: 'santa.decision',
      target: 'file_access',
      decision: 'block',
      reason: 'DENIED:ChromeCookies',
      path: '/Users/a/Cookies',
      process: { pid: 9, path: '/tmp/x' },
    });
    expect(ev(line('AUDIT_ONLY'))).toMatchObject({ decision: 'audit_only' });
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

describe('Santa security notices', () => {
  it('parses XProtect detections', () => {
    const n = santaLogLineToNotice(
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
    const n = santaLogLineToNotice(
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
    expect(santaLogLineToNotice(P + 'action=EXEC|decision=ALLOW|pid=1|path=/x')).toBeUndefined();
  });
});
