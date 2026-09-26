import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { appendFileSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { request } from 'node:https';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { SensorEvent } from '@vigil/sensors';
import { HelperClient } from './client.js';
import { defaultPaths, type HelperPaths } from './config.js';
import { runDaemon } from './daemon.js';
import { FakeSystem } from './testing/fakeSystem.js';

let root: string;
let paths: HelperPaths;
let stop: () => Promise<void>;
let client: HelperClient;
const port = 47000 + Math.floor(Math.random() * 1000);

beforeAll(async () => {
  root = mkdtempSync(join(tmpdir(), 'vigil-daemon-'));
  paths = {
    ...defaultPaths(join(root, 'support')),
    approvalsDir: join(root, 'approvals'),
    socket: join(root, 'helper.sock'),
    santaLog: join(root, 'santa.log'),
    osqueryResults: join(root, 'osquery.log'),
  };
  writeFileSync(paths.santaLog as string, '');
  writeFileSync(paths.osqueryResults as string, '');
  stop = await runDaemon({
    paths,
    syncPort: port,
    sys: new FakeSystem(),
    log: () => {},
    approvalOwnerUid: process.getuid!(),
    opensslBin: 'openssl',
  });
  client = await HelperClient.connect(paths.socket, async () => false);
});

afterAll(async () => {
  client.close();
  await stop();
  rmSync(root, { recursive: true, force: true });
});

// eslint-disable-next-line @typescript-eslint/no-explicit-any -- loose JSON in tests
function santaPost(stage: string, body: unknown): Promise<any> {
  return new Promise((resolve, reject) => {
    const req = request(
      {
        host: '127.0.0.1',
        port,
        method: 'POST',
        path: `/${stage}/M1`,
        ca: readFileSync(join(paths.tlsDir, 'ca.pem')),
        headers: { 'content-type': 'application/json' },
      },
      (res) => {
        let d = '';
        res.on('data', (c) => (d += c));
        res.on('end', () => resolve(JSON.parse(d)));
      },
    );
    req.on('error', reject);
    req.end(JSON.stringify(body));
  });
}

describe('helper daemon', () => {
  it('serves commands, Santa sync and live sensor events together', async () => {
    const status = await client.call<{ activeActions: number }>({ kind: 'helper.status' });
    expect(status.activeActions).toBe(0);

    await client.call({
      kind: 'santa.rule.set',
      ruleType: 'teamid',
      identifier: 'ABCDE12345',
      policy: 'block',
    });
    const pre = await santaPost('preflight', { machine_id: 'M1' });
    expect(pre.sync_type).toBe('CLEAN');
    const rules = await santaPost('ruledownload', { cursor: '' });
    expect(rules.rules).toEqual([
      { identifier: 'ABCDE12345', policy: 'BLOCKLIST', rule_type: 'TEAMID' },
    ]);

    const got: SensorEvent[] = [];
    client.onEvent((e) => got.push(e));
    await client.subscribe();
    appendFileSync(
      paths.santaLog as string,
      '[2026-09-26T21:00:00.000Z] I santad: action=EXEC|decision=DENY|reason=TEAMID|teamid=ABCDE12345|pid=9|ppid=1|uid=501|user=a|mode=M|path=/tmp/evil|args=/tmp/evil|machineid=M1\n',
    );
    await santaPost('eventupload', {
      events: [{ file_path: '/tmp', file_name: 'evil2', decision: 'BLOCK_TEAMID', pid: 10 }],
    });
    await new Promise((r) => setTimeout(r, 600));
    const blocks = got
      .filter((e) => e.kind === 'santa.decision')
      .map((e) => e.kind === 'santa.decision' && e.process.path);
    expect(blocks.sort()).toEqual(['/tmp/evil', '/tmp/evil2']);
    expect(readFileSync(paths.fileAccessPolicy, 'utf8')).toContain('SSHKeys');
  });
});
