import { mkdtempSync, rmSync } from 'node:fs';
import { createServer, type Server, type Socket } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DetectionEngine, macosCoreRules, memoryStores } from '@vigil/detection';
import { fastPathRules } from '@vigil/detection/fastpath';
import {
  Approvals,
  Executor,
  FastPath,
  HelperServer,
  Journal,
  parseRequest,
  type ActionOutcome,
  type HelperResponse,
  type System,
} from '@vigil/helper';
import { HelperClient } from '@vigil/helper/client';
import { RuleStore } from '@vigil/sensors';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { HelperLink, type HelperRuleSet } from './helper.js';
import { HelperSyncer } from './helper-sync.js';

const INSTALLED = '/Applications/Vigil at Home.app';
const DOWNLOADS = '/Users/alex/Downloads/Vigil at Home.app';
const exception = { id: 'x1', ruleId: '*', match: { 'process.path': '/tmp/ok' }, createdAt: 1 };

/** A password dialog the test answers: each one waits until `answer` is called. */
interface Dialog {
  prompt: string;
  answer: (yes: boolean) => void;
}

let root: string;
let fast: FastPath;
let executor: Executor;
let approvalsDir: string;
let server: { close(): Promise<void> } | undefined;
let link: HelperLink | undefined;
let dialogs: Dialog[];
/** How the fake dialog answers: undefined leaves it open, as a user who walked away. */
let answer: (prompt: string) => boolean | undefined;

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), 'vigil-helper-sync-'));
  approvalsDir = join(root, 'approvals');
  dialogs = [];
  answer = () => true;
  const approvals = new Approvals({ dir: approvalsDir, requiredOwnerUid: process.getuid!() });
  executor = new Executor({
    sys: { platform: 'darwin' } as System,
    journal: new Journal(join(root, 'journal.json')),
    approvals,
    rules: new RuleStore(join(root, 'rules.json')),
    quarantine: { quarantineDir: join(root, 'Quarantine') },
    syncPort: 47822,
    get fastPath() {
      return fast;
    },
  });
  fast = new FastPath({
    file: join(root, 'helper-rules.json'),
    installed: [INSTALLED],
    run: async (action) => {
      const out = await executor.execute(action);
      if (out.kind !== 'done') throw new Error('needs the admin password');
      return out.result as ActionOutcome;
    },
  });
});

afterEach(async () => {
  link?.stop();
  link = undefined;
  await server?.close();
  server = undefined;
  rmSync(root, { recursive: true, force: true });
});

/** The password dialog: yes writes the root-owned approval, as `vigil-helper approve` does. */
function approver(nonce: string, prompt: string, also: string[] = []): Promise<boolean> {
  return new Promise((resolve) => {
    const dialog: Dialog = {
      prompt,
      answer: (yes) => {
        if (yes) for (const n of [nonce, ...also]) Approvals.writeApproval(approvalsDir, n);
        resolve(yes);
      },
    };
    dialogs.push(dialog);
    const now = answer(prompt);
    if (now !== undefined) dialog.answer(now);
  });
}

async function connect(socket: string): Promise<HelperLink> {
  const l = new HelperLink(socket, (s) => HelperClient.connect(s, approver));
  await l.tryConnect();
  expect(l.state).toBe('connected');
  link = l;
  return l;
}

/** The current helper. */
async function currentHelper(): Promise<string> {
  const socket = join(root, 'helper.sock');
  const s = new HelperServer({ socketPath: socket, executor });
  await s.listen();
  server = s;
  return socket;
}

/**
 * A helper from before self.grant: it refuses self.grant as an unknown
 * command and a sync without a self set, as its stricter parser did.
 */
async function olderHelper(): Promise<string> {
  const socket = join(root, 'older.sock');
  const conns = new Set<Socket>();
  const srv: Server = createServer((sock) => {
    conns.add(sock);
    sock.on('close', () => conns.delete(sock));
    let buf = '';
    sock.setEncoding('utf8');
    sock.on('data', (chunk: string) => {
      buf += chunk;
      let nl: number;
      while ((nl = buf.indexOf('\n')) >= 0) {
        const line = buf.slice(0, nl);
        buf = buf.slice(nl + 1);
        void reply(line).then((r) => sock.write(JSON.stringify(r) + '\n'));
      }
    });
  });
  const reply = async (line: string): Promise<HelperResponse> => {
    const req = parseRequest(line);
    if ('error' in req) return { id: req.id ?? '', ok: false, error: req.error, code: 'invalid' };
    const cmd = req.command;
    if (cmd.kind === 'self.grant')
      return {
        id: req.id,
        ok: false,
        error: "bad command: kind Invalid discriminator value. Expected 'process.suspend'",
        code: 'invalid',
      };
    if (cmd.kind === 'detection.sync' && cmd.selfPaths === undefined)
      return {
        id: req.id,
        ok: false,
        error: 'bad command: selfPaths Invalid input: expected array, received undefined',
        code: 'invalid',
      };
    if (cmd.kind === 'events.subscribe') return { id: req.id, ok: true, result: {} };
    try {
      const out = await executor.execute(cmd, req.approval);
      return out.kind === 'needs_approval'
        ? { id: req.id, ok: false, needsApproval: true, nonce: out.nonce, prompt: out.prompt }
        : { id: req.id, ok: true, result: out.result };
    } catch (err) {
      return { id: req.id, ok: false, error: (err as Error).message, code: 'refused' };
    }
  };
  await new Promise<void>((resolve) => srv.listen(socket, resolve));
  server = {
    close: () =>
      new Promise<void>((resolve) => {
        for (const c of conns) c.destroy();
        srv.close(() => resolve());
      }),
  };
  return socket;
}

/** What the app hands the helper, with Vigil running from `selfPath`. */
function appRules(selfPath: string): HelperRuleSet {
  const { rules, lists } = fastPathRules(
    new DetectionEngine(macosCoreRules, memoryStores()).listRules(),
  );
  return {
    rules,
    exceptions: [],
    selfPaths: [selfPath],
    lists: Object.fromEntries(lists.map((l) => [l, []])),
  };
}

/** Whether the helper holds this exception (adding it again would weaken nothing). */
function helperHas(set: HelperRuleSet, ex: typeof exception): boolean {
  return (
    fast.loosening({
      kind: 'detection.sync',
      rules: set.rules,
      exceptions: [ex],
      lists: {},
    }).length === 0
  );
}

const until = async (test: () => boolean, ms = 5000) => {
  const end = Date.now() + ms;
  while (!test()) {
    if (Date.now() > end) throw new Error('timed out');
    await new Promise((r) => setTimeout(r, 10));
  }
};

const selfDialog = (d: Dialog) => d.prompt.includes('keep its blocking rules off its own programs');

describe('helper sync with the self grant apart', () => {
  it('applies a user decision at once while the self grant’s dialog stays open', async () => {
    const l = await connect(await currentHelper());
    let set = appRules(DOWNLOADS);
    const syncer = new HelperSyncer({ link: l, rules: () => set });
    // Nobody answers the dialog for Vigil's own path.
    answer = (prompt) => (prompt.includes(DOWNLOADS) ? undefined : true);
    syncer.connected();
    await until(() => dialogs.some(selfDialog));
    expect(await syncer.sync()).toBe('applied');
    expect(fast.status().rules).toBe(set.rules.length);

    // The user marks something fine in the popup: an exception, by the user.
    set = { ...set, exceptions: [exception] };
    expect(await syncer.sync({ byUser: true })).toBe('applied');
    expect(helperHas(set, exception)).toBe(true);
    expect(dialogs.filter((d) => !selfDialog(d)).map((d) => d.prompt)).toEqual([
      'Vigil wants to loosen its blocking rules: add an exception to *.',
    ]);
    // The grant is still waiting, and asks nothing more.
    expect(fast.self().paths).toEqual([]);
    await syncer.sync();
    expect(dialogs.filter(selfDialog)).toHaveLength(1);

    // Approved later: Vigil's own path is in.
    dialogs.find(selfDialog)!.answer(true);
    await syncer.grant();
    expect(fast.self().paths).toEqual([DOWNLOADS]);
  });

  it('keeps the rules when the grant is declined, and asks again only on reconnect or a change', async () => {
    const l = await connect(await currentHelper());
    let set = appRules(DOWNLOADS);
    const syncer = new HelperSyncer({ link: l, rules: () => set });
    answer = (prompt) => !prompt.includes(DOWNLOADS);
    syncer.connected();
    await syncer.grant();
    expect(await syncer.sync()).toBe('applied');
    expect(fast.status().rules).toBe(set.rules.length);
    expect(fast.self().paths).toEqual([]);
    expect(dialogs).toHaveLength(1);

    // The health timer syncs again: no new dialog.
    await syncer.sync();
    await syncer.grant();
    expect(dialogs).toHaveLength(1);
    // A change to the set asks again.
    set = { ...set, selfPaths: [DOWNLOADS, `${DOWNLOADS}/Contents`] };
    await syncer.grant();
    expect(dialogs).toHaveLength(2);
    // So does a new connection.
    syncer.connected();
    await syncer.grant();
    expect(dialogs).toHaveLength(3);
    expect(fast.status().rules).toBe(set.rules.length);
  });

  it('asks nothing for the installed app', async () => {
    const l = await connect(await currentHelper());
    const set = appRules(INSTALLED);
    const syncer = new HelperSyncer({ link: l, rules: () => set });
    syncer.connected();
    await syncer.grant();
    expect(await syncer.sync()).toBe('applied');
    expect(dialogs).toEqual([]);
    expect(fast.self().paths).toEqual([INSTALLED]);
    expect(fast.status().rules).toBe(set.rules.length);
  });

  it('falls back to the combined sync for an older helper, asking nothing for the installed app', async () => {
    const l = await connect(await olderHelper());
    const set = appRules(INSTALLED);
    const syncer = new HelperSyncer({ link: l, rules: () => set });
    syncer.connected();
    expect(await syncer.sync()).toBe('applied');
    await syncer.grant();
    expect(dialogs).toEqual([]);
    expect(fast.self().paths).toEqual([INSTALLED]);
    expect(fast.status().rules).toBe(set.rules.length);
  });

  it('never holds an older helper’s rule syncs behind the combined sync’s dialog', async () => {
    const l = await connect(await olderHelper());
    let set = appRules(DOWNLOADS);
    const syncer = new HelperSyncer({ link: l, rules: () => set });
    answer = () => undefined;
    syncer.connected();
    await until(() => dialogs.length === 1);
    expect(dialogs[0]!.prompt).toContain(`never block ${DOWNLOADS}`);
    // The queue goes on without a dialog; the rules wait for the grant.
    expect(await syncer.sync()).toBe('unavailable');
    expect(dialogs).toHaveLength(1);

    // Approved, with the rules: later syncs carry the self set the helper took.
    dialogs[0]!.answer(true);
    await syncer.grant();
    expect(fast.self().paths).toEqual([DOWNLOADS]);
    expect(fast.status().rules).toBe(set.rules.length);
    answer = () => true;
    set = { ...set, exceptions: [exception] };
    expect(await syncer.sync({ byUser: true })).toBe('applied');
    expect(helperHas(set, exception)).toBe(true);
    expect(dialogs.at(-1)!.prompt).toBe(
      'Vigil wants to loosen its blocking rules: add an exception to *.',
    );
  });
});
