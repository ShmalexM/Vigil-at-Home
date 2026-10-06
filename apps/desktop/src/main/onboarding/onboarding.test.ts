import { mkdtempSync, readFileSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { memoryStore } from '../testing.js';
import { CHECKS, HELPER_SOCKET, type Probe } from './checks.js';
import { KeyStore, type Cipher } from './keys.js';
import {
  FAPOLICYD_ALLOW_RULES,
  LOCAL_MODEL,
  LOCAL_MODEL_SMALL,
  linuxDistro,
  localModelFor,
  setupPlan,
  stepsFor,
} from './plan.js';
import { OnboardingService, type CodexSetup } from './service.js';
import { linuxTerminal } from './terminal.js';

/** A Mac described by the files, programs and command output it has. */
function fakeMac(opts: {
  files?: string[];
  bins?: string[];
  runs?: Record<string, { code: number; stdout: string; timedOut?: boolean }>;
  ollama?: string[] | 'down';
}): Probe & { runs: string[] } {
  const ran: string[] = [];
  const files = new Set([...(opts.files ?? []), ...(opts.bins ?? [])]);
  return {
    home: '/Users/me',
    runs: ran,
    exists: (p) => files.has(p),
    executable: (p) => (opts.bins ?? []).includes(p),
    run: async (file, args) => {
      const key = [file, ...args].join(' ');
      ran.push(key);
      return opts.runs?.[key] ?? { code: 1, stdout: '' };
    },
    getJson: async () => {
      if (!opts.ollama || opts.ollama === 'down') throw new Error('ECONNREFUSED');
      return { models: opts.ollama.map((name) => ({ name })) };
    },
  };
}

const santaOk = (server?: string) => ({
  '/usr/local/bin/santactl status --json': {
    code: 0,
    stdout: JSON.stringify({ daemon: { mode: 'Monitor' }, sync: server ? { server } : {} }),
  },
});

/** XOR "encryption" so tests can see the file never holds the key in the clear. */
const testCipher = (available = true): Cipher => ({
  available: () => available,
  encrypt: (s) => Buffer.from([...Buffer.from(s)].map((b) => b ^ 0x5a)),
  decrypt: (b) => Buffer.from([...b].map((x) => x ^ 0x5a)).toString(),
});

function service(probe: Probe, cipher = testCipher(), codex?: CodexSetup) {
  const dir = mkdtempSync(join(tmpdir(), 'vigil-setup-'));
  const keys = new KeyStore(join(dir, 'keys.json'), cipher);
  let t = 1_000_000;
  const svc = new OnboardingService({
    store: memoryStore(),
    keys,
    probe,
    supported: true,
    now: () => (t += 5000),
    ...(codex ? { codex } : {}),
  });
  return { svc, keys, keyFile: join(dir, 'keys.json') };
}

describe('setup plan', () => {
  it('always installs protection locally, whatever the AI mode', () => {
    for (const mode of ['local', 'cloud', 'both'] as const) {
      const ids = stepsFor(mode).map((s) => s.id);
      expect(ids).toEqual(
        expect.arrayContaining(['homebrew', 'santa', 'santa-approve', 'osquery', 'helper']),
      );
    }
  });

  it('shows the local model only for local and both, and cloud AI only for cloud and both', () => {
    const ids = (m: 'local' | 'cloud' | 'both') => stepsFor(m).map((s) => s.id);
    expect(ids('local')).toContain('ollama-model');
    expect(ids('local')).not.toContain('claude');
    expect(ids('cloud')).toContain('claude');
    expect(ids('cloud')).not.toContain('ollama');
    expect(ids('both')).toEqual(expect.arrayContaining(['ollama', 'claude', 'codex']));
  });

  it('only depends on steps that exist and come earlier', () => {
    const plan = setupPlan({ helperInstallCommand: 'x', santaProfilePath: '/tmp/p' });
    plan.forEach((s, i) => {
      for (const dep of s.after ?? []) {
        const at = plan.findIndex((x) => x.id === dep);
        expect(at, `${s.id} after ${dep}`).toBeGreaterThanOrEqual(0);
        expect(at).toBeLessThan(i);
      }
    });
  });

  it('pulls the small local model', () => {
    const model = stepsFor('local').find((s) => s.id === 'ollama-model')!;
    expect(model.commands[0]!.cmd).toBe(`ollama pull ${LOCAL_MODEL}`);
  });

  it('picks a smaller model for Macs with less than 16 GB', () => {
    expect(localModelFor(4 * 1024 ** 3)).toBe(LOCAL_MODEL_SMALL);
    expect(localModelFor(8 * 1024 ** 3)).toBe(LOCAL_MODEL_SMALL);
    expect(localModelFor(16 * 1024 ** 3)).toBe(LOCAL_MODEL);
    const step = stepsFor('local', { localModel: LOCAL_MODEL_SMALL }).find(
      (s) => s.id === 'ollama-model',
    )!;
    expect(step.commands[0]!.cmd).toBe(`ollama pull ${LOCAL_MODEL_SMALL}`);
    expect(step.why).toContain('400 MB');
  });

  it('offers Claude Code pre-flight only when Claude Code is around, with no commands to run', () => {
    for (const mode of ['local', 'cloud', 'both'] as const) {
      expect(stepsFor(mode).map((s) => s.id)).not.toContain('claude-preflight');
      const step = stepsFor(mode, { claudePreflight: { connected: false } }).find(
        (s) => s.id === 'claude-preflight',
      )!;
      expect(step.optional).toBe(true);
      expect(step.commands).toEqual([]);
      expect(step.check).toBeUndefined();
      expect(step.result).toEqual({ ok: false });
    }
    const on = stepsFor('local', { claudePreflight: { connected: true } }).find(
      (s) => s.id === 'claude-preflight',
    )!;
    expect(on.result?.ok).toBe(true);
    // Heard from, but pre-flight is off: not done, and it says why.
    const off = stepsFor('local', { claudePreflight: { connected: false, off: true } }).find(
      (s) => s.id === 'claude-preflight',
    )!;
    expect(off.result).toEqual({
      ok: false,
      detail: expect.stringMatching(/^Pre-flight checks are off/),
    });
  });

  it('quotes the profile path for the shell', () => {
    const plan = setupPlan({ santaProfilePath: "/Users/o'neil/Vigil Santa.mobileconfig" });
    const step = plan.find((s) => s.id === 'santa-profile')!;
    expect(step.commands[0]!.cmd).toBe(`open '/Users/o'\\''neil/Vigil Santa.mobileconfig'`);
  });
});

describe('checks', () => {
  it('finds Homebrew in either prefix', async () => {
    expect((await CHECKS.homebrew(fakeMac({ bins: ['/usr/local/bin/brew'] }))).ok).toBe(true);
    expect((await CHECKS.homebrew(fakeMac({}))).ok).toBe(false);
  });

  it('sees Santa running and reports its mode', async () => {
    const mac = fakeMac({ bins: ['/usr/local/bin/santactl'], runs: santaOk() });
    expect(await CHECKS['santa.running'](mac)).toEqual({
      ok: true,
      detail: 'Running in monitor mode',
    });
    const off = fakeMac({ bins: ['/usr/local/bin/santactl'] });
    expect((await CHECKS['santa.running'](off)).ok).toBe(false);
  });

  it('accepts Santa synced with Vigil on this Mac only', async () => {
    const check = (server: string) =>
      CHECKS['santa.profile'](
        fakeMac({ bins: ['/usr/local/bin/santactl'], runs: santaOk(server) }),
      );
    expect((await check('https://127.0.0.1:47821/santa')).ok).toBe(true);
    expect((await check('https://localhost:47821')).ok).toBe(true);
    const other = await check('https://sync.example.com');
    expect(other.ok).toBe(false);
    expect(other.detail).toContain('sync.example.com');
    expect((await check('https://127.0.0.1:478219')).ok).toBe(false);
  });

  it('counts the helper only when it answers on its socket', async () => {
    const mac = (answers: boolean) => ({
      ...fakeMac({ files: [HELPER_SOCKET] }),
      helperAnswers: async () => answers,
    });
    expect(await CHECKS.helper(mac(true))).toEqual({ ok: true, detail: 'Running and answering' });
    expect(await CHECKS.helper(mac(false))).toEqual({
      ok: false,
      detail: 'Installed, but the helper isn’t answering',
    });
    // A leftover socket file with nothing to ask is not enough.
    expect((await CHECKS.helper(fakeMac({ files: [HELPER_SOCKET] }))).ok).toBe(false);
  });

  it('prefers the small model but accepts one already installed', async () => {
    expect(await CHECKS['ollama.model'](fakeMac({ ollama: [LOCAL_MODEL] }))).toEqual({
      ok: true,
      detail: LOCAL_MODEL,
    });
    expect((await CHECKS['ollama.model'](fakeMac({ ollama: ['llama3.2:3b'] }))).detail).toContain(
      'llama3.2:3b',
    );
    expect((await CHECKS['ollama.model'](fakeMac({ ollama: [] }))).ok).toBe(false);
    expect((await CHECKS.ollama(fakeMac({ ollama: 'down' }))).ok).toBe(false);
  });

  it('tells installed-but-signed-out Claude apart from signed in', async () => {
    const bin = '/Users/me/.local/bin/claude';
    const status = (r: { code: number; stdout: string; timedOut?: boolean }) =>
      CHECKS.claude(fakeMac({ bins: [bin], runs: { [`${bin} auth status --json`]: r } }));
    expect(await CHECKS.claude(fakeMac({ bins: [bin] }))).toEqual({
      ok: false,
      detail: 'Installed, not signed in',
    });
    expect(
      (await status({ code: 0, stdout: '{"loggedIn": true, "authMethod": "claude.ai"}' })).ok,
    ).toBe(true);
    expect((await status({ code: 0, stdout: '{"loggedIn": false}' })).ok).toBe(false);
    // Versions without --json fall back to the exit code and wording.
    expect((await status({ code: 0, stdout: 'Logged in as me@example.com' })).ok).toBe(true);
    expect((await status({ code: 1, stdout: 'Not logged in' })).ok).toBe(false);
  });

  it('says so when Claude Code is too slow to answer, instead of calling it signed out', async () => {
    const bin = '/opt/homebrew/bin/claude';
    const r = await CHECKS.claude(
      fakeMac({
        bins: [bin],
        runs: { [`${bin} auth status --json`]: { code: 1, stdout: '', timedOut: true } },
      }),
    );
    expect(r.ok).toBe(false);
    expect(r.detail).toContain('didn’t answer');
  });
});

describe('OnboardingService', () => {
  it('shows the pre-flight step as done once the hook has checked in, without running a check', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'vigil-setup-'));
    let connected = false;
    const mac = fakeMac({});
    const svc = new OnboardingService({
      store: memoryStore(),
      keys: new KeyStore(join(dir, 'k.json'), testCipher()),
      probe: mac,
      supported: true,
      plan: () => ({ claudePreflight: { connected } }),
    });
    const step = async () => (await svc.view(true)).steps.find((s) => s.id === 'claude-preflight');
    expect((await step())?.state).toBe('todo');
    connected = true;
    expect(await step()).toMatchObject({ state: 'done', optional: true, commands: [] });
    expect(mac.runs.some((r) => r.includes('claude'))).toBe(false);
  });

  it('starts unfinished with no mode, then remembers the choice', async () => {
    const { svc } = service(fakeMac({}));
    expect(svc.finished()).toBe(false);
    expect((await svc.view()).mode).toBeUndefined();
    svc.setMode('local');
    const v = await svc.view();
    expect(v.mode).toBe('local');
    expect(v.steps.some((s) => s.id === 'claude')).toBe(false);
  });

  it('marks steps done, to do, or waiting on an earlier step', async () => {
    const { svc } = service(fakeMac({ bins: ['/opt/homebrew/bin/brew'] }));
    svc.setMode('local');
    const state = Object.fromEntries((await svc.view()).steps.map((s) => [s.id, s.state]));
    expect(state['homebrew']).toBe('done');
    expect(state['santa']).toBe('todo');
    expect(state['santa-approve']).toBe('waiting');
    expect(state['ollama-model']).toBe('waiting');
  });

  it('says why a step has nothing to run, unless already done', async () => {
    const { svc } = service(
      fakeMac({ bins: ['/opt/homebrew/bin/brew', '/usr/local/bin/osqueryi'] }),
    );
    svc.setMode('local');
    const steps = (await svc.view()).steps;
    const helper = steps.find((s) => s.id === 'helper')!;
    // Santa isn't approved yet, so the helper step waits for it first.
    expect(helper.state).toBe('waiting');
    svc.skip('santa-approve', true);
    const after = (await svc.view(true)).steps;
    const ready = after.find((s) => s.id === 'helper')!;
    expect(ready.state).toBe('unavailable');
    expect(ready.detail).toContain('pnpm build:helper');
    // The Santa profile waits for the helper, rather than saying it is missing.
    expect(after.find((s) => s.id === 'santa-profile')!.state).toBe('waiting');

    const { svc: svc2 } = service({
      ...fakeMac({ files: [HELPER_SOCKET] }),
      helperAnswers: async () => true,
    });
    svc2.setMode('local');
    expect((await svc2.view()).steps.find((s) => s.id === 'helper')!.state).toBe('done');
  });

  it('lets a skipped step unblock the ones after it', async () => {
    const { svc } = service(fakeMac({}));
    svc.setMode('local');
    svc.skip('homebrew', true);
    const state = Object.fromEntries((await svc.view()).steps.map((s) => [s.id, s.state]));
    expect(state['santa']).toBe('todo');
    svc.skip('homebrew', false);
    expect((await svc.view()).steps.find((s) => s.id === 'santa')!.state).toBe('waiting');
  });

  it('runs each check once per round, however many steps share it', async () => {
    const mac = fakeMac({ bins: ['/usr/local/bin/santactl'], runs: santaOk() });
    const { svc } = service(mac);
    svc.setMode('both');
    await Promise.all([svc.view(true), svc.view(true)]);
    // santa.running and santa.profile both read santactl: one call each, one round.
    expect(mac.runs.filter((r) => r.includes('santactl'))).toHaveLength(2);
  });

  it('finishes without choosing an AI, and can be run again', async () => {
    const { svc } = service(fakeMac({}));
    svc.finish();
    expect(svc.finished()).toBe(true);
    expect(svc.mode()).toBeUndefined();
    svc.setMode('cloud');
    svc.restart();
    expect(svc.finished()).toBe(false);
    expect(svc.mode()).toBe('cloud');
  });

  it('shows every step as unavailable off macOS', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'vigil-setup-'));
    const svc = new OnboardingService({
      store: memoryStore(),
      keys: new KeyStore(join(dir, 'k.json'), testCipher()),
      probe: fakeMac({}),
      supported: false,
    });
    const v = await svc.view();
    expect(v.supported).toBe(false);
    expect(v.steps.every((s) => s.state === 'unavailable')).toBe(true);
  });
});

describe('API keys', () => {
  const orKey = 'sk-or-v1-0123456789abcdef0123';

  it('stores keys encrypted, owner-only, and shows only the last four', async () => {
    const { svc, keys, keyFile } = service(fakeMac({}));
    svc.setKey({ provider: 'openrouter', key: orKey });
    expect(readFileSync(keyFile, 'utf8')).not.toContain(orKey);
    expect(statSync(keyFile).mode & 0o777).toBe(0o600);
    expect(keys.get('openrouter')).toEqual({ key: orKey });
    const view = await svc.view();
    expect(view.keys.find((k) => k.provider === 'openrouter')!.saved).toBe('0123');
    expect(JSON.stringify(view)).not.toContain(orKey);
    svc.clearKey('openrouter');
    expect(keys.get('openrouter')).toBeUndefined();
  });

  it('catches a key pasted into the wrong provider', () => {
    const { svc } = service(fakeMac({}));
    expect(() => svc.setKey({ provider: 'anthropic', key: orKey })).toThrow('sk-ant-');
    expect(() => svc.setKey({ provider: 'openrouter', key: 'sk-or- has spaces in it' })).toThrow();
  });

  it('needs an address for a custom gateway, and never sends a key over plain http elsewhere', () => {
    const { svc, keys } = service(fakeMac({}));
    const key = 'gw-0123456789abcdef';
    expect(() => svc.setKey({ provider: 'custom', key })).toThrow('address');
    expect(() =>
      svc.setKey({ provider: 'custom', key, baseUrl: 'http://gateway.example.com/v1' }),
    ).toThrow('https');
    svc.setKey({ provider: 'custom', key, baseUrl: 'http://127.0.0.1:4000/v1' });
    expect(keys.get('custom')).toEqual({ key, baseUrl: 'http://127.0.0.1:4000/v1' });
  });

  it('offers and stores a TypeSafe key for Jev', async () => {
    const { svc, keys } = service(fakeMac({}));
    const v = await svc.view();
    expect(v.keys.map((k) => k.provider)).toContain('typesafe');
    // OpenRouter carries Jev too, so it's the one main key; TypeSafe sits under More options.
    expect(v.keys.filter((k) => !k.more).map((k) => k.provider)).toEqual(['openrouter']);
    expect(v.keys.find((k) => k.provider === 'typesafe')?.use).toMatch(
      /^Not needed if you use OpenRouter/,
    );
    svc.setKey({ provider: 'typesafe', key: 'ts-0123456789abcdef' });
    expect(keys.get('typesafe')).toEqual({ key: 'ts-0123456789abcdef' });
  });

  it('refuses to save when the Keychain is unavailable', () => {
    const { svc } = service(fakeMac({}), testCipher(false));
    expect(() => svc.setKey({ provider: 'openrouter', key: orKey })).toThrow('Keychain');
  });
});

describe('Codex sign-in', () => {
  const codexMac = () => fakeMac({ bins: ['/opt/homebrew/bin/codex'] });
  const fakeCodex = (status: Awaited<ReturnType<CodexSetup['status']>>, share = { ok: true }) => {
    const calls = { status: 0, share: 0 };
    let current = status;
    const codex: CodexSetup = {
      status: async () => (calls.status++, current),
      share: async () => {
        calls.share++;
        if (share.ok) current = { state: 'ready', account: 'me@example.com' };
        return share;
      },
    };
    return { codex, calls };
  };
  const codexStep = async (svc: OnboardingService, fresh = false) => {
    svc.setMode('cloud');
    return (await svc.view(fresh)).steps.find((s) => s.id === 'codex')!;
  };

  it('offers the existing sign-in when Codex can share it, and nothing else runs until pressed', async () => {
    const { codex, calls } = fakeCodex({ state: 'needs_sign_in', canShareSignIn: true });
    const { svc } = service(codexMac(), testCipher(), codex);
    const step = await codexStep(svc);
    expect(step.state).toBe('todo');
    expect(step.action).toEqual({ id: 'codex-share', label: 'Use my Codex sign-in' });
    expect(step.commands).toEqual([]);
    expect(calls.share).toBe(0);
  });

  it('shares the sign-in, re-checks and marks the step done', async () => {
    const { codex, calls } = fakeCodex({ state: 'needs_sign_in', canShareSignIn: true });
    const { svc } = service(codexMac(), testCipher(), codex);
    await codexStep(svc);
    const v = await svc.runAction('codex-share');
    const step = v.steps.find((s) => s.id === 'codex')!;
    expect(calls.share).toBe(1);
    expect(step.state).toBe('done');
    expect(step.detail).toBe('Signed in as me@example.com');
    expect(step.action).toBeUndefined();
  });

  it('keeps ChatGPT sign-in as the way when the sign-in lives in the Keychain', async () => {
    const { codex } = fakeCodex({ state: 'needs_sign_in' }, {
      ok: false,
      reason: 'no_sign_in_file',
    } as never);
    const { svc } = service(codexMac(), testCipher(), codex);
    const step = await codexStep(svc);
    expect(step.action).toBeUndefined();
    await expect(svc.runAction('codex-share')).rejects.toThrow('Keychain');
  });

  it('does not start Codex on every poll', async () => {
    const { codex, calls } = fakeCodex({ state: 'needs_sign_in', canShareSignIn: true });
    const { svc } = service(codexMac(), testCipher(), codex);
    await codexStep(svc);
    await codexStep(svc);
    expect(calls.status).toBe(1);
    await codexStep(svc, true);
    expect(calls.status).toBe(2);
  });

  it('never asks about sign-in when Codex is not installed', async () => {
    const { codex, calls } = fakeCodex({ state: 'not_installed' });
    const { svc } = service(fakeMac({}), testCipher(), codex);
    expect((await codexStep(svc)).state).not.toBe('done');
    expect(calls.status).toBe(0);
  });
});

describe('setup on Linux', () => {
  const linux = (distro: 'debian' | 'fedora' | 'other') =>
    setupPlan({ platform: 'linux', distro, helperInstallCommand: 'sudo sh x' });

  it('tells apt and dnf distributions apart from /etc/os-release', () => {
    expect(linuxDistro('NAME="Ubuntu"\nID=ubuntu\nID_LIKE=debian\n')).toBe('debian');
    expect(linuxDistro('ID=linuxmint\nID_LIKE="ubuntu debian"\n')).toBe('debian');
    expect(linuxDistro('ID=debian\n')).toBe('debian');
    expect(linuxDistro('ID=fedora\n')).toBe('fedora');
    expect(linuxDistro('ID="rocky"\nID_LIKE="rhel centos fedora"\n')).toBe('fedora');
    expect(linuxDistro('ID=arch\n')).toBe('other');
    expect(linuxDistro('')).toBe('other');
  });

  it('protects with fapolicyd, osquery and the helper, with no Homebrew or Santa', () => {
    for (const distro of ['debian', 'fedora', 'other'] as const) {
      const plan = linux(distro);
      const ids = plan.map((s) => s.id);
      expect(ids.slice(0, 3)).toEqual(['fapolicyd', 'osquery', 'helper']);
      expect(ids.some((id) => id === 'homebrew' || id.startsWith('santa'))).toBe(false);
      plan.forEach((s, i) => {
        for (const dep of s.after ?? []) {
          const at = plan.findIndex((x) => x.id === dep);
          expect(at, `${s.id} after ${dep}`).toBeGreaterThanOrEqual(0);
          expect(at).toBeLessThan(i);
        }
      });
      const cmds = plan.flatMap((s) => s.commands.map((c) => c.cmd)).join('\n');
      expect(cmds).not.toMatch(/\bbrew\b/);
    }
  });

  it('sets fapolicyd to allow everything Vigil hasn’t blocked before installing it', () => {
    const cmds = linux('fedora')
      .find((s) => s.id === 'fapolicyd')!
      .commands.map((c) => c.cmd);
    expect(cmds[0]).toContain(`'allow perm=any all : all' | sudo tee ${FAPOLICYD_ALLOW_RULES}`);
    expect(cmds[1]).toBe('sudo dnf install -y fapolicyd');
    expect(cmds[2]).toContain('fagenrules --load');
    // No package hashing at each start: nothing consults the trust list.
    expect(cmds[2]).toMatch(/^sudo sed -i 's\/\^trust .*trust = file/);
    // Sorted right after the helper's 05-vigil.rules, ahead of the distribution's deny rules.
    expect(FAPOLICYD_ALLOW_RULES).toMatch(/\/06-vigil-allow\.rules$/);
    const deb = linux('debian').find((s) => s.id === 'fapolicyd')!;
    expect(deb.commands[1]!.cmd).toBe('sudo apt-get install -y fapolicyd');
    const other = linux('other').find((s) => s.id === 'fapolicyd')!;
    expect(other.commands).toHaveLength(2);
  });

  it('installs osquery from its own signed repository', () => {
    const deb = linux('debian')
      .find((s) => s.id === 'osquery')!
      .commands.map((c) => c.cmd);
    expect(deb.join('\n')).toContain('1484120AC4E9F8A1A577AEEE97A80C63C9D8B80B');
    expect(deb.join('\n')).toContain('signed-by=/etc/apt/keyrings/osquery.gpg');
    expect(deb.at(-1)).toBe('sudo apt-get update && sudo apt-get install -y osquery');
    const rpm = linux('fedora')
      .find((s) => s.id === 'osquery')!
      .commands.map((c) => c.cmd);
    expect(rpm.at(-1)).toBe('sudo dnf install -y --enablerepo=osquery-s3-rpm-repo osquery');
    const other = linux('other').find((s) => s.id === 'osquery')!;
    expect(other.commands).toEqual([]);
    expect(other.unavailable).toMatch(/osquery\.io/);
  });

  it('installs the AI tools without Homebrew', () => {
    const ai = linux('debian').filter((s) => s.group === 'ai');
    expect(ai.find((s) => s.id === 'ollama')!.commands[0]!.cmd).toBe(
      'curl -fsSL https://ollama.com/install.sh | sh',
    );
    expect(ai.find((s) => s.id === 'codex')!.commands[0]!.cmd).toBe(
      'sudo npm install -g @openai/codex',
    );
    expect(ai.every((s) => !(s.after ?? []).includes('homebrew'))).toBe(true);
    expect(ai.find((s) => s.id === 'ollama')!.why).toContain('this computer');
  });

  const fakeLinux = (files: string[], fapolicydActive = false): Probe => ({
    ...fakeMac({
      files,
      runs: fapolicydActive
        ? { '/usr/bin/systemctl is-active --quiet fapolicyd': { code: 0, stdout: '' } }
        : {},
    }),
    platform: 'linux',
  });

  it('checks osquery where its Linux packages put it', async () => {
    expect((await CHECKS.osquery(fakeLinux(['/opt/osquery/bin/osqueryd']))).ok).toBe(true);
    expect((await CHECKS.osquery(fakeLinux(['/usr/local/bin/osqueryi']))).ok).toBe(false);
  });

  it('counts fapolicyd only when it runs with Vigil’s allow rules', async () => {
    expect((await CHECKS.fapolicyd(fakeLinux([]))).ok).toBe(false);
    expect(await CHECKS.fapolicyd(fakeLinux(['/usr/sbin/fapolicyd'], true))).toMatchObject({
      ok: false,
      detail: expect.stringContaining('allow'),
    });
    expect(
      await CHECKS.fapolicyd(fakeLinux(['/usr/sbin/fapolicyd', FAPOLICYD_ALLOW_RULES])),
    ).toEqual({ ok: false, detail: 'Installed, not running' });
    expect(
      (await CHECKS.fapolicyd(fakeLinux(['/usr/sbin/fapolicyd', FAPOLICYD_ALLOW_RULES], true))).ok,
    ).toBe(true);
  });

  it('shows Linux steps when the probe checks a Linux computer', async () => {
    const { svc } = service(fakeLinux(['/usr/sbin/fapolicyd', FAPOLICYD_ALLOW_RULES], true));
    const view = await svc.view(true);
    const byId = Object.fromEntries(view.steps.map((s) => [s.id, s]));
    expect(byId['fapolicyd']?.state).toBe('done');
    // No package manager known, so it points at osquery's downloads.
    expect(byId['osquery']).toMatchObject({ state: 'unavailable' });
    expect(byId['helper']?.state).toBe('waiting');
    expect(byId['santa']).toBeUndefined();
  });
});

describe('opening a terminal on Linux', () => {
  it('picks the first terminal the desktop has', () => {
    expect(linuxTerminal(() => false)).toBeUndefined();
    expect(linuxTerminal((p) => p === '/usr/bin/konsole' || p === '/usr/bin/xterm')).toBe(
      '/usr/bin/konsole',
    );
    expect(linuxTerminal(() => true)).toBe('/usr/bin/x-terminal-emulator');
  });
});
