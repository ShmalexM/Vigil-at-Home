import { mkdtempSync, readFileSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { memoryStore } from '../testing.js';
import { CHECKS, HELPER_SOCKET, type Probe } from './checks.js';
import { KeyStore, type Cipher } from './keys.js';
import { LOCAL_MODEL, LOCAL_MODEL_SMALL, localModelFor, setupPlan, stepsFor } from './plan.js';
import { OnboardingService } from './service.js';

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

function service(probe: Probe, cipher = testCipher()) {
  const dir = mkdtempSync(join(tmpdir(), 'vigil-setup-'));
  const keys = new KeyStore(join(dir, 'keys.json'), cipher);
  let t = 1_000_000;
  const svc = new OnboardingService({
    store: memoryStore(),
    keys,
    probe,
    supported: true,
    now: () => (t += 5000),
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

  it('sees the helper by its socket', async () => {
    expect((await CHECKS.helper(fakeMac({ files: [HELPER_SOCKET] }))).ok).toBe(true);
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

  it('says steps without a command yet are coming, unless already done', async () => {
    const { svc } = service(fakeMac({}));
    svc.setMode('local');
    const helper = (await svc.view()).steps.find((s) => s.id === 'helper')!;
    expect(helper.state).toBe('unavailable');
    expect(helper.detail).toContain('blocking update');

    const { svc: svc2 } = service(fakeMac({ files: [HELPER_SOCKET] }));
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

  it('needs a mode before finishing, and can be run again', async () => {
    const { svc } = service(fakeMac({}));
    expect(() => svc.finish()).toThrow();
    svc.setMode('cloud');
    svc.finish();
    expect(svc.finished()).toBe(true);
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
