import type { DatabaseSync } from 'node:sqlite';
import { describe, expect, it } from 'vitest';
import { createVigilAi, type VigilAiOptions } from '@vigil/ai';
import { AiBridge, type KeySource } from './ai.js';
import { DryRunExecutor } from './executor.js';
import { VigilCore } from './service.js';
import { memoryStore } from './testing.js';
import type { ApiKeyProvider, SetupMode } from '../shared/setup.js';
import type { UsageProvider } from '../shared/usage.js';

const NOW = new Date(2026, 9, 8, 12).getTime();

/** What Alex's Mac had on 09-28, before the claudePlan / codexUses switches existed. */
const SEPT_28 = {
  claude: true,
  codex: true,
  api: true,
  ollama: true,
  jev: true,
  labelling: true,
  claudeUses: 'subscription',
};
/** What it had on 10-08: every AI app off, labelling on. */
const OCT_8 = {
  claude: false,
  codex: false,
  api: false,
  ollama: false,
  jev: false,
  labelling: true,
  claudePlan: true,
  codexUses: 'subscription',
};

/** A key, or a custom gateway's key with its address. */
type Saved = Partial<Record<ApiKeyProvider, string | { key: string; baseUrl: string }>>;

function keys(saved: Saved = {}): KeySource {
  const of = (k: string | { key: string; baseUrl: string }) =>
    typeof k === 'string' ? { key: k } : k;
  return {
    list: () =>
      Object.fromEntries(
        Object.entries(saved).map(([p, k]) => {
          const { key, baseUrl } = of(k!) as { key: string; baseUrl?: string };
          return [p, { last4: key.slice(-4), ...(baseUrl ? { baseUrl } : {}) }];
        }),
      ),
    get: (p) => (saved[p] ? of(saved[p]!) : undefined),
  };
}

function bridge(
  o: {
    prefs?: unknown;
    used?: UsageProvider[];
    mode?: SetupMode;
    saved?: Saved;
  } = {},
) {
  const store = memoryStore();
  const core = new VigilCore(store, new DryRunExecutor(), true, () => NOW);
  if (o.prefs !== undefined) store.setSetting('ai.prefs', o.prefs);
  const made: VigilAiOptions[] = [];
  for (const [i, provider] of (o.used ?? []).entries())
    store.addAiRun({
      id: `r${i}`,
      at: NOW - 7 * 86_400_000,
      provider,
      purpose: 'explain',
      ok: true,
      inputTokens: 1,
      cachedInputTokens: 0,
      outputTokens: 1,
      costUsd: null,
    });
  const make = () =>
    new AiBridge({
      store,
      usage: core.usage,
      keys: keys(o.saved),
      mode: () => o.mode ?? 'both',
      dataDir: '/tmp/vigil-prefs-test',
      openExternal: async () => {},
      create: (options) => (made.push(options), createVigilAi(options)),
      now: () => NOW,
    });
  return { store, ai: make(), make, made };
}

const providers = (p: Record<string, unknown>) =>
  Object.fromEntries(['claude', 'codex', 'api', 'ollama', 'jev'].map((k) => [k, p[k]]));

describe('AI prefs', () => {
  it('keeps every switch of prefs saved by an older Vigil, and adds the new ones off', () => {
    const { ai, make } = bridge({ prefs: SEPT_28 });
    expect(ai.prefs()).toMatchObject({
      ...providers(SEPT_28),
      labelling: true,
      claudePlan: false,
      codexUses: 'subscription',
    });
    // A later change to one switch keeps the rest.
    ai.setPrefs({ claudePlan: true });
    expect(make().prefs()).toMatchObject({ ...providers(SEPT_28), claudePlan: true });
  });

  it('never switches AI back on by itself, and its button names what it turns on', async () => {
    const { ai, make } = bridge({
      prefs: OCT_8,
      used: ['jev', 'ollama', 'claude'],
      saved: { typesafe: 'ts-1234' },
    });
    // A deliberate opt-out looks the same as an accidental one: nothing changes on start.
    expect(providers(make().prefs())).toEqual(providers(OCT_8));
    const fix = ai.offFix();
    expect(fix?.notice).toMatch(/Every AI app is switched off/);
    // His plan switch was on, so the notice says the plan comes back with Claude.
    expect(fix?.notice).toMatch(/Claude plan/);
    expect(fix?.label).toBe('Turn on Claude, Ollama and Jev');
    const after = ai.turnBackOn();
    expect(providers(after)).toEqual({
      claude: true,
      codex: false,
      api: false,
      ollama: true,
      jev: true,
    });
    // The plan stays the user's own choice, and labelling as it was.
    expect(after).toMatchObject({ claudePlan: true, labelling: true, codexUses: 'subscription' });
    expect(make().offNotice()).toBeUndefined();
    // The button does nothing once nothing is wrong.
    expect(providers(make().turnBackOn())).toEqual(providers(after));
  });

  it('never switches on the Claude plan, and uses setup’s mode when nothing ran yet', () => {
    const { ai } = bridge({ prefs: { ...OCT_8, claudePlan: false }, mode: 'local' });
    expect(ai.offFix()?.notice).not.toMatch(/Claude plan/);
    expect(ai.offFix()?.label).toBe('Turn on Ollama');
    expect(ai.turnBackOn()).toMatchObject({ ollama: true, claude: false, claudePlan: false });
  });

  it('says when labelling is on but nothing that labels is switched on', () => {
    const { ai } = bridge({
      prefs: { ...OCT_8, codex: true, claudePlan: false },
      saved: { typesafe: 'ts-1234' },
    });
    // Outside cloud mode Codex doesn't label; Ollama does, for free.
    expect(ai.offNotice()).toMatch(/no AI app that labels events/);
    expect(ai.offFix()?.label).toBe('Label with Ollama');
    expect(ai.turnBackOn()).toMatchObject({ ollama: true, codex: true, jev: false });
    expect(ai.offNotice()).toBeUndefined();
    ai.setPrefs({ ollama: false, jev: true });
    expect(ai.offNotice()).toBeUndefined();
  });

  it('in cloud mode, counts what the cloud runner labels with, and lets the user pick', () => {
    const codex = bridge({ prefs: { ...OCT_8, codex: true }, mode: 'cloud' });
    expect(codex.ai.offNotice()).toBeUndefined();
    const api = bridge({
      prefs: { ...OCT_8, api: true },
      mode: 'cloud',
      saved: { openai: 'sk-1234' },
    });
    expect(api.ai.offNotice()).toBeUndefined();
    const ollamaOnly = bridge({ prefs: { ...OCT_8, ollama: true }, mode: 'cloud' });
    const fix = ollamaOnly.ai.offFix();
    expect(fix?.notice).toMatch(/no AI app that labels events.*Pick one/);
    expect(fix?.label).toBeUndefined();
    expect(providers(ollamaOnly.ai.turnBackOn())).toEqual(providers({ ...OCT_8, ollama: true }));
  });

  it('in cloud mode, never turns on Ollama, which cloud mode doesn’t use', () => {
    const { ai } = bridge({ prefs: OCT_8, used: ['ollama'], mode: 'cloud' });
    const fix = ai.offFix();
    // What ran before isn't allowed, so the button offers what cloud mode can run.
    expect(fix?.label).toBe('Turn on Claude and Codex');
    expect(fix?.patch).toEqual({ claude: true, codex: true });
    expect(ai.turnBackOn()).toMatchObject({ ollama: false, claude: true, codex: true });
  });

  it('turns on a labeller with Codex in both mode, so one click is enough', () => {
    const { ai } = bridge({ prefs: OCT_8, used: ['codex'], mode: 'both' });
    expect(ai.offFix()?.label).toBe('Turn on Codex and Ollama');
    ai.turnBackOn();
    expect(ai.offFix()).toBeUndefined();
  });

  it('in local mode, never promises the Claude plan', () => {
    const { ai } = bridge({ prefs: OCT_8, used: ['claude'], mode: 'local' });
    const fix = ai.offFix();
    expect(fix?.notice).not.toMatch(/Claude plan/);
    expect(fix?.label).toBe('Turn on Ollama');
    expect(fix?.patch).toEqual({ ollama: true });
  });

  it('offers no button when only a key would help, and says where to add it', () => {
    const { ai } = bridge({ prefs: { ...OCT_8, claudePlan: false }, used: ['jev'], mode: 'cloud' });
    // Jev ran before but no key is saved now; Codex is the fallback a switch can start.
    expect(ai.offFix()?.label).toBe('Turn on Codex');
    const keyOnly = bridge({
      prefs: { ...OCT_8, claudePlan: false, codexUses: 'apiKey' },
      used: ['jev', 'api'],
      mode: 'cloud',
    });
    const fix = keyOnly.ai.offFix();
    expect(fix?.label).toBeUndefined();
    expect(fix?.patch).toBeUndefined();
    expect(fix?.notice).toMatch(
      /The API connection needs an OpenRouter or OpenAI key and Jev needs an OpenRouter or TypeSafe key: add them under API keys in Setup, then turn them on under “Explains alerts” and “Labels events no rule matched”/,
    );
  });

  it('says when Codex on an API key has no key to label with', () => {
    const { ai } = bridge({
      prefs: { ...OCT_8, codex: true, codexUses: 'apiKey' },
      mode: 'cloud',
    });
    const fix = ai.offFix();
    expect(fix?.notice).toMatch(/Codex needs an OpenAI API key to label events/);
    expect(fix?.notice).toMatch(/“Explains alerts”/);
    expect(fix?.label).toBeUndefined();
    const withKey = bridge({
      prefs: { ...OCT_8, codex: true, codexUses: 'apiKey' },
      mode: 'cloud',
      saved: { openai: 'sk-1234' },
    });
    expect(withKey.ai.offNotice()).toBeUndefined();
  });

  it('reaches Jev through a custom connection at openrouter.ai, as the runner does', () => {
    const { ai, made } = bridge({
      prefs: { ...OCT_8, api: true, jev: true },
      mode: 'both',
      saved: { custom: { key: 'or-1234', baseUrl: 'https://openrouter.ai/api/v1' } },
    });
    expect(ai.offNotice()).toBeUndefined();
    ai.ai();
    expect(made[0]?.settings.api).toMatchObject({ enabled: true, preset: 'custom' });
    expect(made[0]?.keys).toMatchObject({ api: true, typesafe: false });
  });

  it('keeps every AI app off when the saved prefs are damaged', () => {
    // One bad field keeps the rest of the record.
    const bad = bridge({ prefs: { ...OCT_8, monthlyCapUsd: null } });
    expect(providers(bad.ai.prefs())).toEqual(providers(OCT_8));
    expect(bad.ai.prefs()).toMatchObject({ labelling: true, claudePlan: true });
    // A switch that can't be read stays off; the others keep their value.
    const odd = bridge({ prefs: { ...OCT_8, ollama: 'yes', claude: true } });
    expect(providers(odd.ai.prefs())).toEqual(providers({ ...OCT_8, claude: true }));
    // Not an object at all, or not JSON: still off.
    expect(providers(bridge({ prefs: null }).ai.prefs())).toEqual(providers(OCT_8));
    const notJson = bridge();
    (notJson.store as unknown as { db: DatabaseSync }).db
      .prepare('INSERT INTO settings (key, value) VALUES (?, ?)')
      .run('ai.prefs', '{not json');
    expect(providers(notJson.make().prefs())).toEqual(providers(OCT_8));
    // Only with nothing saved do the defaults apply.
    expect(bridge().ai.prefs()).toMatchObject({ claude: true, ollama: true, jev: true });
  });

  it('rebuilds the runner once a key is saved', () => {
    const saved: Saved = {};
    const store = memoryStore();
    const core = new VigilCore(store, new DryRunExecutor(), true, () => NOW);
    store.setSetting('ai.prefs', { ...OCT_8, jev: true, ollama: true });
    const made: VigilAiOptions[] = [];
    const ai = new AiBridge({
      store,
      usage: core.usage,
      keys: keys(saved),
      mode: () => 'both',
      dataDir: '/tmp/vigil-prefs-test',
      openExternal: async () => {},
      create: (options) => (made.push(options), createVigilAi(options)),
      now: () => NOW,
    });
    const first = ai.ai();
    expect(ai.ai()).toBe(first);
    expect(made[0]?.getJevApiKey).toBeUndefined();
    saved.typesafe = 'ts-1234';
    expect(ai.ai()).not.toBe(first);
    expect(made).toHaveLength(2);
    expect(made[1]?.getJevApiKey).toBeDefined();
    expect(made[1]?.keys?.typesafe).toBe(true);
  });
});
