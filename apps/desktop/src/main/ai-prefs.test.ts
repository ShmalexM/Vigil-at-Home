import { describe, expect, it } from 'vitest';
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

function keys(saved: Partial<Record<ApiKeyProvider, string>> = {}): KeySource {
  return {
    list: () =>
      Object.fromEntries(Object.entries(saved).map(([p, k]) => [p, { last4: k!.slice(-4) }])),
    get: (p) => (saved[p] ? { key: saved[p]! } : undefined),
  };
}

function bridge(
  o: {
    prefs?: unknown;
    used?: UsageProvider[];
    mode?: SetupMode;
    saved?: Partial<Record<ApiKeyProvider, string>>;
  } = {},
) {
  const store = memoryStore();
  const core = new VigilCore(store, new DryRunExecutor(), true, () => NOW);
  if (o.prefs) store.setSetting('ai.prefs', o.prefs);
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
      now: () => NOW,
    });
  return { store, ai: make(), make };
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
    const { ai, make } = bridge({ prefs: OCT_8, used: ['jev', 'ollama', 'claude'] });
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
});
