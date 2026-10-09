import { describe, expect, it } from 'vitest';
import { canRun, jevRoute, whoRuns, type AiKeysSaved } from './reach.js';
import { defaultAiSettings, type AiSettings } from './settings.js';

const NO_KEYS: AiKeysSaved = { anthropic: false, openai: false, api: false, typesafe: false };

/** Every app off, then `on` switched on, in `mode`. */
function only(
  mode: AiSettings['mode'],
  on: Array<'claude' | 'codex' | 'api' | 'ollama' | 'jev'>,
  over: Partial<AiSettings> = {},
): AiSettings {
  const base = defaultAiSettings('/tmp/vigil-reach');
  const s: AiSettings = { ...base, mode, ...over };
  return {
    ...s,
    claude: { ...s.claude, enabled: on.includes('claude') },
    codex: { ...s.codex, enabled: on.includes('codex') },
    api: { ...s.api, enabled: on.includes('api') },
    ollama: { ...s.ollama, enabled: on.includes('ollama') },
    jev: { ...s.jev, enabled: on.includes('jev') },
  };
}

describe('who runs', () => {
  it('keeps each provider to what the mode allows', () => {
    expect(canRun(only('cloud', ['ollama']), NO_KEYS, 'ollama', 'explain')).toBe(
      'not_allowed_by_mode',
    );
    expect(whoRuns(only('cloud', ['ollama']), NO_KEYS, 'label')).toEqual({
      why: 'not_allowed_by_mode',
    });
    const local = only('local', ['claude'], {
      claude: { enabled: true, mode: 'apiKey', allowPlan: true },
    });
    expect(canRun(local, NO_KEYS, 'claude', 'explain')).toBe('not_allowed_by_mode');
    expect(whoRuns(only('local', []), NO_KEYS, 'explain')).toEqual({ why: 'off' });
  });

  it('labels with Codex only in cloud mode', () => {
    expect(whoRuns(only('both', ['codex']), NO_KEYS, 'explain')).toEqual({ provider: 'codex' });
    expect(whoRuns(only('both', ['codex']), NO_KEYS, 'label')).toEqual({ why: 'off' });
    expect(whoRuns(only('cloud', ['codex']), NO_KEYS, 'label')).toEqual({ provider: 'codex' });
  });

  it('needs an OpenAI key for Codex on an API key', () => {
    const s = only('cloud', ['codex'], {
      codex: { enabled: true, mode: 'apiKey', codexHome: '/tmp/vigil-reach/codex' },
    });
    expect(whoRuns(s, NO_KEYS, 'label')).toEqual({ why: 'needs_setup' });
    expect(whoRuns(s, NO_KEYS, 'explain')).toEqual({ why: 'needs_setup' });
    expect(whoRuns(s, { ...NO_KEYS, openai: true }, 'label')).toEqual({ provider: 'codex' });
  });

  it('lets the Claude plan explain, but never label', () => {
    const s = only('both', ['claude'], {
      claude: { enabled: true, mode: 'apiKey', allowPlan: true },
    });
    expect(canRun(s, NO_KEYS, 'claude', 'explain')).toBe(true);
    expect(canRun(s, NO_KEYS, 'claude', 'label')).toBe('needs_setup');
    expect(canRun(s, { ...NO_KEYS, anthropic: true }, 'claude', 'label')).toBe(true);
  });

  it('reaches Jev through any API connection at openrouter.ai', () => {
    const custom = only('cloud', ['api', 'jev'], {
      api: { enabled: true, preset: 'custom', baseUrl: 'https://openrouter.ai/api/v1' },
    });
    const keys = { ...NO_KEYS, api: true };
    expect(jevRoute(custom, keys)).toEqual({ typesafe: false, openrouter: true });
    expect(whoRuns(custom, keys, 'label')).toEqual({ provider: 'jev' });
    const other = only('cloud', ['api', 'jev'], {
      api: { enabled: true, preset: 'custom', baseUrl: 'https://gateway.example/v1' },
    });
    expect(jevRoute(other, keys)).toBeUndefined();
    expect(canRun(other, keys, 'jev', 'label')).toBe('needs_setup');
  });

  it('says labelling is off when it is', () => {
    const s = only('both', ['ollama']);
    expect(
      whoRuns({ ...s, classifier: { ...s.classifier, enabled: false } }, NO_KEYS, 'label'),
    ).toEqual({ why: 'off' });
    expect(whoRuns(s, NO_KEYS, 'label')).toEqual({ provider: 'ollama' });
  });
});
