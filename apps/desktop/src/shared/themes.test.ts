import { describe, expect, it } from 'vitest';
import { Appearance } from './ipc.js';
import {
  contrastRatio,
  DEFAULT_APPEARANCE,
  parseCodexTheme,
  resolveColors,
  shareCodexTheme,
  THEME_PRESETS,
  themeTokens,
  type ThemeVariant,
} from './themes.js';

const variants = (['light', 'dark'] as const).flatMap((v) =>
  THEME_PRESETS.filter((p) => p[v]).map((p) => [p.name, v, p[v]!] as const),
);

describe('themes', () => {
  it.each(variants)('%s %s keeps every text shade readable at every contrast', (_n, v, colors) => {
    for (const contrast of [0, 50, 100]) {
      const t = themeTokens(colors, v, contrast);
      for (const bg of ['--bg0', '--bg1', '--bg2', '--bg3']) {
        for (const tx of ['--tx2', '--tx3']) {
          expect(contrastRatio(t[tx]!, t[bg]!)).toBeGreaterThanOrEqual(4.4);
        }
      }
      expect(contrastRatio(t['--ac-tx']!, t['--ac']!)).toBeGreaterThanOrEqual(3);
    }
  });

  it('matches the Codex app’s default colours', () => {
    expect(resolveColors(DEFAULT_APPEARANCE, 'dark')).toEqual({
      accent: '#339CFF',
      background: '#181818',
      foreground: '#FFFFFF',
    });
    expect(themeTokens(resolveColors(DEFAULT_APPEARANCE, 'dark'), 'dark')['--bg0']).toBe('#181818');
  });

  it('puts overrides on top of the preset', () => {
    const a = { ...DEFAULT_APPEARANCE, light: { preset: 'nord', accent: '#FF0000' } };
    expect(resolveColors(a, 'light')).toEqual({
      accent: '#FF0000',
      background: '#ECEFF4',
      foreground: '#2E3440',
    });
    // An unknown preset falls back to the default rather than breaking the window.
    expect(resolveColors({ ...a, dark: { preset: 'gone' } }, 'dark').background).toBe('#181818');
  });

  it('reads a theme shared from Codex, taking only colours, contrast and fonts', () => {
    const shared =
      'codex-theme-v1:' +
      JSON.stringify({
        codeThemeId: 'one',
        variant: 'dark',
        theme: {
          accent: '#5c99d6',
          ink: '#d8dee9',
          surface: '#303841',
          contrast: 60,
          opaqueWindows: true,
          fonts: { ui: 'Inter', code: null },
          semanticColors: { diffAdded: '#99c794' },
        },
      });
    expect(parseCodexTheme(shared)).toEqual({
      variant: 'dark',
      colors: { accent: '#5c99d6', background: '#303841', foreground: '#d8dee9' },
      contrast: 60,
      uiFont: 'Inter',
    });
  });

  it('refuses anything that isn’t a well-formed theme', () => {
    const bad = (theme: unknown, extra = {}) =>
      parseCodexTheme('codex-theme-v1:' + JSON.stringify({ theme, ...extra }));
    expect(parseCodexTheme('{"theme":{}}')).toBeNull();
    expect(parseCodexTheme('codex-theme-v1:not json')).toBeNull();
    expect(bad({ accent: 'red', ink: '#000000', surface: '#ffffff' })).toBeNull();
    expect(bad({ accent: '#000000', ink: '#000000', surface: '#ffffff;}' })).toBeNull();
    // A font name that could break out of the CSS value is dropped, not used.
    const t = bad({
      accent: '#000000',
      ink: '#000000',
      surface: '#ffffff',
      fonts: { ui: 'x; } body { display: none' },
    });
    expect(t?.uiFont).toBeUndefined();
    // Without a variant, the background decides.
    expect(t?.variant).toBe('light');
  });

  it('shares in a form it (and Codex) can read back', () => {
    for (const v of ['light', 'dark'] as ThemeVariant[]) {
      const a = { ...DEFAULT_APPEARANCE, contrast: 70, [v]: { preset: 'dracula' } };
      const back = parseCodexTheme(shareCodexTheme(a, v));
      expect(back?.variant).toBe(v);
      expect(back?.colors).toEqual(resolveColors(a, v));
      expect(back?.contrast).toBe(70);
    }
  });

  it('validates appearance settings coming over IPC', () => {
    expect(Appearance.parse(DEFAULT_APPEARANCE)).toEqual(DEFAULT_APPEARANCE);
    const bad = (patch: object) =>
      Appearance.safeParse({ ...DEFAULT_APPEARANCE, ...patch }).success;
    expect(bad({ contrast: 101 })).toBe(false);
    expect(bad({ uiFontSize: 40 })).toBe(false);
    expect(bad({ dark: { preset: 'default', accent: 'url(x)' } })).toBe(false);
    expect(bad({ uiFont: 'a} *{color:red' })).toBe(false);
  });
});
