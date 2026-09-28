/**
 * Themes, laid out the way the Codex desktop app does it: pick light, dark or
 * system, then a theme for each, whose accent, background and foreground you can
 * override, plus one contrast level. Every surface, line and text shade is
 * derived from those three colours. Good / Fair / Poor, severities and the AI
 * colour stay Vigil's own (tokens.css), so they read the same in every theme.
 *
 * No zod here: the renderer imports this file. The schema is in ipc.ts.
 */

export type ThemeVariant = 'light' | 'dark';

export interface ThemeColors {
  accent: string;
  background: string;
  foreground: string;
}

export interface ThemePreset {
  id: string;
  name: string;
  light?: ThemeColors;
  dark?: ThemeColors;
}

const c = (accent: string, background: string, foreground: string): ThemeColors => ({
  accent,
  background,
  foreground,
});

/** The Codex desktop app's themes, then Vigil's original look. */
export const THEME_PRESETS: readonly ThemePreset[] = [
  {
    id: 'default',
    name: 'Default',
    light: c('#0285FF', '#FFFFFF', '#0D0D0D'),
    dark: c('#339CFF', '#181818', '#FFFFFF'),
  },
  {
    id: 'catppuccin',
    name: 'Catppuccin',
    light: c('#8839EF', '#EFF1F5', '#4C4F69'),
    dark: c('#CBA6F7', '#1E1E2E', '#CDD6F4'),
  },
  {
    id: 'dracula',
    name: 'Dracula',
    light: c('#A3144D', '#FFFBEB', '#1F1F1F'),
    dark: c('#FF79C6', '#282A36', '#F8F8F2'),
  },
  {
    id: 'github',
    name: 'GitHub',
    light: c('#0969DA', '#FFFFFF', '#1F2328'),
    dark: c('#4493F8', '#0D1117', '#E6EDF3'),
  },
  {
    id: 'gruvbox',
    name: 'Gruvbox',
    light: c('#AF3A03', '#FBF1C7', '#3C3836'),
    dark: c('#FE8019', '#282828', '#EBDBB2'),
  },
  { id: 'monokai', name: 'Monokai', dark: c('#A6E22E', '#272822', '#F8F8F2') },
  {
    id: 'nord',
    name: 'Nord',
    light: c('#5E81AC', '#ECEFF4', '#2E3440'),
    dark: c('#88C0D0', '#2E3440', '#D8DEE9'),
  },
  {
    id: 'one',
    name: 'One',
    light: c('#4078F2', '#FAFAFA', '#383A42'),
    dark: c('#61AFEF', '#282C34', '#ABB2BF'),
  },
  {
    id: 'solarized',
    name: 'Solarized',
    light: c('#268BD2', '#FDF6E3', '#657B83'),
    dark: c('#268BD2', '#002B36', '#839496'),
  },
  {
    id: 'tokyo-night',
    name: 'Tokyo Night',
    light: c('#2E7DE9', '#E1E2E7', '#3760BF'),
    dark: c('#7AA2F7', '#1A1B26', '#C0CAF5'),
  },
  {
    id: 'vigil',
    name: 'Vigil classic',
    light: c('#0A6FD6', '#FFFFFF', '#0B0F19'),
    dark: c('#3AA8FF', '#141414', '#F5F5F5'),
  },
];

export interface VariantTheme {
  preset: string;
  /** Overrides of the preset's colours. */
  accent?: string | undefined;
  background?: string | undefined;
  foreground?: string | undefined;
}

export interface AppearanceSettings {
  light: VariantTheme;
  dark: VariantTheme;
  /** 0 to 100; 50 is the theme as designed. */
  contrast: number;
  /** Base text size in the main window, in pixels. */
  uiFontSize: number;
  /** CSS font families; empty uses Vigil's. */
  uiFont: string;
  codeFont: string;
}

export const DEFAULT_UI_FONT_SIZE = 13;

export const DEFAULT_APPEARANCE: AppearanceSettings = {
  light: { preset: 'default' },
  dark: { preset: 'default' },
  contrast: 50,
  uiFontSize: DEFAULT_UI_FONT_SIZE,
  uiFont: '',
  codeFont: '',
};

export function presetsFor(variant: ThemeVariant): ThemePreset[] {
  return THEME_PRESETS.filter((p) => p[variant]);
}

/** The colours in use for one variant: the preset's, with any overrides on top. */
export function resolveColors(a: AppearanceSettings, variant: ThemeVariant): ThemeColors {
  const t = a[variant];
  const base =
    THEME_PRESETS.find((p) => p.id === t.preset)?.[variant] ?? THEME_PRESETS[0]![variant]!;
  return {
    accent: t.accent ?? base.accent,
    background: t.background ?? base.background,
    foreground: t.foreground ?? base.foreground,
  };
}

// ---------------------------------------------------------------- colour maths

type Rgb = [number, number, number];

export function parseHex(hex: string): Rgb {
  const n = parseInt(hex.slice(1), 16);
  return [(n >> 16) & 255, (n >> 8) & 255, n & 255];
}

function toHex([r, g, b]: Rgb): string {
  return '#' + [r, g, b].map((v) => Math.round(v).toString(16).padStart(2, '0')).join('');
}

/** `a` moved toward `b` by `t` (0 to 1). */
function mix(a: Rgb, b: Rgb, t: number): Rgb {
  const k = Math.min(1, Math.max(0, t));
  return [a[0] + (b[0] - a[0]) * k, a[1] + (b[1] - a[1]) * k, a[2] + (b[2] - a[2]) * k];
}

function luminance([r, g, b]: Rgb): number {
  const ch = (v: number) => {
    const s = v / 255;
    return s <= 0.03928 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4;
  };
  return 0.2126 * ch(r) + 0.7152 * ch(g) + 0.0722 * ch(b);
}

/** WCAG contrast ratio, 1 to 21. */
export function contrastRatio(a: string, b: string): number {
  const [x, y] = [luminance(parseHex(a)), luminance(parseHex(b))];
  return (Math.max(x, y) + 0.05) / (Math.min(x, y) + 0.05);
}

/** Moves `color` toward `toward` until it reaches `ratio` against `on`, if it can. */
function atLeast(color: Rgb, toward: Rgb, on: Rgb, ratio: number): Rgb {
  let out = color;
  for (let t = 0; t <= 1 && contrastRatio(toHex(out), toHex(on)) < ratio; t += 0.04) {
    out = mix(color, toward, t);
  }
  return out;
}

function rgba([r, g, b]: Rgb, alpha: number): string {
  return `rgb(${Math.round(r)} ${Math.round(g)} ${Math.round(b)} / ${Math.round(alpha * 100)}%)`;
}

/** The variant a background reads as, for themes imported without one. */
export function variantOf(background: string): ThemeVariant {
  return luminance(parseHex(background)) > 0.35 ? 'light' : 'dark';
}

/**
 * Every neutral and accent token for one variant. Surfaces step from the
 * background toward the foreground; text steps back, and never falls below
 * WCAG AA (4.5:1) on the darkest surface it sits on.
 */
export function themeTokens(
  colors: ThemeColors,
  variant: ThemeVariant,
  contrast = 50,
): Record<string, string> {
  const bg = parseHex(colors.background);
  const fg = parseHex(colors.foreground);
  const ac = parseHex(colors.accent);
  // 0.6 at the lowest contrast, 1 as designed, 1.4 at the highest.
  const k = 0.6 + (Math.min(100, Math.max(0, contrast)) / 100) * 0.8;
  const surf = (t: number) => mix(bg, fg, t * k);
  const dark = variant === 'dark';

  const s = dark
    ? { bg0: bg, bg1: surf(0.035), bg2: surf(0.06), bg3: surf(0.09), bg4: surf(0.13) }
    : { bg0: surf(0.04), bg1: bg, bg2: surf(0.02), bg3: surf(0.05), bg4: surf(0.085) };
  const lines = dark
    ? { ln0: surf(0.08), ln1: surf(0.12), ln2: surf(0.22) }
    : { ln0: surf(0.09), ln1: surf(0.14), ln2: surf(0.26) };
  // Text sits on bg0 to bg3; the one closest to the foreground is the worst case.
  const worst = [s.bg0, s.bg1, s.bg2, s.bg3].reduce((w, x) =>
    contrastRatio(toHex(x), colors.foreground) < contrastRatio(toHex(w), colors.foreground) ? x : w,
  );
  // Some themes' own foreground is soft (Solarized); text still reaches AA by
  // moving toward black or white.
  const extreme: Rgb = dark ? [255, 255, 255] : [0, 0, 0];
  const text = (t: number, ratio: number) => atLeast(mix(fg, bg, t / k), extreme, worst, ratio);

  const onAccent =
    contrastRatio(colors.accent, '#111111') >= contrastRatio(colors.accent, '#ffffff');
  const tokens: Record<string, [Rgb, number?] | string> = {
    ...Object.fromEntries(Object.entries({ ...s, ...lines }).map(([n, v]) => [n, [v]])),
    tx0: [atLeast(fg, extreme, worst, 7)],
    tx1: [text(0.2, 7)],
    tx2: [text(0.36, 4.5)],
    tx3: [text(0.46, 4.5)],
    ac: [atLeast(ac, dark ? [255, 255, 255] : [0, 0, 0], s.bg1, 3)],
    'ac-bg': [ac, dark ? 0.14 : 0.09],
    'ac-ln': [ac, dark ? 0.42 : 0.38],
    'ac-tx': onAccent ? '#111111' : '#ffffff',
  };
  return Object.fromEntries(
    Object.entries(tokens).map(([name, v]) => [
      `--${name}`,
      typeof v === 'string' ? v : v[1] === undefined ? toHex(v[0]) : rgba(v[0], v[1]),
    ]),
  );
}

/** The window background for a variant, so a new window doesn't flash. */
export function windowBackground(a: AppearanceSettings, variant: ThemeVariant): string {
  return themeTokens(resolveColors(a, variant), variant, a.contrast)['--bg0']!;
}

// ---------------------------------------------------------------- sharing

/** Codex's share format: `codex-theme-v1:` then JSON. */
export const CODEX_THEME_PREFIX = 'codex-theme-v1:';

const HEX = /^#[0-9a-fA-F]{6}$/;
const FONT = /^[\w\s,'"().-]{0,120}$/;

export interface ImportedTheme {
  variant: ThemeVariant;
  colors: ThemeColors;
  contrast?: number;
  uiFont?: string;
  codeFont?: string;
}

/**
 * Reads a theme shared from the Codex app (or from Vigil). Only colours,
 * contrast and font names are taken; anything else in it is ignored.
 */
export function parseCodexTheme(text: string): ImportedTheme | null {
  const s = text.trim();
  if (!s.startsWith(CODEX_THEME_PREFIX) || s.length > 4000) return null;
  let j: unknown;
  try {
    j = JSON.parse(s.slice(CODEX_THEME_PREFIX.length));
  } catch {
    return null;
  }
  if (!j || typeof j !== 'object') return null;
  const o = j as { variant?: unknown; theme?: Record<string, unknown> };
  const t = o.theme;
  if (!t || typeof t !== 'object') return null;
  const [accent, background, foreground] = [t['accent'], t['surface'], t['ink']];
  if (![accent, background, foreground].every((v) => typeof v === 'string' && HEX.test(v))) {
    return null;
  }
  const colors = c(accent as string, background as string, foreground as string);
  const variant =
    o.variant === 'light' || o.variant === 'dark' ? o.variant : variantOf(colors.background);
  const out: ImportedTheme = { variant, colors };
  if (typeof t['contrast'] === 'number' && Number.isFinite(t['contrast'])) {
    out.contrast = Math.round(Math.min(100, Math.max(0, t['contrast'])));
  }
  const fonts = t['fonts'] as Record<string, unknown> | undefined;
  if (fonts && typeof fonts === 'object') {
    if (typeof fonts['ui'] === 'string' && FONT.test(fonts['ui'])) out.uiFont = fonts['ui'];
    if (typeof fonts['code'] === 'string' && FONT.test(fonts['code'])) out.codeFont = fonts['code'];
  }
  return out;
}

const CODEX_THEME_IDS = new Set([
  'catppuccin',
  'dracula',
  'gruvbox',
  'nord',
  'one',
  'solarized',
  'tokyo-night',
]);

/** The same format, so a Vigil theme can be pasted into Codex and back. */
export function shareCodexTheme(a: AppearanceSettings, variant: ThemeVariant): string {
  const colors = resolveColors(a, variant);
  const preset = a[variant].preset;
  return (
    CODEX_THEME_PREFIX +
    JSON.stringify({
      // Codex takes the colours below over its theme's; this id only has to be one it knows.
      codeThemeId: CODEX_THEME_IDS.has(preset) ? preset : 'one',
      variant,
      theme: {
        accent: colors.accent,
        surface: colors.background,
        ink: colors.foreground,
        contrast: a.contrast,
        fonts: { ui: a.uiFont || null, code: a.codeFont || null },
      },
    })
  );
}

export const isFontFamily = (s: string) => FONT.test(s);
export const isHexColor = (s: string) => HEX.test(s);
