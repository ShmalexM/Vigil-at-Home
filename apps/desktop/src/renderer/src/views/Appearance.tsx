import { ChevronRight, ClipboardCopy, Download, RotateCcw } from 'lucide-react';
import { useEffect, useRef, useState } from 'react';
import type { ThemePref } from '../../../shared/ipc';
import {
  DEFAULT_APPEARANCE,
  isFontFamily,
  isHexColor,
  parseCodexTheme,
  presetsFor,
  resolveColors,
  shareCodexTheme,
  type AppearanceSettings,
  type ThemeColors,
  type ThemeVariant,
} from '../../../shared/themes';
import { vigil } from '../api';
import { useToast } from '../components/Toasts';
import { Button, SectionHead, Segmented } from '../components/ui';
import '../styles/appearance.css';

const COLOR_FIELDS: { key: keyof ThemeColors; label: string }[] = [
  { key: 'accent', label: 'Accent' },
  { key: 'background', label: 'Background' },
  { key: 'foreground', label: 'Foreground' },
];

/**
 * Settings › Appearance, laid out like the Codex desktop app: light, dark or
 * system up front; under a collapsed Advanced section, a theme for each whose
 * colours can be changed, contrast, text size and fonts, and Codex's share
 * format to bring themes across.
 */
export function AppearanceSection({
  theme,
  saved,
  onTheme,
}: {
  theme: ThemePref;
  saved: AppearanceSettings;
  onTheme: (t: ThemePref) => void;
}) {
  const toast = useToast();
  // Edits show at once here and are saved a moment later, so dragging a colour stays smooth.
  const [a, setA] = useState(saved);
  const timer = useRef<ReturnType<typeof setTimeout>>(undefined);
  const pending = useRef(false);
  const savedKey = JSON.stringify(saved);
  // Take what's saved (say, from another window), unless an edit here is still on its way.
  useEffect(() => {
    if (!pending.current) setA(JSON.parse(savedKey) as AppearanceSettings);
  }, [savedKey]);
  useEffect(() => () => clearTimeout(timer.current), []);
  const update = (next: AppearanceSettings) => {
    setA(next);
    pending.current = true;
    clearTimeout(timer.current);
    timer.current = setTimeout(() => {
      void vigil.setAppearance(next).finally(() => (pending.current = false));
    }, 150);
  };

  const [importText, setImportText] = useState('');
  const importTheme = () => {
    const t = parseCodexTheme(importText);
    if (!t) {
      toast({
        text: 'That isn’t a Codex theme. Share one from Codex’s Appearance settings and paste it here.',
      });
      return;
    }
    update({
      ...a,
      [t.variant]: { preset: a[t.variant].preset, ...t.colors },
      ...(t.contrast !== undefined ? { contrast: t.contrast } : {}),
      ...(t.uiFont !== undefined ? { uiFont: t.uiFont } : {}),
      ...(t.codeFont !== undefined ? { codeFont: t.codeFont } : {}),
    });
    setImportText('');
    toast({ text: `Imported as your ${t.variant} theme` });
  };

  return (
    <>
      <SectionHead title="Appearance" sub="Use light, dark, or match your system." />
      <div className="row spread">
        <span>Theme</span>
        <Segmented<ThemePref>
          label="Theme"
          value={theme}
          onChange={onTheme}
          options={[
            { value: 'system', label: 'System' },
            { value: 'light', label: 'Light' },
            { value: 'dark', label: 'Dark' },
          ]}
        />
      </div>
      <details className="appearance-advanced">
        <summary>
          <ChevronRight size={15} className="appearance-chevron" aria-hidden />
          <span>
            Advanced
            <span className="small muted"> · theme colours, contrast, text size, fonts</span>
          </span>
        </summary>
        <div className="theme-grid">
          {(['light', 'dark'] as const).map((v) => (
            <VariantEditor
              key={v}
              variant={v}
              a={a}
              onChange={update}
              onCopy={async () => {
                await navigator.clipboard.writeText(shareCodexTheme(a, v));
                toast({
                  text: `Copied your ${v} theme. Paste it into Codex, or into Vigil on another Mac.`,
                });
              }}
            />
          ))}
        </div>
        <div className="appearance-rows">
          <label className="row spread">
            <span>
              Contrast
              <span className="small muted"> · how far surfaces and text step apart</span>
            </span>
            <span className="row" style={{ gap: 10 }}>
              <input
                type="range"
                min={0}
                max={100}
                value={a.contrast}
                aria-label="Contrast"
                onChange={(e) => update({ ...a, contrast: Number(e.target.value) })}
              />
              <span className="mono small range-value">{a.contrast}</span>
            </span>
          </label>
          <label className="row spread">
            <span>
              Text size
              <span className="small muted"> · the main window’s base size</span>
            </span>
            <span className="row" style={{ gap: 10 }}>
              <input
                type="range"
                min={11}
                max={16}
                value={a.uiFontSize}
                aria-label="Text size"
                onChange={(e) => update({ ...a, uiFontSize: Number(e.target.value) })}
              />
              <span className="mono small range-value">{a.uiFontSize}px</span>
            </span>
          </label>
          <FontField
            label="UI font"
            value={a.uiFont}
            placeholder="Plus Jakarta Sans"
            onChange={(uiFont) => update({ ...a, uiFont })}
          />
          <FontField
            label="Code font"
            value={a.codeFont}
            placeholder="Roboto Mono"
            onChange={(codeFont) => update({ ...a, codeFont })}
          />
          <div className="row spread">
            <span>
              Import a theme
              <span className="small muted"> · paste one shared from Codex</span>
            </span>
            <span className="row" style={{ gap: 8 }}>
              <input
                className="field import-field"
                aria-label="Theme to import"
                placeholder="codex-theme-v1:{…}"
                value={importText}
                onChange={(e) => setImportText(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && importTheme()}
              />
              <Button icon={<Download size={15} />} disabled={!importText} onClick={importTheme}>
                Import
              </Button>
            </span>
          </div>
          <div className="row" style={{ justifyContent: 'flex-end' }}>
            <Button
              kind="ghost"
              icon={<RotateCcw size={15} />}
              onClick={() => update(DEFAULT_APPEARANCE)}
            >
              Reset appearance
            </Button>
          </div>
        </div>
      </details>
    </>
  );
}

function VariantEditor({
  variant,
  a,
  onChange,
  onCopy,
}: {
  variant: ThemeVariant;
  a: AppearanceSettings;
  onChange: (a: AppearanceSettings) => void;
  onCopy: () => void;
}) {
  const t = a[variant];
  const colors = resolveColors(a, variant);
  const presets = presetsFor(variant);
  const overridden = t.accent || t.background || t.foreground;
  const name = variant === 'light' ? 'Light theme' : 'Dark theme';
  return (
    <div className="theme-card">
      <div
        className="theme-preview"
        style={{ background: colors.background, color: colors.foreground }}
        aria-hidden
      >
        <span className="theme-preview-dot" style={{ background: colors.accent }} />
        <span>Aa</span>
        <span className="theme-preview-bar" style={{ background: colors.accent }} />
      </div>
      <div className="row spread">
        <strong>{name}</strong>
        <select
          className="field"
          aria-label={name}
          value={presets.some((p) => p.id === t.preset) ? t.preset : 'default'}
          onChange={(e) => onChange({ ...a, [variant]: { preset: e.target.value } })}
        >
          {presets.map((p) => (
            <option key={p.id} value={p.id}>
              {p.name}
            </option>
          ))}
        </select>
      </div>
      {COLOR_FIELDS.map(({ key, label }) => (
        <ColorField
          key={key}
          label={label}
          value={colors[key]}
          changed={!!t[key]}
          onChange={(hex) => onChange({ ...a, [variant]: { ...t, [key]: hex } })}
        />
      ))}
      <div className="row spread">
        <Button kind="ghost" size="sm" icon={<ClipboardCopy size={14} />} onClick={onCopy}>
          Copy theme
        </Button>
        {overridden && (
          <Button
            kind="ghost"
            size="sm"
            onClick={() => onChange({ ...a, [variant]: { preset: t.preset } })}
          >
            Use the theme’s colours
          </Button>
        )}
      </div>
    </div>
  );
}

function ColorField({
  label,
  value,
  changed,
  onChange,
}: {
  label: string;
  value: string;
  changed: boolean;
  onChange: (hex: string) => void;
}) {
  const [text, setText] = useState(value.toUpperCase());
  useEffect(() => setText(value.toUpperCase()), [value]);
  return (
    <label className="row spread color-field">
      <span>
        {label}
        {changed && <span className="small muted"> · changed</span>}
      </span>
      <span className="row" style={{ gap: 8 }}>
        <input
          type="color"
          aria-label={`${label} colour`}
          value={value.toLowerCase()}
          onChange={(e) => onChange(e.target.value.toUpperCase())}
        />
        <input
          className="field mono hex-field"
          aria-label={`${label} hex`}
          value={text}
          maxLength={7}
          onChange={(e) => {
            setText(e.target.value);
            if (isHexColor(e.target.value)) onChange(e.target.value.toUpperCase());
          }}
          onBlur={() => setText(value.toUpperCase())}
        />
      </span>
    </label>
  );
}

function FontField({
  label,
  value,
  placeholder,
  onChange,
}: {
  label: string;
  value: string;
  placeholder: string;
  onChange: (v: string) => void;
}) {
  const [text, setText] = useState(value);
  useEffect(() => setText(value), [value]);
  const ok = isFontFamily(text);
  return (
    <label className="row spread">
      <span>{label}</span>
      <input
        className="field font-field"
        aria-label={label}
        aria-invalid={!ok}
        placeholder={placeholder}
        value={text}
        maxLength={120}
        onChange={(e) => setText(e.target.value)}
        onBlur={() => (ok ? onChange(text.trim()) : setText(value))}
        onKeyDown={(e) => e.key === 'Enter' && (e.target as HTMLInputElement).blur()}
      />
    </label>
  );
}
