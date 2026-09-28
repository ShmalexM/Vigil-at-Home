import { StrictMode, useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import type { ThemePref } from '../../shared/ipc';
import {
  DEFAULT_APPEARANCE,
  DEFAULT_UI_FONT_SIZE,
  resolveColors,
  themeTokens,
  type AppearanceSettings,
} from '../../shared/themes';
import { vigil } from './api';
import { Toaster } from './components/Toasts';
import './styles/app.css';
import './styles/layout.css';
import { AppShell } from './views/AppShell';
import { Popover } from './views/Popover';
import { Popup } from './views/Popup';

const route = location.hash.slice(1) || 'home';
const [surface, param] = route.split('/');

function useTheme() {
  const [pref, setPref] = useState<ThemePref>('system');
  const [appearance, setAppearance] = useState<AppearanceSettings>(DEFAULT_APPEARANCE);
  const [systemDark, setSystemDark] = useState(matchMedia('(prefers-color-scheme: dark)').matches);
  useEffect(() => {
    const load = () =>
      void vigil.getSettings().then((s) => {
        setPref(s.theme);
        setAppearance(s.appearance);
      });
    load();
    const mq = matchMedia('(prefers-color-scheme: dark)');
    const onChange = () => setSystemDark(mq.matches);
    mq.addEventListener('change', onChange);
    // Sent when the theme or any appearance setting changes.
    const off = vigil.on('theme', load);
    return () => {
      mq.removeEventListener('change', onChange);
      off();
    };
  }, []);
  const dark = pref === 'dark' || (pref === 'system' && systemDark);
  useEffect(() => {
    const root = document.documentElement;
    const variant = dark ? 'dark' : 'light';
    root.className = `theme-${variant}`;
    const tokens = themeTokens(resolveColors(appearance, variant), variant, appearance.contrast);
    for (const [name, value] of Object.entries(tokens)) root.style.setProperty(name, value);
    const font = (name: string, family: string) =>
      family ? root.style.setProperty(name, family) : root.style.removeProperty(name);
    font('--font-sans', appearance.uiFont && `${appearance.uiFont}, system-ui, sans-serif`);
    font('--font-mono', appearance.codeFont && `${appearance.codeFont}, ui-monospace, monospace`);
    // Text size scales the main window only; the popover and popup keep their fitted sizes.
    if (surface !== 'popup' && surface !== 'popover') {
      root.style.zoom = String(appearance.uiFontSize / DEFAULT_UI_FONT_SIZE);
    }
  }, [dark, appearance]);
}

function Root() {
  useTheme();
  if (surface === 'popup' && param) {
    document.body.classList.add('transparent');
    return <Popup initialId={param} />;
  }
  if (surface === 'popover') return <Popover />;
  return (
    <Toaster>
      <AppShell initialRoute={route} />
    </Toaster>
  );
}

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <Root />
  </StrictMode>,
);
