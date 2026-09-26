import { StrictMode, useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import type { ThemePref } from '../../shared/ipc';
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
  const [systemDark, setSystemDark] = useState(matchMedia('(prefers-color-scheme: dark)').matches);
  useEffect(() => {
    void vigil.getSettings().then((s) => setPref(s.theme));
    const mq = matchMedia('(prefers-color-scheme: dark)');
    const onChange = () => setSystemDark(mq.matches);
    mq.addEventListener('change', onChange);
    const off = vigil.on('theme', setPref);
    return () => {
      mq.removeEventListener('change', onChange);
      off();
    };
  }, []);
  const dark = pref === 'dark' || (pref === 'system' && systemDark);
  useEffect(() => {
    document.documentElement.className = dark ? 'theme-dark' : 'theme-light';
  }, [dark]);
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
