import { Activity, Bell, House, ListChecks, Settings as SettingsIcon } from 'lucide-react';
import { useEffect, useState, type ReactNode } from 'react';
import { useLive, vigil } from '../api';
import { Shield } from '../components/Shield';
import { LevelPill } from '../components/ui';
import { ActivityView } from './Activity';
import { AlertsView } from './Alerts';
import { HomeView } from './Home';
import { RulesView } from './Rules';
import { SettingsView } from './Settings';

const NAV: { id: string; label: string; icon: ReactNode }[] = [
  { id: 'home', label: 'Home', icon: <House size={16} /> },
  { id: 'alerts', label: 'Alerts', icon: <Bell size={16} /> },
  { id: 'rules', label: 'Rules', icon: <ListChecks size={16} /> },
  { id: 'activity', label: 'Activity', icon: <Activity size={16} /> },
  { id: 'settings', label: 'Settings', icon: <SettingsIcon size={16} /> },
];

export function AppShell({ initialRoute }: { initialRoute: string }) {
  const [route, setRoute] = useState(initialRoute);
  useEffect(() => vigil.on('navigate', setRoute), []);
  useEffect(() => {
    const onHash = () => setRoute(location.hash.slice(1) || 'home');
    window.addEventListener('hashchange', onHash);
    return () => window.removeEventListener('hashchange', onHash);
  }, []);
  const go = (r: string) => {
    location.hash = r;
    setRoute(r);
  };

  const [status] = useLive(() => vigil.getStatus());
  const [section = 'home', param] = route.split('/');

  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="drag" />
        <div className="row brand">
          <Shield height={22} />
          <span className="t-h3">Vigil at Home</span>
        </div>
        <nav className="col" style={{ gap: 2 }}>
          {NAV.map((n) => (
            <button
              key={n.id}
              type="button"
              className="nav-item"
              aria-current={section === n.id ? 'page' : undefined}
              onClick={() => go(n.id)}
            >
              {n.icon}
              <span className="grow">{n.label}</span>
              {n.id === 'alerts' && status && status.needsYou > 0 && (
                <span className="count hot">{status.needsYou}</span>
              )}
            </button>
          ))}
        </nav>
        <div className="grow" />
        {status && (
          <button type="button" className="sidebar-status" onClick={() => go('home')}>
            <LevelPill level={status.level} small />
            <span className="t-small ellipsis">{status.reasons[0] ?? 'All quiet'}</span>
          </button>
        )}
      </aside>
      <main className="content scroll">
        <div className="drag" />
        {section === 'home' && <HomeView go={go} />}
        {section === 'alerts' && <AlertsView selected={param} go={go} />}
        {section === 'rules' && <RulesView />}
        {section === 'activity' && <ActivityView />}
        {section === 'settings' && <SettingsView />}
      </main>
    </div>
  );
}

export function PageHead({
  title,
  purpose,
  right,
}: {
  title: string;
  purpose: string;
  right?: ReactNode;
}) {
  return (
    <div className="row spread page-head">
      <div className="col" style={{ gap: 5 }}>
        <h1 className="t-title">{title}</h1>
        <span style={{ maxWidth: 720 }}>{purpose}</span>
      </div>
      {right && <div className="row">{right}</div>}
    </div>
  );
}
