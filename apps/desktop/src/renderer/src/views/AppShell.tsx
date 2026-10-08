import {
  Activity,
  Bell,
  Bot,
  ChartSpline,
  ChevronRight,
  Dog as DogIcon,
  Download,
  History as HistoryIcon,
  House,
  ListChecks,
  Settings as SettingsIcon,
  SlidersHorizontal,
  Wrench,
} from 'lucide-react';
import { useEffect, useState, type ReactNode } from 'react';
import { LEVEL_RULES } from '../../../shared/levels';
import { useLive, vigil } from '../api';
import { AskScout } from '../components/AskScout';
import { Shield } from '../components/Shield';
import { Button, IconButton, LevelPill } from '../components/ui';
import { ActivityView } from './Activity';
import { AgentsView } from './Agents';
import { AlertsView } from './Alerts';
import { HistoryView } from './History';
import { HomeView } from './Home';
import { isTyping, navKey, navKeys, navShortcut } from './nav-keys';
import { PackPage } from './Pack';
import { SetupWizard } from './onboarding/SetupWizard';
import { RulesView } from './Rules';
import { SettingsView } from './Settings';
import { UsageView } from './Usage';

type NavItem = { id: string; label: string; icon: ReactNode };

/** What everyone needs day to day. */
const NAV: NavItem[] = [
  { id: 'home', label: 'Home', icon: <House size={16} /> },
  { id: 'history', label: 'History', icon: <HistoryIcon size={16} /> },
  { id: 'settings', label: 'Settings', icon: <SettingsIcon size={16} /> },
];

/**
 * The detail behind what Vigil does: a collapsible Advanced group in the sidebar,
 * always reachable by route too (popups link to alerts).
 */
export const ADVANCED_NAV: NavItem[] = [
  { id: 'alerts', label: 'Alerts', icon: <Bell size={16} /> },
  { id: 'rules', label: 'Rules', icon: <ListChecks size={16} /> },
  { id: 'agents', label: 'Agents', icon: <Bot size={16} /> },
  { id: 'pack', label: 'Pack', icon: <DogIcon size={16} /> },
  { id: 'activity', label: 'Activity', icon: <Activity size={16} /> },
  { id: 'usage', label: 'Usage', icon: <ChartSpline size={16} /> },
];

/** ⌘1…⌘9 follow the sidebar's own order. */
const NAV_KEYS = navKeys([...NAV, ...ADVANCED_NAV].map((n) => n.id));

export function AppShell({ initialRoute }: { initialRoute: string }) {
  const [route, setRoute] = useState(initialRoute);
  // Keep the hash in step with pushed navigation, so the window's URL always names its page.
  useEffect(
    () =>
      vigil.on('navigate', (r) => {
        location.hash = r;
        setRoute(r);
      }),
    [],
  );
  useEffect(() => {
    const onHash = () => setRoute(location.hash.slice(1) || 'home');
    window.addEventListener('hashchange', onHash);
    return () => window.removeEventListener('hashchange', onHash);
  }, []);
  const go = (r: string) => {
    location.hash = r;
    setRoute(r);
  };
  // ⌘1…⌘9 in sidebar order and ⌘, (Ctrl elsewhere) move between pages without the mouse.
  useEffect(() => {
    const mac = navigator.platform.toLowerCase().includes('mac');
    const onKey = (e: KeyboardEvent) => {
      const r = navKey(e, NAV_KEYS, mac, isTyping(e.target));
      if (!r) return;
      e.preventDefault();
      location.hash = r;
      setRoute(r);
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  const [status] = useLive(() => vigil.getStatus());
  const [setup] = useLive(() => vigil.getSetup());
  const [updates] = useLive(() => vigil.getUpdates());
  const [settings] = useLive(() => vigil.getSettings());
  // Names and statuses only: the badge needs no stats, and this runs on every page.
  const [agents] = useLive(() => vigil.listAgentNames());
  const suggestions = agents?.filter((a) => a.status === 'suggested').length ?? 0;
  const [section = 'home', param] = route.split('/');
  const onAdvanced = ADVANCED_NAV.some((n) => n.id === section);
  // The Advanced group starts closed and remembers how it was left. Landing on one
  // of its pages opens it for this window without changing what's remembered.
  const [advancedOpen, setAdvancedOpen] = useState<boolean | undefined>(undefined);
  const savedOpen = settings?.showAdvanced;
  useEffect(() => {
    if (savedOpen !== undefined) setAdvancedOpen((open) => open ?? savedOpen);
  }, [savedOpen]);
  // Every arrival on an Advanced page (a link, a shortcut) opens the group, so
  // the current page always shows in the sidebar.
  useEffect(() => {
    if (onAdvanced) setAdvancedOpen(true);
  }, [onAdvanced, section]);
  const showAdvanced = advancedOpen ?? onAdvanced;
  const toggleAdvanced = () => {
    const open = !showAdvanced;
    setAdvancedOpen(open);
    void vigil.setShowAdvanced(open);
  };

  if (section === 'setup') return <SetupWizard onDone={() => go('home')} />;

  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="drag" />
        <div className="row brand">
          <Shield height={22} />
          <span className="t-h3">Vigil at Home</span>
          {/* After Later, a quiet reminder here takes over from the banner. */}
          {updates?.available && updates.dismissed && (
            <IconButton
              size="sm"
              className="btn icon-btn sm update-pill"
              label={`Download Vigil at Home ${updates.available.version}`}
              onClick={() => void vigil.downloadUpdate()}
            >
              <Download size={15} />
            </IconButton>
          )}
        </div>
        <nav className="col" style={{ gap: 2 }}>
          {NAV.map((n) => (
            <NavButton
              key={n.id}
              item={n}
              current={section === n.id}
              badge={n.id === 'home' ? status?.badge : undefined}
              onClick={() => go(n.id)}
            />
          ))}
          <button
            type="button"
            className="nav-item nav-group"
            aria-expanded={showAdvanced}
            aria-controls="nav-advanced"
            onClick={toggleAdvanced}
          >
            <SlidersHorizontal size={16} />
            <span className="grow">Advanced</span>
            {!showAdvanced && suggestions > 0 && (
              <span className="count" title="Suggested agents waiting on you">
                {suggestions}
              </span>
            )}
            <ChevronRight size={14} className="nav-chevron" />
          </button>
          {showAdvanced && (
            <div id="nav-advanced" className="col nav-sub" role="group" aria-label="Advanced">
              {ADVANCED_NAV.map((n) => (
                <NavButton
                  key={n.id}
                  item={n}
                  current={section === n.id}
                  {...(n.id === 'agents'
                    ? {
                        badge: suggestions,
                        calm: true,
                        badgeTitle: 'Suggested agents waiting on you',
                      }
                    : {})}
                  onClick={() => go(n.id)}
                />
              ))}
            </div>
          )}
        </nav>
        <div className="grow" />
        {status && (
          <button
            type="button"
            className="sidebar-status"
            onClick={() => go('home')}
            title={[LEVEL_RULES[status.level], '', ...status.reasons].join('\n')}
          >
            <span className="row spread" style={{ width: '100%' }}>
              <span className="t-small muted">Protection</span>
              <LevelPill level={status.level} small />
            </span>
            {(status.reasons.length > 0 || status.needsYou === 0) && (
              <span className="t-small sidebar-status-why">
                {status.reasons[0] ?? 'Nothing needs you'}
              </span>
            )}
            {status.reasons.length > 1 && (
              <span className="t-small muted">and {status.reasons.length - 1} more · see Home</span>
            )}
            {status.needsYou > 0 && (
              <span className="t-small sidebar-status-why">
                {status.needsYou} {status.needsYou === 1 ? 'thing needs' : 'things need'} you
              </span>
            )}
          </button>
        )}
      </aside>
      <main className="content scroll">
        <div className="drag" />
        {setup && !setup.finished && (
          <div className="attn accent setup-banner">
            <Wrench size={16} />
            <span className="grow">Setup isn’t finished, so some protection is missing.</span>
            <Button size="sm" kind="primary" onClick={() => go('setup')}>
              Continue setup
            </Button>
          </div>
        )}
        {updates?.available && !updates.dismissed && (
          <div className="attn accent setup-banner">
            <Download size={16} />
            <span className="grow">
              Vigil at Home {updates.available.version} is available. You have {updates.current}.
            </span>
            <Button size="sm" kind="ghost" onClick={() => void vigil.dismissUpdate()}>
              Later
            </Button>
            <Button size="sm" kind="ghost" onClick={() => void vigil.openUpdateNotes()}>
              What’s new
            </Button>
            <Button size="sm" kind="primary" onClick={() => void vigil.downloadUpdate()}>
              {updates.available.downloadUrl ? 'Download' : 'Get it on GitHub'}
            </Button>
          </div>
        )}
        {section === 'home' && <HomeView go={go} />}
        {section === 'history' && <HistoryView go={go} />}
        {section === 'alerts' && <AlertsView selected={param} go={go} />}
        {section === 'rules' && <RulesView selected={param} go={go} />}
        {section === 'agents' && <AgentsView selected={param} go={go} />}
        {section === 'pack' && <PackPage />}
        {section === 'activity' && <ActivityView selected={param} go={go} />}
        {section === 'usage' && <UsageView />}
        {section === 'settings' && <SettingsView go={go} />}
        <AskScout page={section} selected={param} go={go} />
      </main>
    </div>
  );
}

function NavButton({
  item,
  current,
  badge,
  calm,
  badgeTitle,
  onClick,
}: {
  item: NavItem;
  current: boolean;
  badge?: number | undefined;
  /** A count that waits on the user but isn't urgent. */
  calm?: boolean;
  badgeTitle?: string;
  onClick: () => void;
}) {
  const shortcut = navShortcut(item.id, NAV_KEYS);
  return (
    <button
      type="button"
      className="nav-item"
      aria-current={current ? 'page' : undefined}
      aria-keyshortcuts={shortcut?.aria}
      title={shortcut ? `${item.label} (${shortcut.label})` : undefined}
      onClick={onClick}
    >
      {item.icon}
      <span className="grow">{item.label}</span>
      {!!badge && (
        <span className={calm ? 'count' : 'count hot'} title={badgeTitle}>
          {badge}
        </span>
      )}
    </button>
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
