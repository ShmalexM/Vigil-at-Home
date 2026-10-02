import { CircleCheck, Power, Settings } from 'lucide-react';
import { useLive, vigil } from '../api';
import { NoticedList, WatchLine, WorkingHeadline } from '../components/Attention';
import { Shield } from '../components/Shield';
import { Button, Chip, IconButton, LevelPill, SeverityMark } from '../components/ui';
import { timeAgo } from '../format';
import { isNoticed, needsDecision } from '../../../shared/attention';

/** The menu-bar popover: "it's working", then Needs you, then what Vigil only noticed. */
export function Popover() {
  const [status] = useLive(() => vigil.getStatus());
  const [alerts] = useLive(() => vigil.listAlerts('open'));
  const needs = (alerts ?? []).filter(needsDecision);
  const noticed = (alerts ?? []).filter(isNoticed);
  const open = (id: string) => void vigil.openMain(`alerts/${id}`);

  return (
    <div className="popover">
      <header className="col" style={{ gap: 6 }}>
        <div className="row spread">
          <div className="row">
            <Shield height={20} />
            <span className="t-h3">Vigil at Home</span>
          </div>
          {status && <LevelPill level={status.level} small />}
        </div>
        {status && status.reasons.length === 0 && <WorkingHeadline />}
        {status && status.reasons.length > 0 && (
          <span className="t-small">{status.reasons.slice(0, 2).join(' · ')}</span>
        )}
        {status && <WatchLine watch={status.watch} />}
        {status?.dryRun && (
          <span className="t-small" style={{ color: 'var(--fair)' }}>
            Blocks are simulated until the Vigil helper is installed.
          </span>
        )}
      </header>

      <div className="col scroll grow" style={{ gap: 14 }}>
        {needs.length > 0 && (
          <section className="col" style={{ gap: 6 }}>
            <div className="row spread">
              <span className="t-label">Needs you</span>
              <span className="count hot">{needs.length}</span>
            </div>
            <div className="list">
              {needs.map((a) => (
                <button key={a.id} type="button" className="list-row" onClick={() => open(a.id)}>
                  <div className="col grow" style={{ gap: 2 }}>
                    <span className="t-h3 ellipsis">{a.title}</span>
                    <span className="row t-small">
                      <SeverityMark severity={a.severity} />
                      <span>· {timeAgo(a.createdAt)}</span>
                      {a.containment === 'active' && <Chip tone="good">Blocked</Chip>}
                    </span>
                  </div>
                </button>
              ))}
            </div>
          </section>
        )}

        {needs.length === 0 && noticed.length === 0 && (
          <div className="empty" style={{ border: 0 }}>
            <span className="empty-icon">
              <CircleCheck size={20} />
            </span>
            <span className="t-small">Vigil will pop up if something needs a decision.</span>
          </div>
        )}

        {status && <NoticedList alerts={noticed} view={status.alertView} open={open} />}
      </div>

      <footer className="row">
        <Button kind="primary" className="grow" onClick={() => void vigil.openMain('home')}>
          Open Vigil
        </Button>
        <IconButton label="Settings" onClick={() => void vigil.openMain('settings')}>
          <Settings size={16} />
        </IconButton>
        <IconButton label="Quit Vigil" onClick={() => void vigil.quit()}>
          <Power size={16} />
        </IconButton>
      </footer>
    </div>
  );
}
