import { CircleCheck, Download, Power, Settings } from 'lucide-react';
import { useClock, useLive, vigil } from '../api';
import {
  NeedsYouLine,
  needsRows,
  NoticedList,
  pileLine,
  WatchLine,
  WorkingHeadline,
} from '../components/Attention';
import { Shield } from '../components/Shield';
import { Button, Chip, IconButton, LevelPill, SeverityMark } from '../components/ui';
import { timeAgo } from '../format';
import { isNoticed, needsDecision } from '../../../shared/attention';

/** Rows the popover lists before handing over to the app. */
export const POPOVER_ROWS = 5;

/** The menu-bar popover: "it's working", then Needs you, then what Vigil only noticed. */
export function Popover() {
  // It's loaded once and kept, so "2 min ago" must move on while it waits.
  useClock();
  const [status] = useLive(() => vigil.getStatus());
  const [alerts] = useLive(() => vigil.listAlerts('open'));
  const [updates] = useLive(() => vigil.getUpdates());
  const needs = needsRows((alerts ?? []).filter(needsDecision));
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
          {status && (
            <span
              className="row"
              style={{ gap: 6 }}
              title="How the protection layers are running. Alerts never change this."
            >
              <span className="t-small muted">Protection</span>
              <LevelPill level={status.level} small />
            </span>
          )}
        </div>
        {status && status.reasons.length === 0 && <WorkingHeadline needsYou={status.needsYou} />}
        {status && status.needsYou > 0 && <NeedsYouLine count={status.needsYou} />}
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
              <span className="count hot">{status?.needsYou ?? needs.length}</span>
            </div>
            <div className="list">
              {needs.slice(0, POPOVER_ROWS).map((r) => (
                <button key={r.id} type="button" className="list-row" onClick={() => open(r.id)}>
                  <div className="col grow" style={{ gap: 2 }}>
                    <span className="t-h3 ellipsis">{r.title}</span>
                    <span className="row t-small">
                      <SeverityMark severity={r.severity} />
                      {pileLine(r) && <span>· {pileLine(r)}</span>}
                      <span>· {timeAgo(r.at)}</span>
                      {r.blocked && <Chip tone="good">Blocked</Chip>}
                    </span>
                  </div>
                </button>
              ))}
            </div>
            {needs.length > POPOVER_ROWS && (
              <button
                type="button"
                className="btn sm ghost"
                onClick={() => void vigil.openMain('alerts')}
              >
                See all {status?.needsYou ?? needs.length} in Vigil
              </button>
            )}
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

        {status && (
          <NoticedList
            alerts={noticed}
            total={status.noticed}
            view={status.alertView}
            open={open}
            limit={5}
          />
        )}
      </div>

      <footer className="row">
        <Button kind="primary" className="grow" onClick={() => void vigil.openMain('home')}>
          Open Vigil
        </Button>
        {updates?.available && (
          <Button
            className="update-pill"
            icon={<Download size={14} />}
            title={`Download Vigil at Home ${updates.available.version}`}
            onClick={() => void vigil.downloadUpdate()}
          >
            Update
          </Button>
        )}
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
