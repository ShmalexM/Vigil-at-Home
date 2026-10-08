import { Sparkles, X } from 'lucide-react';
import { useEffect, useRef, useState } from 'react';
import { useLive, vigil } from '../api';
import { DecisionControls } from '../components/Decision';
import { Shield } from '../components/Shield';
import { Button, Chip, IconButton, SeverityMark, StatusMark } from '../components/ui';
import { describeAction, headline, timeAgo } from '../format';
import { isSimulated, othersNeedingYou, provenance, responseProvenance } from '../decision';

/**
 * The always-on-top detection popup. It appears without taking focus, says
 * what happened and what Vigil already did, and asks for one decision.
 */
export function Popup({ initialId }: { initialId: string }) {
  const [id, setId] = useState(initialId);
  useEffect(() => vigil.on('popup', setId), []);
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && void vigil.closePopup();
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  const card = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const el = card.current;
    if (!el) return;
    const fit = () => void vigil.fitPopup(Math.ceil(el.getBoundingClientRect().height) + 20);
    const ro = new ResizeObserver(fit);
    ro.observe(el);
    return () => ro.disconnect();
  });

  const [detail] = useLive(() => vigil.getAlertDetail(id), id);
  const [status] = useLive(() => vigil.getStatus());
  const [open] = useLive(() => vigil.listAlerts('open'));

  if (!detail) return null;
  const { alert, actions, proposals } = detail;
  const pending = proposals.filter((p) => p.status === 'pending');
  const contained = alert.containment === 'active';
  // The same count as Needs you everywhere else: decisions only, a pile once.
  const others = othersNeedingYou(alert, status?.needsYou ?? 0, open ?? []);
  // Worded from what every action really did, not whether the helper is connected now.
  const response = contained ? responseProvenance(actions) : undefined;
  const shown = actions.filter((r) => !r.undoes);
  const allSimulated = shown.length > 0 && shown.every(isSimulated);
  const decided = !!alert.decision;

  return (
    <div
      ref={card}
      className={`popup ${contained ? 'contained' : 'needs'}`}
      role="alertdialog"
      aria-labelledby="popup-title"
    >
      <div className="row spread">
        <div className="row">
          <Shield height={20} />
          <span className="t-h3">{headline(alert, response)}</span>
          <span className="t-small">· {timeAgo(alert.createdAt)}</span>
        </div>
        <IconButton
          label="Hide (stays in Needs you)"
          size="sm"
          onClick={() => void vigil.closePopup()}
        >
          <X size={15} />
        </IconButton>
      </div>

      <div className="col" style={{ gap: 6 }}>
        <div className="row">
          <SeverityMark severity={alert.severity} />
          {response === 'simulated' && (
            <Chip
              tone="fair"
              title="The Vigil helper wasn’t connected when this ran, so nothing was actually changed"
            >
              Simulated
            </Chip>
          )}
          {response === 'mixed' && (
            <Chip tone="fair" title="Some of this ran while the Vigil helper wasn’t connected">
              Partly simulated
            </Chip>
          )}
          {response === 'unknown' && (
            <Chip
              tone="fair"
              title="An older Vigil recorded this without noting whether the helper was connected"
            >
              May be simulated
            </Chip>
          )}
        </div>
        <h1 id="popup-title" className="t-h2">
          {alert.title}
        </h1>
        <p className="t-small clamp-3" style={{ margin: 0 }}>
          {alert.summary}
        </p>
        {alert.subject?.path && <div className="subject mono">{alert.subject.path}</div>}
      </div>

      {(actions.length > 0 || pending.length > 0) && (
        <div className="col" style={{ gap: 6 }}>
          <span className="t-label">
            {actions.length === 0
              ? 'Vigil suggests'
              : allSimulated
                ? 'What Vigil would have done'
                : 'What Vigil did'}
          </span>
          {shown.map((r) => (
            <div key={r.id} className="row">
              <StatusMark
                state={
                  r.status === 'done'
                    ? provenance(r) !== 'real'
                      ? 'warn'
                      : 'done'
                    : r.status === 'pending'
                      ? 'running'
                      : r.status === 'undone'
                        ? 'warn'
                        : 'failed'
                }
                label={
                  r.status !== 'done'
                    ? r.status
                    : { real: r.status, simulated: 'Simulated', unknown: 'Maybe simulated' }[
                        provenance(r)
                      ]
                }
              />
              <span className="grow ellipsis">
                {describeAction(r.action)}
                {isSimulated(r) && !allSimulated && <span className="muted"> (simulated)</span>}
              </span>
            </div>
          ))}
          {actions.length === 0 &&
            pending.map((p) => (
              <div key={p.id} className="row">
                <StatusMark state="pending" label="Suggested" />
                <span className="grow ellipsis">{describeAction(p.action)}</span>
              </div>
            ))}
        </div>
      )}

      {alert.ai && (
        <div className="ai-note">
          <Sparkles size={14} aria-hidden />
          <div className="col" style={{ gap: 2 }}>
            <span className="t-label" style={{ color: 'var(--ai)' }}>
              AI opinion · may be wrong
            </span>
            <span className="t-small" style={{ color: 'var(--tx1)' }}>
              {alert.ai.summary}
            </span>
          </div>
        </div>
      )}

      {decided ? (
        <div className="popup-actions">
          <Button kind="primary" full onClick={() => void vigil.closePopup()}>
            Done
          </Button>
        </div>
      ) : (
        <DecisionControls
          alert={alert}
          actions={actions}
          proposals={proposals}
          full
          onDecided={() => void vigil.closePopup()}
        />
      )}
      <Button kind="ghost" size="sm" onClick={() => void vigil.openMain(`alerts/${alert.id}`)}>
        Details
      </Button>

      {others > 0 && (
        <button type="button" className="more-link" onClick={() => void vigil.openMain('alerts')}>
          {others} more {others === 1 ? 'needs' : 'need'} you
        </button>
      )}
    </div>
  );
}
