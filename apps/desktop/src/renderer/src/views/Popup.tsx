import { ShieldAlert, ShieldCheck, Sparkles, X } from 'lucide-react';
import { useEffect, useRef, useState } from 'react';
import { useLive, vigil } from '../api';
import { HoldButton } from '../components/HoldButton';
import { Shield } from '../components/Shield';
import { Button, Chip, IconButton, SeverityMark, StatusMark } from '../components/ui';
import { describeAction, headline, releaseFailed, timeAgo } from '../format';

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
  const [failure, setFailure] = useState<{ id: string; text: string }>();

  if (!detail) return null;
  const { alert, actions, proposals } = detail;
  const pending = proposals.filter((p) => p.status === 'pending');
  const others = (open ?? []).filter((a) => a.id !== alert.id && !a.decision).length;
  const contained = alert.containment === 'active';
  const decided = !!alert.decision;

  const decide = async (verdict: 'malicious' | 'benign' | 'expected', release: boolean) => {
    const out = await vigil.decide(alert.id, { verdict, release });
    if (release && !out.decision) {
      setFailure({ id: alert.id, text: releaseFailed(out) });
      return;
    }
    await vigil.closePopup();
  };
  const blockIt = async () => {
    for (const p of pending) await vigil.approveProposal(p.id);
    await decide('malicious', false);
  };

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
          <span className="t-h3">{headline(alert)}</span>
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
          {status?.dryRun && contained && (
            <Chip
              tone="fair"
              title="The Vigil helper is not installed, so nothing was actually changed"
            >
              Simulated
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
            {actions.length > 0 ? 'What Vigil did' : 'Vigil suggests'}
          </span>
          {actions
            .filter((r) => !r.undoes)
            .map((r) => (
              <div key={r.id} className="row">
                <StatusMark
                  state={
                    r.status === 'done'
                      ? 'done'
                      : r.status === 'pending'
                        ? 'running'
                        : r.status === 'undone'
                          ? 'warn'
                          : 'failed'
                  }
                  label={r.status}
                />
                <span className="grow ellipsis">{describeAction(r.action)}</span>
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

      {failure?.id === alert.id && (
        <p role="alert" className="t-small" style={{ margin: 0, color: 'var(--poor)' }}>
          {failure.text}
        </p>
      )}

      <div className="popup-actions">
        {decided ? (
          <Button kind="primary" full onClick={() => void vigil.closePopup()}>
            Done
          </Button>
        ) : contained ? (
          <>
            <Button
              kind="primary"
              icon={<ShieldCheck size={15} />}
              onClick={() => void decide('malicious', false)}
            >
              Keep blocked
            </Button>
            <HoldButton
              label="Allow"
              doneLabel="Allowed"
              onConfirm={() => void decide('benign', true)}
            />
          </>
        ) : pending.length > 0 ? (
          <>
            <Button kind="primary" icon={<ShieldAlert size={15} />} onClick={() => void blockIt()}>
              Block it
            </Button>
            <Button kind="outline" onClick={() => void decide('benign', false)}>
              It's fine
            </Button>
          </>
        ) : (
          <Button kind="primary" onClick={() => void decide('expected', false)}>
            Got it
          </Button>
        )}
        <Button kind="ghost" onClick={() => void vigil.openMain(`alerts/${alert.id}`)}>
          Details
        </Button>
      </div>

      {others > 0 && (
        <button type="button" className="more-link" onClick={() => void vigil.openMain('alerts')}>
          {others} more {others === 1 ? 'needs' : 'need'} you
        </button>
      )}
    </div>
  );
}
