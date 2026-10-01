import type { Alert } from '@vigil/core';
import { CircleCheck, Eye } from 'lucide-react';
import { useState } from 'react';
import { vigil } from '../api';
import { timeAgo } from '../format';
import type { WatchSummary } from '../../../shared/ipc';

/** "Vigil is working": proof it is running, in one line. */
export function WatchLine({ watch }: { watch: WatchSummary }) {
  const parts = [
    `Checked ${watch.checkedToday.toLocaleString()} ${watch.checkedToday === 1 ? 'thing' : 'things'} today`,
    watch.lastEventAt ? `latest ${timeAgo(watch.lastEventAt)}` : 'waiting for the first event',
    watch.blockedToday === 0 ? 'nothing blocked' : `${watch.blockedToday} blocked`,
  ];
  return <span className="t-small watch-line">{parts.join(' · ')}</span>;
}

/** The headline when nothing needs the user. */
export function WorkingHeadline() {
  return (
    <span className="row working">
      <CircleCheck size={16} />
      <span className="t-h3">Vigil is working</span>
    </span>
  );
}

/**
 * Alerts Vigil only noticed: shown so nothing is hidden, but framed as "was
 * this you?" with one tap to clear them all. Clearing never touches anything
 * that needs a decision; the main process checks that again.
 */
export function NoticedList({
  alerts,
  open,
  limit,
}: {
  alerts: readonly Alert[];
  open: (id: string) => void;
  limit?: number;
}) {
  const [busy, setBusy] = useState(false);
  if (alerts.length === 0) return null;
  const shown = limit ? alerts.slice(0, limit) : alerts;
  const clear = async () => {
    setBusy(true);
    try {
      await vigil.clearNoticed(alerts.map((a) => a.id));
    } finally {
      setBusy(false);
    }
  };
  return (
    <section className="col noticed" style={{ gap: 6 }}>
      <div className="row spread">
        <span className="row" style={{ gap: 6 }}>
          <Eye size={14} />
          <span className="t-label">Noticed</span>
          <span className="count">{alerts.length}</span>
        </span>
        <button
          type="button"
          className="btn sm ghost"
          disabled={busy}
          title="Marks these as expected. Rules and blocks stay as they are."
          onClick={() => void clear()}
        >
          {alerts.length === 1 ? 'That was me' : 'Those were me'}
        </button>
      </div>
      <span className="t-small">
        Usually this is you installing or setting something up. None of these were blocked. Open one
        if it wasn’t you.
      </span>
      <div className="list">
        {shown.map((a) => (
          <button key={a.id} type="button" className="list-row" onClick={() => open(a.id)}>
            <div className="col grow" style={{ gap: 2, minWidth: 0 }}>
              <span className="row spread" style={{ gap: 8 }}>
                <span className="ellipsis">{a.title}</span>
                <span className="t-small nowrap">{timeAgo(a.createdAt)}</span>
              </span>
              <span className="t-small clamp-2" title={a.summary}>
                {a.summary}
              </span>
            </div>
          </button>
        ))}
        {shown.length < alerts.length && (
          <span className="t-small" style={{ padding: '4px 12px' }}>
            and {alerts.length - shown.length} more
          </span>
        )}
      </div>
    </section>
  );
}
