import type { Alert } from '@vigil/core';
import { CircleCheck, Eye } from 'lucide-react';
import { useState } from 'react';
import { vigil } from '../api';
import { seenTimes, timeAgo } from '../format';
import type { AlertView, WatchSummary } from '../../../shared/ipc';
import { Segmented } from './ui';

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

/** The Show me less / Show me more switch, for Settings. */
export function AlertViewSwitch({ value }: { value: AlertView }) {
  return (
    <Segmented
      label="How much to show"
      value={value}
      options={[
        { value: 'less', label: 'Show me less' },
        { value: 'more', label: 'Show me more' },
      ]}
      onChange={(v) => void vigil.setAlertView(v)}
    />
  );
}

/**
 * Alerts Vigil only noticed, framed as "was this you?" with one tap to clear
 * them all. With Show me less they fold into one line; with Show me more each
 * one is listed with its command. Clearing never touches anything that needs
 * a decision; the main process checks that again.
 */
export function NoticedList({
  alerts,
  view,
  open,
  limit,
}: {
  alerts: readonly Alert[];
  view: AlertView;
  open: (id: string) => void;
  limit?: number;
}) {
  const [busy, setBusy] = useState(false);
  if (alerts.length === 0) return null;
  const more = view === 'more';
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
        <span className="row" style={{ gap: 2 }}>
          <button
            type="button"
            className="btn sm ghost"
            onClick={() => void vigil.setAlertView(more ? 'less' : 'more')}
          >
            {more ? 'Show me less' : 'Show me more'}
          </button>
          <button
            type="button"
            className="btn sm ghost"
            disabled={busy}
            title="Marks these as expected. Rules and blocks stay as they are."
            onClick={() => void clear()}
          >
            {alerts.length === 1 ? 'That was me' : 'Those were me'}
          </button>
        </span>
      </div>
      <span className="t-small">
        {more
          ? 'Usually this is you installing or setting something up. None of these were blocked. Open one if it wasn’t you.'
          : `${alerts.length === 1 ? 'One thing' : `${alerts.length} things`} Vigil noticed, probably you installing or setting something up. Nothing was blocked.`}
      </span>
      {more && (
        <div className="list">
          {shown.map((a) => (
            <button key={a.id} type="button" className="list-row" onClick={() => open(a.id)}>
              <div className="col grow" style={{ gap: 2, minWidth: 0 }}>
                <span className="row spread" style={{ gap: 8 }}>
                  <span className="ellipsis">{a.title}</span>
                  <span className="t-small nowrap">{seenTimes(a) ?? timeAgo(a.createdAt)}</span>
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
      )}
    </section>
  );
}
