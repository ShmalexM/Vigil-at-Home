import type { Alert } from '@vigil/core';
import { CircleCheck, Eye } from 'lucide-react';
import { useEffect, useState } from 'react';
import { vigil } from '../api';
import { seenTimes, timeAgo } from '../format';
import type { AlertView, WatchSummary } from '../../../shared/ipc';
import { Segmented } from './ui';
import { pileUp } from '../../../shared/piles';

/** Proof Vigil is running, in one line. */
export function WatchLine({ watch }: { watch: WatchSummary }) {
  const parts = [
    `Checked ${watch.checkedToday.toLocaleString()} ${watch.checkedToday === 1 ? 'thing' : 'things'} today`,
    watch.lastEventAt ? `latest ${timeAgo(watch.lastEventAt)}` : 'waiting for the first event',
    watch.blockedToday === 0 ? 'nothing blocked' : `${watch.blockedToday} blocked`,
  ];
  return <span className="t-small watch-line">{parts.join(' · ')}</span>;
}

/** The popover headline when every protection layer runs, worded like Home's. */
export function WorkingHeadline({ needsYou }: { needsYou: number }) {
  return (
    <span className="row working">
      <CircleCheck size={16} />
      <span className="t-h3">
        {needsYou === 0 ? 'Protection is on. Nothing needs you.' : 'Protection is on.'}
      </span>
    </span>
  );
}

/** Needs you, kept apart from the protection level. */
export function NeedsYouLine({ count }: { count: number }) {
  return (
    <span className="row needs-line">
      <span className="count hot">{count}</span>
      <span className="t-h3">
        {count === 1 ? 'thing needs your decision' : 'things need your decision'}
      </span>
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
  toggle = true,
  total,
}: {
  alerts: readonly Alert[];
  view: AlertView;
  open: (id: string) => void;
  limit?: number;
  /** Show the Show me less / more button. History always lists them, so it hides it. */
  toggle?: boolean;
  /**
   * Every noticed alert (the status count). The lists load only the newest
   * open alerts, so this can be more than `alerts`; the header shows it.
   */
  total?: number | undefined;
}) {
  const [busy, setBusy] = useState(false);
  // When the confirm opened, and how many it offered: only those are cleared.
  const [confirm, setConfirm] = useState<{ at: number; count: number }>();
  const [cleared, setCleared] = useState<number>();
  // The "Marked N as you" note fades after a few seconds.
  useEffect(() => {
    if (cleared === undefined) return;
    const t = setTimeout(() => setCleared(undefined), 6000);
    return () => clearTimeout(t);
  }, [cleared]);
  if (alerts.length === 0) return null;
  const more = view === 'more';
  const shown = limit ? alerts.slice(0, limit) : alerts;
  const count = Math.max(total ?? 0, alerts.length);
  const confirming = confirm !== undefined;
  const ask = () => {
    setCleared(undefined);
    setConfirm({ at: Date.now(), count });
  };
  const clear = async () => {
    if (!confirm) return;
    setBusy(true);
    try {
      setCleared(await vigil.clearNoticedUpTo(confirm.at));
    } finally {
      setBusy(false);
      setConfirm(undefined);
    }
  };
  const offered = confirm?.count ?? count;
  const these = offered === 1 ? 'this one' : `all ${offered}`;
  return (
    <section className="col noticed" style={{ gap: 6 }}>
      <div className="row spread">
        <span className="row" style={{ gap: 6 }}>
          <Eye size={14} />
          <span className="t-label">Noticed</span>
          <span className="count">{count}</span>
        </span>
        <span className="row" style={{ gap: 2 }}>
          {toggle && (
            <button
              type="button"
              className="btn sm ghost"
              onClick={() => void vigil.setAlertView(more ? 'less' : 'more')}
            >
              {more ? 'Show me less' : 'Show me more'}
            </button>
          )}
          {!confirming && (
            <button
              type="button"
              className="btn sm ghost"
              disabled={busy}
              title="Marks these as expected. Rules and blocks stay as they are."
              onClick={ask}
            >
              {count === 1 ? 'That was me' : `Those were me (${count})`}
            </button>
          )}
        </span>
      </div>
      {confirming && (
        <div className="row noticed-confirm" role="group" aria-label="Confirm">
          <span className="t-small grow">
            Mark {these} as you? They move to History as expected. Rules and blocks stay as they
            are.
          </span>
          <button type="button" className="btn sm ghost" onClick={() => setConfirm(undefined)}>
            Cancel
          </button>
          <button
            type="button"
            className="btn sm primary"
            disabled={busy}
            autoFocus
            onClick={() => void clear()}
          >
            {offered === 1 ? 'Yes, that was me' : `Yes, all ${offered}`}
          </button>
        </div>
      )}
      {cleared !== undefined && !confirming && (
        <span className="t-small" role="status">
          Marked {cleared === 1 ? 'one' : cleared} as you. They’re in History.
        </span>
      )}
      <span className="t-small">
        {more
          ? 'Usually this is you installing or setting something up. None of these were blocked. Open one if it wasn’t you.'
          : `${count === 1 ? 'One thing' : `${count} things`} Vigil noticed, probably you installing or setting something up. Nothing was blocked.`}
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
          {shown.length < count && (
            <span className="t-small" style={{ padding: '4px 12px' }}>
              and {count - shown.length} more
            </span>
          )}
        </div>
      )}
    </section>
  );
}

/** What a Needs-you row shows: one alert, or a pile told as one thing. */
export interface NeedsRowView {
  /** The alert the row opens. */
  id: string;
  title: string;
  severity: Alert['severity'];
  at: number;
  blocked: boolean;
  /** For a pile: how many alerts, and the agent or program behind them. */
  count?: number;
  who?: string;
}

export function needsRows(alerts: readonly Alert[]): NeedsRowView[] {
  return pileUp(alerts).map((r) => {
    if (r.kind === 'alert') {
      const a = r.alert;
      return {
        id: a.id,
        title: a.title,
        severity: a.severity,
        at: a.createdAt,
        blocked: a.containment === 'active',
      };
    }
    const newest = r.alerts.reduce((x, y) => (y.createdAt > x.createdAt ? y : x));
    return {
      id: newest.id,
      title: newest.title,
      severity: newest.severity,
      at: newest.createdAt,
      blocked: false,
      count: r.alerts.length,
      who: r.who,
    };
  });
}

/** "Claude app · 194 times" for a pile. */
export function pileLine(r: NeedsRowView): string | undefined {
  return r.count ? `${r.who} · ${r.count} times` : undefined;
}
