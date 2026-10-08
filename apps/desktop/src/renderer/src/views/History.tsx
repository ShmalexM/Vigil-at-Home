import { ChevronRight, Search } from 'lucide-react';
import { useState } from 'react';
import { useLive, vigil } from '../api';
import { NoticedList } from '../components/Attention';
import { Card, Chip, SeverityMark } from '../components/ui';
import { responseProvenance } from '../decision';
import { actorLabel, describeRecord } from '../format';
import { isNoticed } from '../../../shared/attention';
import { PageHead } from './AppShell';
import { DAYS, filterEntries, historyEntries, LIMIT, outcome, type Entry } from './history-entries';

const time = (ts: number) =>
  new Date(ts).toLocaleTimeString(undefined, { hour: 'numeric', minute: '2-digit' });

function dayLabel(ts: number, now = Date.now()): string {
  const day = (t: number) => new Date(t).toDateString();
  if (day(ts) === day(now)) return 'Today';
  if (day(ts) === day(now - 86_400_000)) return 'Yesterday';
  return new Date(ts).toLocaleDateString(undefined, {
    weekday: 'long',
    month: 'short',
    day: 'numeric',
  });
}

export function HistoryView({ go }: { go: (r: string) => void }) {
  const [alerts] = useLive(() => vigil.listAlerts('resolved'));
  const [actions] = useLive(() => vigil.listActions());
  const [open] = useLive(() => vigil.listAlerts('open'));
  const [status] = useLive(() => vigil.getStatus());
  const [query, setQuery] = useState('');
  // One row opens in place; the full alert is a button away.
  const [expanded, setExpanded] = useState<string>();
  if (!alerts || !actions) return null;
  const noticed = (open ?? []).filter(isNoticed);
  const all = historyEntries(alerts, actions);
  const entries = filterEntries(all, query, describeRecord);
  const searching = query.trim() !== '';
  const days: { label: string; items: Entry[] }[] = [];
  for (const e of entries) {
    const label = dayLabel(e.at);
    const last = days[days.length - 1];
    if (last?.label === label) last.items.push(e);
    else days.push({ label, items: [e] });
  }

  return (
    <div className="page">
      <PageHead
        title="History"
        purpose={`What Vigil handled in the last ${DAYS} days, and what it only noticed. None of it is waiting on a decision.`}
        right={
          all.length > 0 ? (
            <label className="search history-search">
              <Search size={14} aria-hidden />
              <input
                type="search"
                aria-label="Search History"
                placeholder="Search programs, addresses, actions"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                onKeyDown={(e) => e.key === 'Escape' && setQuery('')}
              />
            </label>
          ) : undefined
        }
      />
      {noticed.length > 0 && !searching && (
        <Card>
          <NoticedList
            alerts={noticed}
            total={status?.noticed}
            clearable={status?.noticedClearable}
            view="more"
            toggle={false}
            open={(id) => go(`alerts/${id}`)}
          />
        </Card>
      )}
      {searching && entries.length === 0 && (
        <Card>
          <span className="t-small">
            Nothing in the last {DAYS} days matches “{query.trim()}”. Advanced › Activity searches
            every event Vigil saw.
          </span>
          <span className="row" style={{ gap: 8 }}>
            <button type="button" className="btn sm" onClick={() => setQuery('')}>
              Clear search
            </button>
            <button type="button" className="btn sm ghost" onClick={() => go('activity')}>
              Open Activity
            </button>
          </span>
        </Card>
      )}
      {all.length === 0 && noticed.length === 0 && (
        <Card>
          <span className="t-small">
            Nothing handled in the last {DAYS} days. When Vigil blocks something, or you decide on
            an alert, it’s listed here.
          </span>
        </Card>
      )}
      {days.map((d) => (
        <Card key={d.label}>
          <h2 className="t-h2">{d.label}</h2>
          <div className="list">
            {d.items.map((e) =>
              e.kind === 'alert' ? (
                <AlertRow
                  key={e.alert.id}
                  e={e}
                  expanded={expanded === e.alert.id}
                  onToggle={() => setExpanded(expanded === e.alert.id ? undefined : e.alert.id)}
                  go={go}
                />
              ) : (
                <ActionRow key={e.record.id} e={e} go={go} />
              ),
            )}
          </div>
        </Card>
      ))}
      {all.length === LIMIT && (
        <span className="row t-small" style={{ gap: 8 }}>
          {searching ? `Searching the latest ${LIMIT}.` : `Showing the latest ${LIMIT}.`} Activity
          has everything.
          <button type="button" className="btn sm ghost" onClick={() => go('activity')}>
            Open Activity
          </button>
        </span>
      )}
    </div>
  );
}

/**
 * An action on its own: one on an alert that's still open (it opens that
 * alert), or one with no alert, which has nothing further to open.
 */
function ActionRow({ e, go }: { e: Extract<Entry, { kind: 'action' }>; go: (r: string) => void }) {
  const body = (
    <>
      <span className="grow ellipsis" title={e.record.reason || undefined}>
        {describeRecord(e.record)}
      </span>
      <span className="t-small nowrap">
        {actorLabel(e.record.actor)} · {time(e.at)}
      </span>
    </>
  );
  const alertId = e.record.alertId;
  return alertId ? (
    <button
      type="button"
      className="list-row"
      title="Open the alert this was for"
      onClick={() => go(`alerts/${alertId}`)}
    >
      {body}
    </button>
  ) : (
    <div className="list-row history-row">{body}</div>
  );
}

/**
 * A handled alert. Clicking opens what happened right here, in History,
 * instead of jumping to Advanced › Alerts; the full alert is one more click.
 */
function AlertRow({
  e,
  expanded,
  onToggle,
  go,
}: {
  e: Extract<Entry, { kind: 'alert' }>;
  expanded: boolean;
  onToggle: () => void;
  go: (r: string) => void;
}) {
  const a = e.alert;
  const panel = `history-${a.id}`;
  return (
    <div className={expanded ? 'history-item open' : 'history-item'}>
      <button
        type="button"
        className="list-row history-row"
        aria-expanded={expanded}
        aria-controls={panel}
        onClick={onToggle}
      >
        <SeverityMark severity={a.severity} />
        <span className="col grow" style={{ gap: 2, minWidth: 0 }}>
          <span className="t-h3 clamp-2" title={a.title}>
            {a.title}
          </span>
          {e.actions.length > 0 && (
            <span className="t-small ellipsis">
              {e.actions.map((r) => describeRecord(r)).join(' · ')}
            </span>
          )}
        </span>
        <Chip
          tone={
            a.containment !== 'active'
              ? undefined
              : responseProvenance(e.actions) === 'real'
                ? 'good'
                : 'fair'
          }
        >
          {outcome(a, e.actions)}
        </Chip>
        <span className="t-small nowrap">{time(e.at)}</span>
        <ChevronRight size={14} className="history-chevron" aria-hidden />
      </button>
      {expanded && (
        <div id={panel} className="col history-detail">
          {a.summary && <p className="t-small">{a.summary}</p>}
          {a.subject?.path && <div className="subject mono">{a.subject.path}</div>}
          {e.actions.length > 0 && (
            <ul className="t-small">
              {e.actions.map((r) => (
                <li key={r.id}>
                  {describeRecord(r)} · {actorLabel(r.actor)} · {time(r.requestedAt)}
                </li>
              ))}
            </ul>
          )}
          {a.decision && (
            <span className="t-small">
              You decided at {time(a.decision.at)}
              {a.decision.note ? ` · ${a.decision.note}` : ''}
            </span>
          )}
          <span className="row" style={{ gap: 8 }}>
            <button type="button" className="btn sm" onClick={() => go(`alerts/${a.id}`)}>
              Open the full alert
            </button>
          </span>
        </div>
      )}
    </div>
  );
}
