import { Search } from 'lucide-react';
import { useState } from 'react';
import { useLive, vigil } from '../api';
import { NoticedList } from '../components/Attention';
import { Card, Chip, SeverityMark } from '../components/ui';
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
  const [query, setQuery] = useState('');
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
        purpose={`What Vigil handled in the last ${DAYS} days. Nothing here needs you.`}
        right={
          all.length > 0 ? (
            <label className="search">
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
                <button
                  key={e.alert.id}
                  type="button"
                  className="list-row history-row"
                  onClick={() => go(`alerts/${e.alert.id}`)}
                >
                  <SeverityMark severity={e.alert.severity} />
                  <span className="col grow" style={{ gap: 2 }}>
                    <span className="t-h3 clamp-2" title={e.alert.title}>
                      {e.alert.title}
                    </span>
                    {e.actions.length > 0 && (
                      <span className="t-small ellipsis">
                        {e.actions.map((r) => describeRecord(r)).join(' · ')}
                      </span>
                    )}
                  </span>
                  <Chip tone={e.alert.containment === 'active' ? 'good' : undefined}>
                    {outcome(e.alert)}
                  </Chip>
                  <span className="t-small nowrap">{time(e.at)}</span>
                </button>
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
