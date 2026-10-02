import { useLive, vigil } from '../api';
import { NoticedList } from '../components/Attention';
import { Card, Chip, SeverityMark } from '../components/ui';
import { actorLabel, describeRecord } from '../format';
import { isNoticed } from '../../../shared/attention';
import { PageHead } from './AppShell';
import { DAYS, historyEntries, LIMIT, outcome, type Entry } from './history-entries';

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
  if (!alerts || !actions) return null;
  const noticed = (open ?? []).filter(isNoticed);
  const entries = historyEntries(alerts, actions);
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
      />
      {noticed.length > 0 && (
        <Card>
          <NoticedList
            alerts={noticed}
            view="more"
            toggle={false}
            open={(id) => go(`alerts/${id}`)}
          />
        </Card>
      )}
      {days.length === 0 && noticed.length === 0 && (
        <Card>
          <span className="t-small">Nothing yet. Vigil lists what it handled here.</span>
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
                <div key={e.record.id} className="list-row history-row">
                  <span className="grow ellipsis">{describeRecord(e.record)}</span>
                  <span className="t-small nowrap">
                    {actorLabel(e.record.actor)} · {time(e.at)}
                  </span>
                </div>
              ),
            )}
          </div>
        </Card>
      ))}
      {entries.length === LIMIT && (
        <span className="t-small">
          Showing the latest {LIMIT}. Settings › Advanced › Activity has everything.
        </span>
      )}
    </div>
  );
}
