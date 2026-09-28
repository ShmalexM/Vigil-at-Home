import type { EventKind, SensorEvent } from '@vigil/core';
import {
  AppWindow,
  ChevronDown,
  ChevronRight,
  FileText,
  Globe,
  Pause,
  Play,
  Puzzle,
  Radio,
  Rocket,
  Search,
  ShieldAlert,
  ShieldCheck,
} from 'lucide-react';
import { useEffect, useRef, useState, type ReactNode } from 'react';
import type { EventGroup, EventOutcome, EventView } from '../../../shared/ipc';
import { useLive, vigil } from '../api';
import { useToast } from '../components/Toasts';
import { Button, Card, Chip, Segmented, StatusMark } from '../components/ui';
import { actorLabel, clock, describeAction, describeEvent, timeAgo, timeOfDay } from '../format';
import { PageHead } from './AppShell';

const UNDOABLE = new Set([
  'process.suspend',
  'network.block',
  'file.quarantine',
  'santa.rule.set',
  'persistence.disable',
]);

type Tab = 'sees' | 'did';

export function ActivityView() {
  const [tab, setTab] = useState<Tab>('sees');
  return (
    <div className="page">
      <PageHead
        title="Activity"
        purpose="Everything Vigil looks at on this Mac, what its rules made of it, and every action it took."
      />
      <div className="tabs" role="tablist">
        <button
          type="button"
          role="tab"
          aria-selected={tab === 'sees'}
          onClick={() => setTab('sees')}
        >
          What Vigil sees
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={tab === 'did'}
          onClick={() => setTab('did')}
        >
          What Vigil did
        </button>
      </div>
      {tab === 'sees' ? <EventFeed /> : <ActionLog />}
    </div>
  );
}

// ---------------------------------------------------------------- what Vigil sees

const GROUPS: { value: EventGroup | 'all'; label: string }[] = [
  { value: 'all', label: 'All' },
  { value: 'programs', label: 'Programs' },
  { value: 'network', label: 'Network' },
  { value: 'files', label: 'Files' },
  { value: 'startup', label: 'Startup & extensions' },
  { value: 'system', label: 'macOS alerts' },
];

const PAGE = 100;

function EventFeed() {
  const [group, setGroup] = useState<EventGroup | 'all'>('all');
  const [matchedOnly, setMatchedOnly] = useState(false);
  const [text, setText] = useState('');
  const [paused, setPaused] = useState(false);
  const [rows, setRows] = useState<EventView[]>();
  const [more, setMore] = useState(false);
  const [waiting, setWaiting] = useState(0);
  const [open, setOpen] = useState<string>();
  const [stats, reloadStats] = useLive(() => vigil.eventStats());

  const query = {
    ...(group !== 'all' ? { group } : {}),
    ...(matchedOnly ? { matchedOnly } : {}),
    ...(text.trim() ? { text: text.trim() } : {}),
    limit: PAGE,
  };
  const queryRef = useRef(query);
  queryRef.current = query;
  const pausedRef = useRef(paused);
  pausedRef.current = paused;

  const load = useRef(() => {
    void vigil.listEvents(queryRef.current).then((r) => {
      setRows(r);
      setMore(r.length === PAGE);
      setWaiting(0);
    });
  }).current;

  // Reload when the filters change (search waits for typing to settle).
  const key = JSON.stringify(query);
  useEffect(() => {
    const t = setTimeout(load, text ? 250 : 0);
    return () => clearTimeout(t);
  }, [key, load, text]);

  // New events arrive in batches at most once a second.
  useEffect(
    () =>
      vigil.on('events', (n) => {
        reloadStats();
        if (pausedRef.current) setWaiting((w) => w + n);
        else load();
      }),
    [load, reloadStats],
  );

  const older = async () => {
    const last = rows?.at(-1);
    if (!last) return;
    const r = await vigil.listEvents({ ...queryRef.current, before: last.event.ts });
    setRows([...(rows ?? []), ...r]);
    setMore(r.length === PAGE);
  };

  const empty = stats && stats.newest === null;

  return (
    <div className="col" style={{ gap: 16 }}>
      <div className="stat-strip">
        <Stat label="Events in the last hour" value={stats?.lastHour ?? 0} />
        <Stat label="Programs started" value={stats?.programsLastHour ?? 0} />
        <Stat label="Matched a rule" value={stats?.matchedLastHour ?? 0} />
        <Stat
          label="Latest event"
          value={stats?.newest ? timeAgo(stats.newest) : 'None yet'}
          live={!paused && !!stats?.newest}
        />
      </div>

      <div className="row feed-controls">
        <Segmented label="Kind of event" value={group} options={GROUPS} onChange={setGroup} />
        <Segmented
          label="Which events"
          value={matchedOnly ? 'matched' : 'all'}
          options={[
            { value: 'all', label: 'Everything' },
            { value: 'matched', label: 'Rule matches' },
          ]}
          onChange={(v) => setMatchedOnly(v === 'matched')}
        />
        <label className="search grow">
          <Search size={14} />
          <input
            type="search"
            placeholder="Search programs, paths, addresses"
            value={text}
            onChange={(e) => setText(e.target.value)}
          />
        </label>
        <Button
          size="sm"
          kind="ghost"
          icon={paused ? <Play size={14} /> : <Pause size={14} />}
          onClick={() => {
            setPaused(!paused);
            if (paused) load();
          }}
        >
          {paused ? 'Resume' : 'Pause'}
        </Button>
      </div>

      {paused && waiting > 0 && (
        <button type="button" className="feed-waiting" onClick={() => (setPaused(false), load())}>
          {waiting} new {waiting === 1 ? 'event' : 'events'} while paused. Show them.
        </button>
      )}

      <Card tight className="feed">
        {empty ? (
          <div className="empty">
            <span className="empty-icon">
              <Radio size={20} />
            </span>
            <span className="t-h3">Nothing to show yet</span>
            <span className="t-small" style={{ maxWidth: 440 }}>
              Vigil sees programs starting, network connections and new startup items once Santa and
              osquery are installed. Everything it sees will show up here as it happens.
            </span>
          </div>
        ) : rows && rows.length === 0 ? (
          <span className="t-small feed-none">No events match these filters.</span>
        ) : (
          (rows ?? []).map((v) => (
            <EventRow
              key={v.event.id}
              view={v}
              open={open === v.event.id}
              onToggle={() => setOpen(open === v.event.id ? undefined : v.event.id)}
            />
          ))
        )}
        {more && (
          <div className="row" style={{ justifyContent: 'center', padding: 10 }}>
            <Button size="sm" kind="ghost" onClick={() => void older()}>
              Show older events
            </Button>
          </div>
        )}
      </Card>

      <span className="t-small">
        Events stay on this Mac for {stats?.retentionDays ?? 30} days, except ones an alert points
        to. When you use the AI, it gets a summary with your name and home folder removed, never
        this raw feed.
      </span>
    </div>
  );
}

function Stat({ label, value, live }: { label: string; value: ReactNode; live?: boolean }) {
  return (
    <div className="stat">
      <span className="t-small">{label}</span>
      <span className="stat-value">
        {live && <span className="live-dot" aria-label="Live" />}
        {value}
      </span>
    </div>
  );
}

const KIND_ICON: Record<EventKind, ReactNode> = {
  'process.exec': <AppWindow size={15} />,
  'process.exit': <AppWindow size={15} />,
  'santa.decision': <ShieldCheck size={15} />,
  'network.connection': <Globe size={15} />,
  'network.listen': <Radio size={15} />,
  file: <FileText size={15} />,
  persistence: <Rocket size={15} />,
  'browser.extension': <Puzzle size={15} />,
  'system.alert': <ShieldAlert size={15} />,
};

function EventRow({
  view: { event: e, outcome },
  open,
  onToggle,
}: {
  view: EventView;
  open: boolean;
  onToggle: () => void;
}) {
  const detail = eventDetail(e);
  return (
    <div className={`feed-row ${open ? 'open' : ''}`}>
      <button type="button" className="feed-line" onClick={onToggle} aria-expanded={open}>
        <span className="t-small mono feed-time">{timeOfDay(e.ts)}</span>
        <span className="feed-icon">{KIND_ICON[e.kind]}</span>
        <span className="col grow" style={{ gap: 1, minWidth: 0 }}>
          <span className="ellipsis">{describeEvent(e)}</span>
          {detail && <span className="t-small mono ellipsis">{detail}</span>}
        </span>
        <OutcomeChip outcome={outcome} />
        {open ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
      </button>
      {open && <EventFields event={e} outcome={outcome} />}
    </div>
  );
}

function OutcomeChip({ outcome }: { outcome: EventOutcome | null }) {
  if (!outcome) return <span className="t-small feed-outcome">Not checked</span>;
  const top = outcome.matches[0];
  if (!top) {
    return (
      <span className="t-small feed-outcome">
        {outcome.checked} {outcome.checked === 1 ? 'rule' : 'rules'}, no match
      </span>
    );
  }
  const tone = top.mode === 'block' ? 'poor' : top.mode === 'alert' ? 'fair' : undefined;
  const extra = outcome.matches.length > 1 ? ` +${outcome.matches.length - 1}` : '';
  return (
    <Chip tone={tone} title={outcome.matches.map((m) => `${m.ruleName} (${m.mode})`).join('\n')}>
      {{ block: 'Blocked: ', alert: 'Alert: ', shadow: 'Shadow: ', disabled: '' }[top.mode]}
      {top.ruleName}
      {extra}
    </Chip>
  );
}

/** The one line under the headline: which program, or where. */
function eventDetail(e: SensorEvent): string | undefined {
  switch (e.kind) {
    case 'process.exec':
    case 'process.exit':
    case 'santa.decision':
      return e.process.path;
    case 'file':
      return e.process ? `${e.path}  ·  by ${base(e.process.path)}` : e.path;
    case 'network.connection':
    case 'network.listen':
      return e.process?.path;
    case 'persistence':
      return e.program ?? e.path;
    case 'browser.extension':
      return e.extensionId;
    case 'system.alert':
      return e.path;
  }
}

const base = (p: string) => p.split('/').filter(Boolean).pop() ?? p;

function EventFields({ event: e, outcome }: { event: SensorEvent; outcome: EventOutcome | null }) {
  const fields: [string, ReactNode][] = [
    ['When', clock(e.ts)],
    ['Seen by', e.source === 'osquery' ? 'osquery' : e.source === 'santa' ? 'Santa' : 'Vigil'],
  ];
  const p = 'process' in e ? e.process : undefined;
  if (p) {
    fields.push(['Program', <code key="p">{p.path}</code>]);
    fields.push(['Process id', p.pid]);
    if (p.args?.length) fields.push(['Arguments', <code key="a">{p.args.join(' ')}</code>]);
    if (p.parentPath) fields.push(['Started by', <code key="pp">{p.parentPath}</code>]);
    if (p.signing) fields.push(['Signature', signingLabel(p.signing, p.teamId)]);
    if (p.sha256) fields.push(['SHA-256', <code key="h">{p.sha256}</code>]);
    if (p.quarantine?.originUrl)
      fields.push(['Downloaded from', <code key="q">{p.quarantine.originUrl}</code>]);
  }
  if (e.kind === 'network.connection') {
    fields.push([
      'Remote',
      <code key="r">
        {e.remoteHost ? `${e.remoteHost} (${e.remoteAddress})` : e.remoteAddress}
        {e.remotePort ? `:${e.remotePort}` : ''}
      </code>,
    ]);
    fields.push(['Direction', `${e.direction}, ${e.protocol.toUpperCase()}`]);
  }
  if (e.kind === 'file') fields.push(['File', <code key="f">{e.path}</code>]);
  if (e.kind === 'persistence') {
    fields.push(['Item', <code key="i">{e.path}</code>]);
    if (e.programArgs?.length)
      fields.push(['Runs', <code key="r">{e.programArgs.join(' ')}</code>]);
  }
  if (e.kind === 'santa.decision') fields.push(['Santa said', `${e.decision}: ${e.reason}`]);
  fields.push([
    'Rules',
    outcome
      ? outcome.matches.length
        ? outcome.matches.map((m) => `${m.ruleName} (${m.mode})`).join(', ')
        : `Checked by ${outcome.checked}, none matched`
      : 'Not checked by any rule',
  ]);
  return (
    <dl className="feed-fields">
      {fields.map(([k, v]) => (
        <div key={k} className="contents">
          <dt className="t-small">{k}</dt>
          <dd>{v}</dd>
        </div>
      ))}
    </dl>
  );
}

function signingLabel(s: string, team?: string): string {
  const label =
    {
      apple: 'Apple',
      developer_id: 'Developer ID',
      app_store: 'App Store',
      adhoc: 'Ad hoc (no developer)',
      unsigned: 'Unsigned',
      invalid: 'Invalid signature',
    }[s] ?? s;
  return team ? `${label}, team ${team}` : label;
}

// ---------------------------------------------------------------- what Vigil did

function ActionLog() {
  const [actions] = useLive(() => vigil.listActions());
  const toast = useToast();
  return (
    <Card>
      {(actions ?? []).length === 0 && (
        <span className="t-small">Vigil hasn't taken any action yet.</span>
      )}
      {(actions ?? []).map((r) => (
        <div key={r.id} className="row activity-row">
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
          <div className="col grow" style={{ gap: 1, minWidth: 0 }}>
            <span className="ellipsis">{describeAction(r.action)}</span>
            <span className="t-small ellipsis">
              {r.reason}
              {r.result?.error ? ` · ${r.result.error}` : ''}
            </span>
          </div>
          <Chip tone={r.actor === 'user' ? 'accent' : r.actor === 'ai' ? 'ai' : undefined}>
            {actorLabel(r.actor)}
          </Chip>
          <span className="t-small" style={{ width: 150, textAlign: 'right' }}>
            {clock(r.requestedAt)}
          </span>
          {r.status === 'done' && !r.undoes && UNDOABLE.has(r.action.kind) ? (
            <Button
              size="sm"
              kind="ghost"
              onClick={async () => {
                await vigil.undoAction(r.id);
                toast({ text: `Undone: ${describeAction(r.action)}` });
              }}
            >
              Undo
            </Button>
          ) : (
            <span style={{ width: 54 }} />
          )}
        </div>
      ))}
    </Card>
  );
}
