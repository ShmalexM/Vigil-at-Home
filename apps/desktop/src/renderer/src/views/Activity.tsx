import type { AgentTag, EventKind, RuleMode, SensorEvent } from '@vigil/core';
import {
  AppWindow,
  Bot,
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
  X,
} from 'lucide-react';
import { useEffect, useRef, useState, type ReactNode } from 'react';
import type { EventGroup, EventLabel, EventOutcome, EventView } from '../../../shared/ipc';
import { useLive, vigil } from '../api';
import { useToast } from '../components/Toasts';
import { Button, Card, Chip, Segmented, StatusMark } from '../components/ui';
import { actorLabel, clock, describeAction, describeEvent, timeAgo, timeOfDay } from '../format';
import { agentRoute, parseActivityParam, VIGIL_CONNECTOR, VIGIL_SELF } from './agents-format';
import { PageHead } from './AppShell';

const UNDOABLE = new Set([
  'process.suspend',
  'network.block',
  'file.quarantine',
  'santa.rule.set',
  'persistence.disable',
]);

type Tab = 'sees' | 'did';

/** What an opened event needs to name its agent and link to its session. */
export interface AgentLinks {
  /** The agent's name, or its id when Vigil doesn't list it. */
  nameOf: (id: string) => string;
  go?: ((route: string) => void) | undefined;
}

/** Agent names for opened events and the filter chip. */
export function useAgentLinks(go?: (route: string) => void): AgentLinks {
  const [agents] = useLive(() => vigil.listAgents());
  return {
    nameOf: (id) =>
      id === VIGIL_SELF
        ? 'Vigil’s own AI helper'
        : id === VIGIL_CONNECTOR
          ? 'A pack connector'
          : (agents?.find((a) => a.id === id)?.name ?? id),
    go,
  };
}

/**
 * `selected` narrows the feed to one agent (`agent-<id>`) or one of its
 * sessions (`session-<hex>`), as linked from the Agents page.
 */
export function ActivityView({
  selected,
  go,
}: {
  selected?: string | undefined;
  go?: (route: string) => void;
}) {
  const [tab, setTab] = useState<Tab>('sees');
  const filter = parseActivityParam(selected);
  const filtered = !!(filter.agent || filter.session);
  const links = useAgentLinks(go);
  // A link to an agent's activity always lands on the feed.
  useEffect(() => {
    if (filtered) setTab('sees');
  }, [selected, filtered]);
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
      {tab === 'sees' ? <EventFeed filter={filter} links={links} /> : <ActionLog />}
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
  { value: 'agents', label: 'Agent requests' },
];

const PAGE = 100;

/** Matches TEXT_SEARCH_WINDOW_MS in shared/ipc.ts (not imported, to keep zod out of the renderer). */
const SEARCH_WINDOW_MS = 24 * 60 * 60 * 1000;

function EventFeed({
  filter,
  links,
}: {
  filter: { agent?: string; session?: string };
  links: AgentLinks;
}) {
  const [group, setGroup] = useState<EventGroup | 'all'>('all');
  const [matchedOnly, setMatchedOnly] = useState(false);
  const [text, setText] = useState('');
  const [paused, setPaused] = useState(false);
  const [rows, setRows] = useState<EventView[]>();
  const [more, setMore] = useState(false);
  /** With a search: how far back it has looked so far. */
  const [searchedTo, setSearchedTo] = useState<number>();
  const [waiting, setWaiting] = useState(0);
  const [open, setOpen] = useState<string>();
  const [stats, reloadStats] = useLive(() => vigil.eventStats());

  const query = {
    ...(group !== 'all' ? { group } : {}),
    ...(matchedOnly ? { matchedOnly } : {}),
    ...(text.trim() ? { text: text.trim() } : {}),
    ...(filter.agent ? { agent: filter.agent } : {}),
    ...(filter.session ? { agentSession: filter.session } : {}),
    limit: PAGE,
  };
  const queryRef = useRef(query);
  queryRef.current = query;
  const pausedRef = useRef(paused);
  pausedRef.current = paused;

  const load = useRef(() => {
    const from = Date.now();
    void vigil.listEvents(queryRef.current).then((r) => {
      setRows(r);
      setMore(r.length === PAGE);
      setSearchedTo(queryRef.current.text ? from - SEARCH_WINDOW_MS : undefined);
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

  // A search looks back one day at a time, so it never scans the whole history at once.
  const searching = searchedTo !== undefined;
  const oldestKept = Date.now() - (stats?.retentionDays ?? 30) * 24 * 60 * 60 * 1000;
  const canSearchBack = searching && !more && searchedTo > oldestKept;

  const older = async () => {
    const last = rows?.at(-1);
    const before = more && last ? last.event.ts : searchedTo;
    if (before === undefined) return;
    const r = await vigil.listEvents({ ...queryRef.current, before });
    setRows([...(rows ?? []), ...r]);
    setMore(r.length === PAGE);
    if (searching) setSearchedTo(before - SEARCH_WINDOW_MS);
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
        {(filter.agent || filter.session) && (
          <span className="chip accent filter-chip">
            {filter.agent ? `Agent: ${links.nameOf(filter.agent)}` : 'One agent session'}
            <button
              type="button"
              aria-label="Show every event"
              title="Show every event"
              onClick={() => links.go?.('activity')}
            >
              <X size={12} />
            </button>
          </span>
        )}
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
        ) : rows && rows.length === 0 && !canSearchBack ? (
          <span className="t-small feed-none">No events match these filters.</span>
        ) : (
          (rows ?? []).map((v) => (
            <EventRow
              key={v.event.id}
              view={v}
              open={open === v.event.id}
              onToggle={() => setOpen(open === v.event.id ? undefined : v.event.id)}
              links={links}
            />
          ))
        )}
        {(more || canSearchBack) && (
          <div className="row" style={{ justifyContent: 'center', padding: 10, gap: 10 }}>
            {!more && searchedTo !== undefined && (
              <span className="t-small">
                {rows?.length ? 'No more matches' : 'No matches'} since {timeOfDay(searchedTo)}
              </span>
            )}
            <Button size="sm" kind="ghost" onClick={() => void older()}>
              {more ? 'Show older events' : 'Search the day before'}
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
  'agent.tool_request': <Bot size={15} />,
};

/** One line of the feed, opening into the event's fields. Also used for an agent session's events. */
export function EventRow({
  view: { event: e, outcome, label },
  open,
  onToggle,
  links,
}: {
  view: EventView;
  open: boolean;
  onToggle: () => void;
  links: AgentLinks;
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
        {label && label.label !== 'benign' && <LabelChip label={label} />}
        <OutcomeChip outcome={outcome} toolRequest={e.kind === 'agent.tool_request'} />
        {open ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
      </button>
      {open && <EventFields event={e} outcome={outcome} links={links} />}
    </div>
  );
}

/** A model's hint on an event no rule matched. Hints never act on anything. */
function LabelChip({ label }: { label: EventLabel }) {
  const who = label.by === 'jev' ? 'Jev' : 'AI';
  return (
    <Chip
      tone={label.label === 'suspicious' ? 'fair' : 'ai'}
      title={`${label.reason}\nA hint only: nothing was blocked or allowed because of it.`}
    >
      {who}: {label.label === 'suspicious' ? 'looks suspicious' : 'unusual'}
    </Chip>
  );
}

/** What the top match did. A tool request is asked about or stopped before it runs. */
const OUTCOME_PREFIX: Record<RuleMode, string> = {
  block: 'Blocked: ',
  alert: 'Alert: ',
  shadow: 'Shadow: ',
  disabled: '',
};
const TOOL_OUTCOME_PREFIX: Record<RuleMode, string> = {
  block: 'Stopped: ',
  alert: 'Asked: ',
  shadow: 'Recorded: ',
  disabled: '',
};

function OutcomeChip({
  outcome,
  toolRequest,
}: {
  outcome: EventOutcome | null;
  toolRequest: boolean;
}) {
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
      {(toolRequest ? TOOL_OUTCOME_PREFIX : OUTCOME_PREFIX)[top.mode]}
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
    case 'agent.tool_request':
      return e.command ?? e.filePath ?? e.url ?? e.mcpServer;
  }
}

const base = (p: string) => p.split('/').filter(Boolean).pop() ?? p;

/** Which agent an event ran under, with a link to its session when there is a page for it. */
function AgentField({
  id,
  session,
  links,
}: {
  id: string;
  session?: string | undefined;
  links: AgentLinks;
}) {
  const own = id === VIGIL_SELF;
  // Pack connectors have no page on Agents; the Pack page lists them.
  const linked = !own && id !== VIGIL_CONNECTOR;
  return (
    <span className="row" style={{ gap: 8, flexWrap: 'wrap' }}>
      <Chip tone={own ? 'ai' : 'accent'}>
        <Bot size={12} />
        {links.nameOf(id)}
      </Chip>
      {session && linked && links.go && (
        <button
          type="button"
          className="more-link"
          onClick={() => links.go?.(agentRoute(id, session))}
        >
          Open this session
        </button>
      )}
    </span>
  );
}

/** How the hook was answered, from the rules that matched. */
function answerOf(outcome: EventOutcome | null): string {
  const modes = new Set(outcome?.matches.map((m) => m.mode));
  if (modes.has('block')) return 'Stopped: Claude Code did not run it';
  if (modes.has('alert')) return 'Claude Code asked you first';
  return 'Left to Claude Code';
}

/** "the agent itself", "started by the agent", "2 levels under the agent". */
function depthText(t: AgentTag): string {
  if (t.depth === 0) return 'the agent itself';
  return t.depth === 1 ? 'started by the agent' : `${t.depth} levels under the agent`;
}

function EventFields({
  event: e,
  outcome,
  links,
}: {
  event: SensorEvent;
  outcome: EventOutcome | null;
  links: AgentLinks;
}) {
  const fields: [string, ReactNode][] = [
    ['When', clock(e.ts)],
    ['Seen by', e.source === 'osquery' ? 'osquery' : e.source === 'santa' ? 'Santa' : 'Vigil'],
  ];
  // A tool request's process is the shell it would start, not a real one.
  const p = 'process' in e && e.kind !== 'agent.tool_request' ? e.process : undefined;
  if (p) {
    fields.push(['Program', <code key="p">{p.path}</code>]);
    fields.push(['Process id', p.pid]);
    if (p.args?.length) fields.push(['Arguments', <code key="a">{p.args.join(' ')}</code>]);
    if (p.parentPath) fields.push(['Started by', <code key="pp">{p.parentPath}</code>]);
    if (p.ancestors?.length) {
      fields.push([
        'Process chain',
        <code key="anc" title="Nearest first">
          {[base(p.path), ...p.ancestors].join(' ← ')}
        </code>,
      ]);
    }
    if (p.agent) {
      fields.push([
        'Agent',
        <span key="ag" className="col" style={{ gap: 2 }}>
          <AgentField id={p.agent.id} session={p.agent.session} links={links} />
          <span className="t-small">This program is {depthText(p.agent)}.</span>
        </span>,
      ]);
    }
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
  if (e.kind === 'agent.tool_request') {
    fields.push(['Tool', <code key="t">{e.tool}</code>]);
    if (e.mcpServer) fields.push(['MCP server', <code key="m">{e.mcpServer}</code>]);
    if (e.command) fields.push(['Command', <code key="c">{e.command}</code>]);
    if (e.commandBytes !== undefined && e.commandBytes > 4096)
      fields.push(['Command size', `${e.commandBytes} bytes; Vigil checked the first 4 KB`]);
    if (e.filePath) fields.push(['File', <code key="f">{e.filePath}</code>]);
    if (e.url) fields.push(['Address', <code key="u">{e.url}</code>]);
    if (e.cwd) fields.push(['In folder', <code key="w">{e.cwd}</code>]);
    if (e.contentBytes !== undefined)
      fields.push([
        'Content',
        `${e.contentBytes} bytes${e.contentSha256 ? `, SHA-256 ${e.contentSha256.slice(0, 16)}…` : ''}. The text itself never reaches Vigil.`,
      ]);
    fields.push([
      'Agent',
      e.agent.id ? (
        <AgentField key="ag" id={e.agent.id} session={e.agent.session} links={links} />
      ) : (
        'Claude Code (Vigil didn’t see which session started it)'
      ),
    ]);
    fields.push(['Answer', answerOf(outcome)]);
  }
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
