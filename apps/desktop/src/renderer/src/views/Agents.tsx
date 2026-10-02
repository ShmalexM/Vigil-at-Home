import type { RuleMode } from '@vigil/core';
import {
  AppWindow,
  ArrowLeft,
  Bot,
  ChevronDown,
  ChevronRight,
  Code,
  Cpu,
  Pencil,
  Plus,
  RotateCcw,
  Sparkles,
  SquareTerminal,
  Trash2,
} from 'lucide-react';
import { useEffect, useState, type ReactNode } from 'react';
import {
  AGENT_KIND_LABEL,
  PRESENCE_LABEL,
  type AgentDetail,
  type AgentKind,
  type AgentPresence,
  type AgentSessionView,
  type AgentView,
  type VigilHelperId,
} from '../../../shared/agents';
import type { RuleView } from '../../../shared/ipc';
import { PROVIDER_LABEL, type UsageProvider } from '../../../shared/usage';
import { TOOL_RULE_TEMPLATES, type ToolRuleTemplate } from '../agent-templates';
import { useLive, vigil } from '../api';
import { AgentForm } from '../components/AgentForm';
import { AgentToolsSetup } from '../components/AgentToolsSetup';
import { HoldButton } from '../components/HoldButton';
import { PreflightSetup } from '../components/PreflightSetup';
import { ProcessTree } from '../components/ProcessTree';
import { NewRulePanel, RuleEditorPanel } from '../components/RuleEditor';
import { useToast } from '../components/Toasts';
import {
  Button,
  Card,
  Chip,
  SectionHead,
  Segmented,
  SeverityMark,
  StatusMark,
  type MarkState,
} from '../components/ui';
import { clock, timeAgo } from '../format';
import {
  confirmsFirst,
  groupAgentRules,
  modeLabel,
  modesFor,
  RAISED_MODE_LABEL,
  RULE_MODE_LABEL,
  TOOL_MODE_LABEL,
} from '../rule-modes';
import '../styles/agents.css';
import { useAgentLinks, EventRow, type AgentLinks } from './Activity';
import {
  activityRoute,
  agentRoute,
  describeMatcher,
  loadOlderSessions,
  mergeSessions,
  noSessionsText,
  originLabel,
  parseAgentParam,
  plural,
  watching,
} from './agents-format';
import { PageHead } from './AppShell';

type Tab = 'mac' | 'policy' | 'helpers';
const TABS: { id: Tab; label: string }[] = [
  { id: 'mac', label: 'On this Mac' },
  { id: 'policy', label: 'Tool policy' },
  { id: 'helpers', label: 'Vigil’s AI helpers' },
];

const PREFS_KEY = 'vigil:agents-page:v1';

function readTab(): Tab {
  try {
    const p = JSON.parse(localStorage.getItem(PREFS_KEY) ?? 'null') as { tab?: unknown } | null;
    const tab = TABS.find((t) => t.id === p?.tab);
    if (tab) return tab.id;
  } catch {
    // Fall through to the first tab.
  }
  return 'mac';
}

function saveTab(tab: Tab): void {
  try {
    localStorage.setItem(PREFS_KEY, JSON.stringify({ tab }));
  } catch {
    // The remembered tab is a convenience.
  }
}

/**
 * Watched agents (the AI tools on this Mac and what they start), the rules
 * their pre-flight hooks ask, and Vigil's own AI helpers. Routes:
 * `agents/<id>` opens an agent, `agents/<id>_<session>` one of its sessions.
 */
export function AgentsView({
  selected,
  go,
}: {
  selected?: string | undefined;
  go: (route: string) => void;
}) {
  const [tab, setTab] = useState<Tab>(readTab);
  const [adding, setAdding] = useState(false);
  const [agents] = useLive(() => vigil.listAgents(), null, 'agents');
  const { id, session } = parseAgentParam(selected);
  const links = useAgentLinks(go);
  // A link to one agent always lands on its tab.
  const shown: Tab = id ? 'mac' : tab;
  const waiting = (agents ?? []).filter((a) => a.status === 'suggested').length;

  const pick = (t: Tab) => {
    setTab(t);
    saveTab(t);
    if (id) go('agents');
  };

  return (
    <div className="page agents">
      <PageHead
        title="Agents"
        purpose="The AI agents on this Mac, what they start, and the steps they ask about. Rules decide what is asked or stopped. AI only explains or suggests."
        right={
          shown === 'mac' && !id ? (
            <Button size="sm" icon={<Plus size={14} />} onClick={() => setAdding(true)}>
              Add an agent
            </Button>
          ) : undefined
        }
      />
      <div className="tabs" role="tablist">
        {TABS.map((t) => (
          <button
            key={t.id}
            type="button"
            role="tab"
            aria-selected={shown === t.id}
            onClick={() => pick(t.id)}
          >
            {t.label}
            {t.id === 'mac' && waiting > 0 && (
              <span className="count" title="Suggestions waiting on you">
                {waiting}
              </span>
            )}
          </button>
        ))}
      </div>
      {shown === 'mac' &&
        agents &&
        (id ? (
          <AgentPage id={id} session={session} agents={agents} links={links} go={go} />
        ) : (
          <OnThisMac agents={agents} adding={adding} setAdding={setAdding} go={go} />
        ))}
      {shown === 'policy' && <ToolPolicy />}
      {shown === 'helpers' && <Helpers go={go} />}
    </div>
  );
}

// ---------------------------------------------------------------- on this Mac

const KIND_ICON: Record<AgentKind, ReactNode> = {
  cli: <SquareTerminal size={17} />,
  app: <AppWindow size={17} />,
  ide: <Code size={17} />,
  runtime: <Cpu size={17} />,
};

const PRESENCE_MARK: Record<AgentPresence, MarkState> = {
  running: 'done',
  seen: 'pending',
  installed: 'pending',
  'not-found': 'pending',
};

/** Why some kinds start unwatched, on their cards. */
const KIND_WHY: Partial<Record<AgentKind, string>> = {
  ide: 'Off by default: its built-in terminal runs your own commands too, so watching it would mix your work with its agent’s.',
  runtime:
    'Listed only. A model runtime answers other programs and never starts a session of its own.',
};

function OnThisMac({
  agents,
  adding,
  setAdding,
  go,
}: {
  agents: AgentView[];
  adding: boolean;
  setAdding: (on: boolean) => void;
  go: (route: string) => void;
}) {
  const [showOthers, setShowOthers] = useState(false);
  const suggested = agents.filter((a) => a.status === 'suggested');
  const active = agents.filter((a) => a.status === 'active');
  const here = active.filter((a) => !a.builtin || a.presence !== 'not-found');
  const others = active.filter((a) => a.builtin && a.presence === 'not-found');
  const ignored = agents.filter((a) => a.status === 'ignored');

  return (
    <>
      {adding && (
        <Card>
          <AgentForm
            agents={agents}
            onClose={() => setAdding(false)}
            onSaved={(a) => {
              setAdding(false);
              go(agentRoute(a.id));
            }}
          />
        </Card>
      )}
      {suggested.map((a) => (
        <Suggestion key={a.id} agent={a} go={go} />
      ))}
      {here.length === 0 ? (
        <div className="empty">
          <span className="empty-icon">
            <Bot size={20} />
          </span>
          <span className="t-h3">No AI agents seen on this Mac yet</span>
          <span className="t-small" style={{ maxWidth: 460 }}>
            Vigil recognises Claude Code, Codex, Copilot, Gemini, Cursor and others as soon as they
            run. It tags what command-line agents and agent apps start. Editors start unwatched, and
            model runtimes are only listed. Use “Add an agent” for one it doesn’t know.
          </span>
        </div>
      ) : (
        <div className="agent-grid">
          {here.map((a) => (
            <AgentCard key={a.id} agent={a} go={go} />
          ))}
        </div>
      )}
      {others.length > 0 && (
        <Card tight>
          <button
            type="button"
            className="agent-fold"
            aria-expanded={showOthers}
            onClick={() => setShowOthers(!showOthers)}
          >
            {showOthers ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
            <span className="t-h3">Other agents Vigil knows</span>
            <span className="t-small grow">
              {plural(others.length, 'agent')} not found on this Mac. Vigil recognises one the
              moment it runs, and watches what it starts if its switch is On.
            </span>
          </button>
          {showOthers && others.map((a) => <AgentLine key={a.id} agent={a} go={go} />)}
        </Card>
      )}
      {ignored.length > 0 && (
        <Card tight>
          <SectionHead
            title="Ignored"
            sub="Not treated as agents: what they start isn’t tagged. Watch one again at any time."
          />
          {ignored.map((a) => (
            <AgentLine key={a.id} agent={a} go={go} />
          ))}
        </Card>
      )}
    </>
  );
}

/** A program Vigil's fixed heuristic flagged. It tags nothing until you accept it. */
function Suggestion({ agent: a, go }: { agent: AgentView; go: (route: string) => void }) {
  const toast = useToast();
  return (
    <div className="attn accent agent-suggestion">
      <Bot size={16} />
      <span className="col grow" style={{ gap: 2 }}>
        <span className="t-h3">Is {a.name} an AI agent?</span>
        <span className="t-small">
          It started many shell commands in a few minutes, the way agents do. Vigil spotted this
          with a fixed rule, not an AI, and tags nothing it runs until you say so.
        </span>
      </span>
      <Button size="sm" kind="ghost" onClick={() => go(agentRoute(a.id))}>
        Details
      </Button>
      <Button
        size="sm"
        onClick={async () => {
          await vigil.setAgentStatus(a.id, 'ignored');
          toast({ text: `${a.name} won’t be suggested again` });
        }}
      >
        Not an agent
      </Button>
      <Button
        size="sm"
        kind="primary"
        onClick={async () => {
          await vigil.setAgentStatus(a.id, 'active');
          toast({ text: `Watching ${a.name}` });
        }}
      >
        Watch it
      </Button>
    </div>
  );
}

function AgentCard({ agent: a, go }: { agent: AgentView; go: (route: string) => void }) {
  return (
    <Card tight className="agent-card">
      <button
        type="button"
        className="agent-open"
        title={`Open ${a.name}`}
        onClick={() => go(agentRoute(a.id))}
      >
        <AgentTitle agent={a} />
        <ChevronRight size={15} className="agent-chevron" />
      </button>
      <TodayStats agent={a} />
      {KIND_WHY[a.kind] && <span className="t-small">{KIND_WHY[a.kind]}</span>}
      <div className="row spread agent-foot">
        <span className="t-small">Watch what it starts</span>
        <WatchSwitch agent={a} />
      </div>
    </Card>
  );
}

/** Icon, name, chips, kind and presence: the top of a card and of an agent's page. */
function AgentTitle({ agent: a, large }: { agent: AgentView; large?: boolean }) {
  const origin = originLabel(a);
  return (
    <>
      <span className="agent-icon">{KIND_ICON[a.kind]}</span>
      <span className="col grow" style={{ gap: 2 }}>
        <span className="row" style={{ gap: 6, flexWrap: 'wrap' }}>
          <span className={`${large ? 't-h2' : 't-h3'} ellipsis`}>{a.name}</span>
          <Chip {...(origin.tone ? { tone: origin.tone } : {})}>{origin.label}</Chip>
          {a.edited && <Chip title="You changed how Vigil recognises it">Edited</Chip>}
          {a.preflightHost && (
            <Chip title="Its hook can ask Vigil before each tool call">Pre-flight</Chip>
          )}
        </span>
        <span className="t-small">
          {AGENT_KIND_LABEL[a.kind]}
          {a.lastSeenAt !== undefined && ` · last active ${timeAgo(a.lastSeenAt)}`}
        </span>
      </span>
      <span className="row agent-presence">
        <StatusMark state={PRESENCE_MARK[a.presence]} label={PRESENCE_LABEL[a.presence]} />
        <span className="t-small nowrap">{PRESENCE_LABEL[a.presence]}</span>
      </span>
    </>
  );
}

function TodayStats({ agent: a }: { agent: AgentView }) {
  const cells: { label: string; n: number; tone?: 'fair' | 'poor' }[] = [
    { label: 'Sessions today', n: a.sessionsToday },
    { label: 'Rule matches', n: a.matchesToday, ...(a.matchesToday ? { tone: 'fair' } : {}) },
  ];
  if (a.preflightHost) {
    cells.push(
      { label: 'Steps asked', n: a.asksToday },
      { label: 'Steps stopped', n: a.deniesToday, ...(a.deniesToday ? { tone: 'poor' } : {}) },
    );
  }
  return (
    <div className="agent-stats">
      {cells.map(({ label, n, tone }) => (
        <span key={label} className="agent-stat">
          <span className={`agent-stat-n ${tone ?? ''}`}>{n}</span>
          <span className="t-small">{label}</span>
        </span>
      ))}
    </div>
  );
}

function WatchSwitch({ agent: a }: { agent: AgentView }) {
  const toast = useToast();
  const runtime = a.kind === 'runtime';
  const ignored = a.status !== 'active';
  return (
    <Segmented
      label={`Watch what ${a.name} starts`}
      // What the matcher does: an ignored agent or a runtime is never tagged.
      value={watching(a) ? 'on' : 'off'}
      disabled={runtime || ignored}
      options={[
        { value: 'off', label: 'Off' },
        { value: 'on', label: 'On' },
      ]}
      onChange={async (v) => {
        const on = v === 'on';
        if (on === a.watch) return;
        await vigil.setAgentWatch(a.id, on);
        toast({
          text: on ? `Watching what ${a.name} starts` : `Stopped watching ${a.name}`,
          undo: () => void vigil.setAgentWatch(a.id, !on),
        });
      }}
    />
  );
}

/** A compact row: agents not found here, and ignored ones. */
function AgentLine({ agent: a, go }: { agent: AgentView; go: (route: string) => void }) {
  return (
    <div className="row agent-line">
      <button type="button" className="list-row grow" onClick={() => go(agentRoute(a.id))}>
        <span className="agent-icon sm">{KIND_ICON[a.kind]}</span>
        <span className="t-h3">{a.name}</span>
        <span className="t-small grow ellipsis" title={KIND_WHY[a.kind]}>
          {AGENT_KIND_LABEL[a.kind]}
        </span>
      </button>
      {a.status === 'ignored' ? (
        <Button size="sm" kind="ghost" onClick={() => void vigil.setAgentStatus(a.id, 'active')}>
          {a.origin === 'suggested' ? 'Watch it' : 'Treat as an agent again'}
        </Button>
      ) : (
        <WatchSwitch agent={a} />
      )}
    </div>
  );
}

// ---------------------------------------------------------------- one agent

function AgentPage({
  id,
  session,
  agents,
  links,
  go,
}: {
  id: string;
  session?: string | undefined;
  agents: AgentView[];
  links: AgentLinks;
  go: (route: string) => void;
}) {
  const toast = useToast();
  const [detail, reload] = useLive(() => vigil.getAgent(id), id, 'agents');
  const [rules] = useLive(() => vigil.listRules());
  const [editing, setEditing] = useState(false);
  useEffect(() => setEditing(false), [id]);

  const back = (
    <div className="row">
      <Button size="sm" kind="ghost" icon={<ArrowLeft size={14} />} onClick={() => go('agents')}>
        All agents
      </Button>
    </div>
  );
  if (detail === undefined) return back;
  if (detail === null) {
    return (
      <>
        {back}
        <div className="empty">
          <span className="t-h3">Vigil doesn’t know this agent</span>
          <span className="t-small">It may have been removed.</span>
        </div>
      </>
    );
  }
  const a = detail;
  const views = new Map((rules ?? []).map((r) => [r.rule.id, r]));
  const groups = groupAgentRules(a.rules, (rid) => views.get(rid)?.rule.eventKinds);

  return (
    <>
      {back}
      {a.status === 'suggested' && <Suggestion agent={a} go={go} />}
      <Card>
        <div className="row agent-head">
          <AgentTitle agent={a} large />
        </div>
        <TodayStats agent={a} />
        {KIND_WHY[a.kind] && <span className="t-small">{KIND_WHY[a.kind]}</span>}
        {a.status === 'ignored' && (
          <span className="t-small">
            Ignored: Vigil doesn’t treat it as an agent, so it tags nothing it runs.
          </span>
        )}
        <div className="row spread agent-foot" style={{ flexWrap: 'wrap' }}>
          <div className="row">
            <span className="t-small">Watch what it starts</span>
            <WatchSwitch agent={a} />
          </div>
          <div className="row">
            <Button size="sm" kind="ghost" onClick={() => go(activityRoute({ agent: a.id }))}>
              Its activity
            </Button>
            {a.status === 'active' && (
              <Button
                size="sm"
                kind="ghost"
                onClick={async () => {
                  await vigil.setAgentStatus(a.id, 'ignored');
                  toast({
                    text: `${a.name} is ignored`,
                    undo: () => void vigil.setAgentStatus(a.id, 'active'),
                  });
                }}
              >
                Ignore
              </Button>
            )}
            {a.status === 'ignored' && (
              <Button size="sm" onClick={() => void vigil.setAgentStatus(a.id, 'active')}>
                Treat as an agent again
              </Button>
            )}
            {!a.builtin && (
              <HoldButton
                size="sm"
                icon={<Trash2 size={13} />}
                label="Hold to remove"
                doneLabel="Removed"
                onConfirm={async () => {
                  await vigil.removeAgent(a.id);
                  toast({ text: `${a.name} removed` });
                  go('agents');
                }}
              />
            )}
          </div>
        </div>
      </Card>

      {editing && (
        <Card>
          <AgentForm
            agents={agents}
            initial={a}
            onClose={() => setEditing(false)}
            onSaved={() => {
              setEditing(false);
              reload();
            }}
          />
        </Card>
      )}

      <div className="grid-2">
        <Card>
          <SectionHead
            title="How Vigil recognises it"
            sub="Any one of these is enough. Everything the program starts belongs to the agent."
            right={
              !editing && (
                <Button
                  size="sm"
                  kind="ghost"
                  icon={<Pencil size={13} />}
                  onClick={() => setEditing(true)}
                >
                  Edit
                </Button>
              )
            }
          />
          <div className="col" style={{ gap: 6 }}>
            {a.match.map((m, i) => (
              <div key={i} className="excl-row">
                <span className="grow mono">{describeMatcher(m)}</span>
              </div>
            ))}
          </div>
          {a.edited && (
            <div className="row spread">
              <span className="t-small">You changed Vigil’s built-in matchers.</span>
              <HoldButton
                size="sm"
                icon={<RotateCcw size={13} />}
                label="Hold to reset to built-in"
                doneLabel="Reset"
                onConfirm={async () => {
                  await vigil.resetAgent(a.id);
                  toast({ text: `${a.name} is back to Vigil’s built-in matchers` });
                }}
              />
            </div>
          )}
        </Card>
        <Card>
          <SectionHead
            title="Rules that apply"
            sub="Change a rule’s mode or exclusions on the Rules page."
          />
          <RuleList
            title="On what it starts"
            rules={groups.watch}
            labels={RULE_MODE_LABEL}
            go={go}
          />
          {groups.tool.length > 0 && (
            <RuleList
              title="On the steps it asks about"
              rules={groups.tool}
              labels={TOOL_MODE_LABEL}
              go={go}
            />
          )}
          {groups.raised.length > 0 && (
            <RuleList
              title="Vigil’s own checks"
              rules={groups.raised}
              labels={RAISED_MODE_LABEL}
              go={go}
            />
          )}
        </Card>
      </div>

      <Sessions agent={a} open={session} links={links} go={go} />
    </>
  );
}

const MODE_ORDER: RuleMode[] = ['block', 'alert', 'shadow', 'disabled'];
const modeTone = (m: RuleMode) =>
  m === 'block' ? { tone: 'poor' as const } : m === 'alert' ? { tone: 'fair' as const } : {};

/** One group of rules, folded to a count per mode until opened. */
function RuleList({
  title,
  rules,
  labels,
  go,
}: {
  title: string;
  rules: AgentDetail['rules'];
  labels: Record<RuleMode, string>;
  go: (route: string) => void;
}) {
  const [open, setOpen] = useState(false);
  const counts = MODE_ORDER.map((m) => [m, rules.filter((r) => r.mode === m).length] as const);
  return (
    <div className="col" style={{ gap: 2 }}>
      <button
        type="button"
        className="agent-fold"
        aria-expanded={open}
        disabled={rules.length === 0}
        onClick={() => setOpen(!open)}
      >
        {open ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
        <span className="t-h3 grow">{title}</span>
        {rules.length === 0 && <span className="t-small">None</span>}
        {counts.map(
          ([m, n]) =>
            n > 0 && (
              <Chip key={m} {...modeTone(m)}>
                {n} {labels[m]}
              </Chip>
            ),
        )}
      </button>
      {open &&
        rules.map((r) => (
          <button
            key={r.id}
            type="button"
            className="list-row agent-rule"
            onClick={() => go(`rules/${r.id}`)}
          >
            <span className="grow ellipsis">{r.name}</span>
            <Chip {...modeTone(r.mode)}>{labels[r.mode]}</Chip>
          </button>
        ))}
    </div>
  );
}

const SESSIONS_PAGE = 100;

function Sessions({
  agent,
  open,
  links,
  go,
}: {
  agent: AgentDetail;
  open?: string | undefined;
  links: AgentLinks;
  go: (route: string) => void;
}) {
  const [first] = useLive(() => vigil.listAgentSessions(agent.id), agent.id, 'agents');
  const [older, setOlder] = useState<{ agent: string; rows: AgentSessionView[]; more: boolean }>();
  const pages = older?.agent === agent.id ? older : undefined;
  // The live first page comes first, so new sessions show at the top with fresh counts.
  const list = mergeSessions(first ?? [], pages?.rows ?? []);
  const all = new Set(list.map((s) => s.id));
  const more = pages ? pages.more : (first?.length ?? 0) === SESSIONS_PAGE;
  const toggle = (id: string) => go(agentRoute(agent.id, open === id ? undefined : id));

  const loadOlder = async () => {
    const id = agent.id;
    const page = await loadOlderSessions(
      list,
      (before) => vigil.listAgentSessions(id, { before }),
      SESSIONS_PAGE,
    );
    if (page) setOlder({ agent: id, ...page });
  };

  return (
    <Card>
      <SectionHead
        title="Sessions"
        sub="Each time the agent starts, with everything it ran. Newest first."
      />
      {open && !all.has(open) && (
        <div className="session-open">
          <SessionView id={open} links={links} go={go} />
        </div>
      )}
      {first && list.length === 0 && <span className="t-small">{noSessionsText(agent)}</span>}
      <div className="col" style={{ gap: 0 }}>
        {list.map((s) => (
          <div key={s.id} className={`session-row ${open === s.id ? 'open' : ''}`}>
            <button
              type="button"
              className="list-row"
              aria-expanded={open === s.id}
              onClick={() => toggle(s.id)}
            >
              {open === s.id ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
              <span className="col grow" style={{ gap: 1 }}>
                <span className="row" style={{ gap: 8 }}>
                  <span className="t-h3 nowrap">{clock(s.startedAt)}</span>
                  <span className="t-small mono ellipsis">{s.rootPath}</span>
                </span>
                <span className="t-small">
                  {plural(s.events, 'event')} · last activity {timeAgo(s.lastAt)}
                  {s.seeded && ' · already running when Vigil started'}
                  {s.parentSession && ' · started by another agent'}
                </span>
              </span>
              {s.matches > 0 && <Chip tone="fair">{plural(s.matches, 'match', 'matches')}</Chip>}
              {s.asks > 0 && <Chip tone="accent">{s.asks} asked</Chip>}
              {s.denies > 0 && <Chip tone="poor">{s.denies} stopped</Chip>}
            </button>
            {open === s.id && (
              <div className="session-open">
                <SessionView id={s.id} links={links} go={go} />
              </div>
            )}
          </div>
        ))}
      </div>
      {more && (
        <div className="row" style={{ justifyContent: 'center' }}>
          <Button size="sm" kind="ghost" onClick={() => void loadOlder()}>
            Show older sessions
          </Button>
        </div>
      )}
    </Card>
  );
}

/** One session: the programs it started, as a tree, and its newest events. */
function SessionView({
  id,
  links,
  go,
}: {
  id: string;
  links: AgentLinks;
  go: (route: string) => void;
}) {
  const [d] = useLive(() => vigil.getAgentSession(id), id, 'agents');
  const [openEvent, setOpenEvent] = useState<string>();
  if (d === undefined) return <span className="t-small">Loading…</span>;
  if (d === null) return <span className="t-small">This session is no longer stored.</span>;
  const s = d.session;
  return (
    <div className="col" style={{ gap: 12 }}>
      <div className="row spread">
        <span className="t-small">
          Started {clock(s.startedAt)} as process {s.rootPid}. {plural(s.events, 'event')},{' '}
          {plural(s.matches, 'rule match', 'rule matches')}.
        </span>
        <Button size="sm" kind="ghost" onClick={() => go(activityRoute({ session: id }))}>
          Open in Activity
        </Button>
      </div>
      <div className="col" style={{ gap: 6 }}>
        <span className="t-label">What it started</span>
        <ProcessTree nodes={d.tree} />
      </div>
      <div className="col" style={{ gap: 6 }}>
        <span className="t-label">Events{d.events.length >= 500 ? ', the newest 500' : ''}</span>
        {d.events.length === 0 ? (
          <span className="t-small">No events stored for this session.</span>
        ) : (
          <Card tight className="feed">
            {d.events.map((v) => (
              <EventRow
                key={v.event.id}
                view={v}
                open={openEvent === v.event.id}
                onToggle={() => setOpenEvent(openEvent === v.event.id ? undefined : v.event.id)}
                links={links}
              />
            ))}
          </Card>
        )}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------- tool policy

function ToolPolicy() {
  const [rules] = useLive(() => vigil.listRules());
  const [picking, setPicking] = useState(false);
  const [draft, setDraft] = useState<string>();
  const [editing, setEditing] = useState<string>();
  const tool = (rules ?? []).filter((r) => r.rule.eventKinds.includes('agent.tool_request'));
  const taken = new Set((rules ?? []).map((r) => r.rule.id));

  return (
    <>
      <Card>
        <SectionHead
          title="Claude Code pre-flight checks"
          sub="Before a step runs, Claude Code’s hook asks Vigil and the rules below answer."
        />
        <PreflightSetup />
      </Card>
      <Card>
        <SectionHead
          title="Tool rules"
          sub="Ask makes Claude Code ask you before the step, Deny stops it, Record only logs it. A step no rule matches is left to Claude Code."
          right={
            <Button
              size="sm"
              icon={<Plus size={14} />}
              aria-expanded={picking}
              onClick={() => setPicking(!picking)}
            >
              New tool rule
            </Button>
          }
        />
        {picking && (
          <Templates
            taken={taken}
            onPick={(json) => {
              setDraft(json);
              setPicking(false);
            }}
          />
        )}
        {draft && (
          <div className="tool-draft">
            <NewRulePanel key={draft} initial={draft} onClose={() => setDraft(undefined)} />
          </div>
        )}
        <div className="col" style={{ gap: 8 }}>
          {tool.map((r) => (
            <ToolRuleRow
              key={r.rule.id}
              view={r}
              editing={editing === r.rule.id}
              onEdit={(on) => setEditing(on ? r.rule.id : undefined)}
            />
          ))}
        </div>
      </Card>
      <Card>
        <SectionHead
          title="Vigil tools for your agents (advanced)"
          sub="Your own agent can read Vigil’s alerts and activity. It can’t change anything."
        />
        <AgentToolsSetup />
      </Card>
    </>
  );
}

function Templates({
  taken,
  onPick,
}: {
  taken: ReadonlySet<string>;
  onPick: (json: string) => void;
}) {
  return (
    <div className="col" style={{ gap: 8 }}>
      <span className="t-small">
        Start from one of these. It opens in the rule editor, where Check replays it over the steps
        Vigil has stored before you save it.
      </span>
      <div className="template-grid">
        {TOOL_RULE_TEMPLATES.map((t) => (
          <TemplateCard key={t.id} template={t} taken={taken} onPick={onPick} />
        ))}
      </div>
    </div>
  );
}

function TemplateCard({
  template: t,
  taken,
  onPick,
}: {
  template: ToolRuleTemplate;
  taken: ReadonlySet<string>;
  onPick: (json: string) => void;
}) {
  const [raw, setRaw] = useState('');
  const [bad, setBad] = useState(false);
  const use = () => {
    if (!t.input) return onPick(t.json(taken));
    const value = t.input.clean(raw);
    setBad(!value);
    if (value) onPick(t.json(taken, value));
  };
  return (
    <div className="template">
      <span className="t-h3">{t.title}</span>
      <span className="t-small grow">{t.description}</span>
      {t.input && (
        <input
          className="field"
          aria-label={t.input.label}
          aria-invalid={bad || undefined}
          aria-describedby={bad ? `${t.id}-hint` : undefined}
          placeholder={t.input.placeholder}
          value={raw}
          onChange={(e) => setRaw(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter') use();
          }}
        />
      )}
      {bad && t.input && (
        <span id={`${t.id}-hint`} className="t-small warn-text" role="alert">
          {t.input.hint}
        </span>
      )}
      <div className="row">
        <Button size="sm" disabled={!!t.input && !raw.trim()} onClick={use}>
          Open in editor
        </Button>
      </div>
    </div>
  );
}

function ToolRuleRow({
  view,
  editing,
  onEdit,
}: {
  view: RuleView;
  editing: boolean;
  onEdit: (on: boolean) => void;
}) {
  const { rule, matches } = view;
  const toast = useToast();
  const [confirmDeny, setConfirmDeny] = useState(false);

  const set = async (mode: RuleMode) => {
    // Picking anything else dismisses a Deny confirmation still showing.
    const confirm = confirmsFirst(rule.mode, mode);
    setConfirmDeny(confirm);
    if (confirm) return;
    const before = rule.mode;
    await vigil.setRuleMode(rule.id, mode);
    toast({
      text: `${rule.name}: ${modeLabel(rule, mode)}`,
      undo: () => void vigil.setRuleMode(rule.id, before),
    });
  };

  return (
    <div className="tool-rule">
      <div className="row">
        <div className="col grow" style={{ gap: 2 }}>
          <div className="row">
            <span className="t-h3 ellipsis">{rule.name}</span>
            {rule.origin === 'ai' && <Chip tone="ai">AI-drafted</Chip>}
            {rule.origin === 'user' && <Chip>Yours</Chip>}
          </div>
          <span className="t-small clamp-2" title={rule.description}>
            {rule.description}
          </span>
        </div>
        <span className="tool-rule-sev">
          <SeverityMark severity={rule.severity} />
        </span>
        <span
          className="t-small nowrap tool-rule-count"
          title="Matches in the last 14 days, in any mode"
        >
          {matches} in 14 days
        </span>
        <span className="tool-rule-mode">
          <Segmented
            label={`What ${rule.name} does`}
            value={rule.mode}
            options={modesFor(rule)}
            onChange={(m) => void set(m)}
          />
        </span>
        <Button
          size="sm"
          kind={editing ? 'secondary' : 'ghost'}
          icon={<Pencil size={13} />}
          aria-expanded={editing}
          title={`Edit ${rule.name}`}
          onClick={() => onEdit(!editing)}
        >
          {editing ? 'Close' : 'Edit'}
        </Button>
      </div>
      {confirmDeny && rule.mode !== 'block' && (
        <div className="attn poor">
          <span className="grow">
            In Deny mode Claude Code stops every step this rule matches, without asking you.
          </span>
          <button type="button" className="btn sm ghost" onClick={() => setConfirmDeny(false)}>
            Cancel
          </button>
          <HoldButton
            size="sm"
            label="Hold to turn on Deny"
            doneLabel="Denying"
            onConfirm={async () => {
              await vigil.setRuleMode(rule.id, 'block');
              setConfirmDeny(false);
            }}
          />
        </div>
      )}
      {editing && <RuleEditorPanel id={rule.id} onClose={() => onEdit(false)} />}
    </div>
  );
}

// ---------------------------------------------------------------- Vigil's AI helpers

const HELPER_WHAT: Record<VigilHelperId, string> = {
  explainer: 'Explains an alert in plain words when it comes in, or when you ask.',
  labeller: 'Marks events no rule matched as unusual or suspicious. Hints only, shown in Activity.',
  'rule-reviewer':
    'About once a day, reads a redacted summary of recent activity and drafts rules. They start in Shadow until you approve them.',
};

function Helpers({ go }: { go: (route: string) => void }) {
  const [helpers] = useLive(() => vigil.listVigilHelpers());
  return (
    <>
      <div className="attn accent">
        <Sparkles size={16} />
        <span className="grow">
          Vigil’s own AI helpers. They read and propose. They never act: rules do the blocking, and
          you decide.
        </span>
      </div>
      <div className="helper-grid">
        {(helpers ?? []).map((h) => (
          <Card key={h.id} tight className="helper-card">
            <div className="row">
              <span className="agent-icon ai">
                <Sparkles size={16} />
              </span>
              <span className="col grow" style={{ gap: 2 }}>
                <span className="t-h3">{h.name}</span>
                <span className="t-small">{HELPER_WHAT[h.id]}</span>
              </span>
            </div>
            <dl className="kv">
              <dt>Uses</dt>
              <dd className="row" style={{ gap: 4, flexWrap: 'wrap' }}>
                {h.providers.map((p) => (
                  <Chip key={p}>{PROVIDER_LABEL[p as UsageProvider] ?? p}</Chip>
                ))}
              </dd>
              <dt>Tools</dt>
              <dd className="row" style={{ gap: 4, flexWrap: 'wrap' }}>
                {h.tools.length === 0 ? (
                  <span className="t-small">None. It sees only what Vigil hands it.</span>
                ) : (
                  h.tools.map((t) => (
                    <code key={t} className="mono helper-tool">
                      {t}
                    </code>
                  ))
                )}
              </dd>
              <dt>Last run</dt>
              <dd>{h.lastRunAt ? timeAgo(h.lastRunAt) : 'Not yet'}</dd>
              <dt>Last 7 days</dt>
              <dd>{plural(h.runs7d, 'run')}</dd>
            </dl>
          </Card>
        ))}
      </div>
      <div className="row" style={{ flexWrap: 'wrap' }}>
        <span className="t-small grow">
          Which AI apps they may use is set in Settings; what their runs cost is on the Usage page.
          Their tools only read: none can run a command, change a rule or release a block.
        </span>
        <Button size="sm" kind="ghost" onClick={() => go('settings')}>
          Settings
        </Button>
        <Button size="sm" kind="ghost" onClick={() => go('usage')}>
          Usage
        </Button>
      </div>
    </>
  );
}
