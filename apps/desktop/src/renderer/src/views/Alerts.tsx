import type { Alert, SensorEvent } from '@vigil/core';
import { Bell, BookOpen, Copy, ListChecks, RotateCcw, Sparkles, VolumeX } from 'lucide-react';
import { Fragment, useEffect, useRef, useState } from 'react';
import type { AlertDetail as AlertDetailT } from '../../../shared/ipc';
import { useLive, vigil } from '../api';
import { DecisionControls, type Decided } from '../components/Decision';
import { NotebookSheet } from '../components/Notebook';
import { PileBox } from '../components/Pile';
import { pileUp } from '../../../shared/piles';
import { useToast } from '../components/Toasts';
import { toolRequestFields } from '../components/ToolRequestFields';
import { Button, Card, Chip, SectionHead, SeverityMark, StatusMark } from '../components/ui';
import { evidenceSub, isHookRequest, realProcess, STOPPED_ANSWER } from '../evidence';
import { actorLabel, clock, describeAction, describeEvent, seenTimes, timeAgo } from '../format';
import { helperNote, PASSWORD_CANCELLED } from '../format';
import { modeLabel, quieterMode } from '../rule-modes';
import { ExcludeFromAlert } from '../components/ExcludeFromAlert';
import { useAgentLinks, type AgentLinks } from './Activity';
import { PageHead } from './AppShell';
import { onRovingKeyDown } from '../components/roving';
import { shownAlert, tabFor } from './alerts-selection';

export function AlertsView({
  selected,
  go,
}: {
  selected: string | undefined;
  go: (r: string) => void;
}) {
  const [tab, setTab] = useState<'open' | 'resolved'>('open');
  const [open] = useLive(() => vigil.listAlerts('open'));
  const [resolved] = useLive(() => vigil.listAlerts('resolved'));
  // The lists hold the newest alerts only; the tabs count them all.
  const [counts] = useLive(() => vigil.alertCounts());
  const total = counts?.[tab];
  const list = (tab === 'open' ? open : resolved) ?? [];
  const current = shownAlert(selected, list);

  // An alert opened by link (from History, Home or a popup) brings up the tab
  // it is in. Only when the link changes: deciding an alert moves it out of
  // Open, and then the next open one shows instead of jumping tabs.
  const synced = useRef<string | undefined>(undefined);
  useEffect(() => {
    if (!selected || synced.current === selected) return;
    const t = tabFor(selected, open, resolved);
    if (!t) return;
    synced.current = selected;
    setTab(t);
  }, [selected, open, resolved]);

  return (
    <div className="page">
      <PageHead
        title="Alerts"
        purpose="Everything Vigil flagged. Blocks happen first; you decide whether they stay."
      />
      <div className="tabs" role="tablist" onKeyDown={onRovingKeyDown}>
        <button
          type="button"
          role="tab"
          aria-selected={tab === 'open'}
          tabIndex={tab === 'open' ? 0 : -1}
          onClick={() => setTab('open')}
        >
          Open <span className="count">{counts?.open ?? open?.length ?? 0}</span>
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={tab === 'resolved'}
          tabIndex={tab === 'resolved' ? 0 : -1}
          onClick={() => setTab('resolved')}
        >
          Resolved <span className="count">{counts?.resolved ?? resolved?.length ?? 0}</span>
        </button>
      </div>
      {tab === 'open' && <StaleBanner />}
      <div className="split">
        <div className="list split-list scroll">
          {list.length === 0 && (
            <div className="empty">
              <span className="empty-icon">
                <Bell size={20} />
              </span>
              <span className="t-h3">
                {tab === 'open' ? 'No open alerts' : 'Nothing resolved yet'}
              </span>
            </div>
          )}
          {total !== undefined && total > list.length && list.length > 0 && (
            <span className="t-small list-note">
              Showing the newest {list.length} of {total.toLocaleString()}.
            </span>
          )}
          {pileUp(list).map((r) => {
            const a = r.kind === 'alert' ? r.alert : r.alerts[0]!;
            const ids = r.kind === 'alert' ? [a.id] : r.alerts.map((x) => x.id);
            return (
              <AlertRow
                key={a.id}
                alert={a}
                pile={r.kind === 'pile' ? `${r.who} · ${r.alerts.length} times` : undefined}
                current={!!current && ids.includes(current)}
                onClick={() => go(`alerts/${a.id}`)}
              />
            );
          })}
        </div>
        <div className="split-detail">
          {current ? <AlertDetailView id={current} go={go} /> : null}
        </div>
      </div>
    </div>
  );
}

/**
 * Open alerts a rule no longer raises: an update or an exclusion made the
 * rule quieter after they came in. One tap closes them; nothing is held
 * back by them, and the rules learn nothing from it.
 */
function StaleBanner() {
  const [stale] = useLive(() => vigil.staleAlerts());
  const toast = useToast();
  const [busy, setBusy] = useState(false);
  if (!stale?.length) return null;
  const n = stale.length;
  return (
    <div className="attn accent">
      <span className="grow">
        {n} open {n === 1 ? 'alert is' : 'alerts are'} no longer flagged by{' '}
        {n === 1 ? 'its rule' : 'their rules'}: a rule update or an exclusion now lets{' '}
        {n === 1 ? 'it' : 'them'} off.
      </span>
      <Button
        size="sm"
        kind="primary"
        disabled={busy}
        onClick={async () => {
          setBusy(true);
          try {
            const done = await vigil.clearStale(stale);
            toast({ text: `Closed ${done} ${done === 1 ? 'alert' : 'alerts'}` });
          } finally {
            setBusy(false);
          }
        }}
      >
        Close {n === 1 ? 'it' : `all ${n}`}
      </Button>
    </div>
  );
}

function AlertRow({
  alert,
  pile,
  current,
  onClick,
}: {
  alert: Alert;
  /** For a pile's row: who and how many. */
  pile?: string | undefined;
  current: boolean;
  onClick: () => void;
}) {
  return (
    <button type="button" className="list-row" aria-current={current} onClick={onClick}>
      <div className="col grow" style={{ gap: 3 }}>
        <span className="t-h3 clamp-2" title={alert.title}>
          {alert.title}
        </span>
        <span className="row t-small">
          <SeverityMark severity={alert.severity} />
          {pile && <span>· {pile}</span>}
          <span>· {timeAgo(alert.createdAt)}</span>
          {seenTimes(alert) && <Chip>{seenTimes(alert)}</Chip>}
          {alert.containment === 'active' && <Chip tone="good">Blocked</Chip>}
          {alert.ai && <Chip tone="ai">AI read</Chip>}
        </span>
      </div>
    </button>
  );
}

function AlertDetailView({ id, go }: { id: string; go: (r: string) => void }) {
  const [detail] = useLive(() => vigil.getAlertDetail(id), id);
  const toast = useToast();
  const links = useAgentLinks(go);
  if (!detail) return null;
  const { alert, events, actions, proposals, rule } = detail;
  const pending = proposals.filter((p) => p.status === 'pending');
  const contained = alert.containment === 'active';

  const decided = (d: Decided) =>
    toast({
      text: {
        kept: 'Kept as it is',
        released: 'Done, and marked safe',
        contained: 'Done',
        fine: 'Marked as fine',
        expected: 'Marked as you',
      }[d],
      undo: d === 'released' || d === 'contained' ? undefined : () => void vigil.reopen(alert.id),
    });

  return (
    <div className="col" style={{ gap: 14 }}>
      <Card>
        <div className="row">
          <SeverityMark severity={alert.severity} />
          {seenTimes(alert) && <Chip>{seenTimes(alert)}</Chip>}
          {contained && <Chip tone="good">Blocked</Chip>}
          {alert.containment === 'released' && <Chip tone="fair">Released</Chip>}
          {alert.status === 'resolved' && <Chip>Resolved</Chip>}
          <span className="grow" />
          {!alert.ai && <ExplainButton alertId={alert.id} />}
          <span className="t-small">{clock(alert.createdAt)}</span>
        </div>
        <h2 className="t-title">{alert.title}</h2>
        <p style={{ margin: 0 }}>{alert.summary}</p>
        {alert.subject?.path && <div className="subject mono">{alert.subject.path}</div>}

        {alert.status === 'open' ? (
          <DecisionControls
            alert={alert}
            actions={actions}
            proposals={proposals}
            onDecided={decided}
          />
        ) : (
          <div className="row">
            <span className="t-small">
              You marked this {alert.decision?.verdict}
              {alert.decision ? ` ${timeAgo(alert.decision.at)}` : ''}.
            </span>
            <Button
              size="sm"
              kind="ghost"
              icon={<RotateCcw size={13} />}
              onClick={() => void vigil.reopen(alert.id)}
            >
              Reopen
            </Button>
          </div>
        )}
        {alert.status === 'open' && (
          <PileBox
            alert={alert}
            onDone={(n) => toast({ text: `Closed ${n} ${n === 1 ? 'alert' : 'alerts'}` })}
          />
        )}
      </Card>

      {alert.ai && (
        <Card>
          <SectionHead
            title="AI opinion"
            sub={`${alert.ai.provider}${alert.ai.model ? ` · ${alert.ai.model}` : ''} · advisory, may be wrong`}
            right={
              <div className="row">
                <WhyButton alertId={alert.id} />
                <ExplainButton alertId={alert.id} again />
                <Chip tone="ai">
                  <Sparkles size={12} /> {alert.ai.verdict.replace('_', ' ')}
                </Chip>
              </div>
            }
          />
          <p style={{ margin: 0 }}>{alert.ai.summary}</p>
          {alert.ai.details && (
            <p className="t-small" style={{ margin: 0, whiteSpace: 'pre-wrap' }}>
              {alert.ai.details}
            </p>
          )}
        </Card>
      )}
      {(actions.length > 0 || proposals.length > 0) && (
        <Card>
          <SectionHead title="Response" sub="What was done, and what was suggested" />
          {actions.map((r) => (
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
              <span className="grow ellipsis">
                {describeAction(r.action)}
                {r.result?.error ? <span className="t-small"> · {r.result.error}</span> : null}
              </span>
              <span className="t-small">{actorLabel(r.actor)}</span>
              {r.status === 'done' && !r.undoes && isUndoable(r.action.kind) && (
                <Button
                  size="sm"
                  kind="ghost"
                  onClick={async () => {
                    const out = await vigil.undoAction(r.id);
                    toast({
                      text:
                        out.status === 'done'
                          ? `Undone: ${describeAction(r.action)}`
                          : `Couldn’t undo: ${describeAction(r.action)}. It’s still in force.`,
                    });
                  }}
                >
                  Undo
                </Button>
              )}
            </div>
          ))}
          {pending.map((p) => (
            <div key={p.id} className="row">
              <StatusMark state="pending" label="Suggested" />
              <span className="grow ellipsis">
                {describeAction(p.action)}{' '}
                <span className="t-small">· suggested by {actorLabel(p.proposedBy)}</span>
              </span>
              <Button size="sm" kind="primary" onClick={() => void vigil.approveProposal(p.id)}>
                Do it
              </Button>
              <Button size="sm" kind="ghost" onClick={() => void vigil.rejectProposal(p.id)}>
                Skip
              </Button>
            </div>
          ))}
        </Card>
      )}

      <Card>
        <SectionHead
          title="Evidence"
          sub={evidenceSub(events)}
          right={
            <Button
              size="sm"
              kind="ghost"
              icon={<Copy size={13} />}
              title="Copy the alert, its events and what was done, as JSON"
              onClick={async () => {
                try {
                  await navigator.clipboard.writeText(evidenceJson(detail));
                  toast({ text: 'Copied the evidence as JSON' });
                } catch {
                  toast({ text: 'Couldn’t copy to the clipboard' });
                }
              }}
            >
              Copy
            </Button>
          }
        />
        {events.map((e) => (
          <EventBlock key={e.id} event={e} links={links} />
        ))}
      </Card>

      {rule && <RuleCard alert={alert} rule={rule} go={go} />}

      {events[0] && (
        <ExcludeFromAlert
          alertId={alert.id}
          ruleId={alert.ruleId}
          event={events[0]}
          onEditRule={() => go(`rules/${alert.ruleId}`)}
        />
      )}
    </div>
  );
}

/** How the alert reached the user, as its notify level says. */
const REACHED: Record<Alert['notify'], { text: string; title: string }> = {
  popup: { text: 'Popped up', title: 'This alert showed a popup' },
  badge: { text: 'Badge only', title: 'This alert added to the menu-bar badge, without a popup' },
  silent: { text: 'Quiet', title: 'This alert only landed here: no popup, no badge' },
};

/**
 * The rule behind an alert: a link to it, how its alert reached the user,
 * and, for a rule that alerts too often, the way to turn it down to Shadow
 * (Record), where its matches still show in Activity.
 */
function RuleCard({
  alert,
  rule,
  go,
}: {
  alert: Alert;
  rule: NonNullable<AlertDetailT['rule']>;
  go: (r: string) => void;
}) {
  const toast = useToast();
  const quieter = quieterMode(rule);
  const reached = REACHED[alert.notify];
  const quiet = async () => {
    if (!quieter) return;
    const before = rule.mode;
    const { helper } = await vigil.setRuleMode(rule.id, quieter);
    if (helper === 'declined') {
      toast({ text: `${rule.name}: ${PASSWORD_CANCELLED}` });
      return;
    }
    toast({
      text: `${rule.name}: ${modeLabel(rule, quieter)}. It stops alerting and keeps logging matches in Activity.${helperNote(helper)}`,
      undo: () => void vigil.setRuleMode(rule.id, before),
    });
  };
  return (
    <Card tight>
      <div className="row" style={{ flexWrap: 'wrap' }}>
        <span className="t-label">Rule</span>
        <span className="grow t-h3">{rule.name}</span>
        <Chip>{modeLabel(rule, rule.mode)}</Chip>
        <Chip>{rule.fidelity} fidelity</Chip>
        <Chip title={reached.title}>{reached.text}</Chip>
        {rule.origin === 'ai' && <Chip tone="ai">AI-drafted</Chip>}
      </div>
      <span className="t-small">{rule.description}</span>
      <div className="row" style={{ flexWrap: 'wrap' }}>
        <Button
          size="sm"
          kind="ghost"
          icon={<ListChecks size={13} />}
          onClick={() => go(`rules/${rule.id}`)}
        >
          Open rule
        </Button>
        <Button
          size="sm"
          kind="ghost"
          icon={<Bell size={13} />}
          title="Every event this rule matched, newest first"
          onClick={() => go(`activity/rule-${rule.id}`)}
        >
          Its matches in Activity
        </Button>
        {quieter && (
          <Button
            size="sm"
            kind="ghost"
            icon={<VolumeX size={13} />}
            title={`Too noisy? ${modeLabel(rule, quieter)} only logs what this rule matches; it raises no alert.`}
            onClick={() => void quiet()}
          >
            Only log this rule
          </Button>
        )}
      </div>
    </Card>
  );
}

/** The alert as JSON for a bug report, a note or another tool. */
function evidenceJson(d: AlertDetailT): string {
  const { alert, events, actions, proposals, rule } = d;
  return JSON.stringify(
    {
      alert,
      rule: rule
        ? { id: rule.id, name: rule.name, version: rule.version, mode: rule.mode }
        : undefined,
      events,
      actions,
      proposals,
    },
    null,
    2,
  );
}

function isUndoable(kind: string): boolean {
  return [
    'process.suspend',
    'network.block',
    'file.quarantine',
    'santa.rule.set',
    'persistence.disable',
  ].includes(kind);
}

function EventBlock({ event, links }: { event: SensorEvent; links: AgentLinks }) {
  // A tool request's process is only the shell it would have started, never a real one.
  const p = realProcess(event);
  return (
    <div className="event">
      <div className="row spread">
        <span className="t-h3">{describeEvent(event)}</span>
        <span className="t-small">
          {event.source} · {clock(event.ts)}
        </span>
      </div>
      <dl className="kv">
        {event.kind === 'agent.tool_request' &&
          toolRequestFields(event, links).map(([k, v]) => (
            <Fragment key={k}>
              <dt>{k}</dt>
              <dd>{v}</dd>
            </Fragment>
          ))}
        {isHookRequest(event) && (
          <>
            <dt>Answer</dt>
            <dd>{STOPPED_ANSWER}</dd>
          </>
        )}
        {p && (
          <>
            <dt>Program</dt>
            <dd className="mono">{p.path}</dd>
            {p.args && (
              <>
                <dt>Command line</dt>
                <dd className="mono">{p.args.join(' ')}</dd>
              </>
            )}
            <dt>Process</dt>
            <dd>
              {p.pid}
              {p.parentPath ? ` · started by ${p.parentPath}` : ''}
            </dd>
            {p.signing && (
              <>
                <dt>Signed</dt>
                <dd>
                  {p.signing.replace('_', ' ')}
                  {p.teamId ? ` · team ${p.teamId}` : ''}
                </dd>
              </>
            )}
            {p.sha256 && (
              <>
                <dt>SHA-256</dt>
                <dd className="mono">{p.sha256}</dd>
              </>
            )}
          </>
        )}
        {event.kind === 'network.connection' && (
          <>
            <dt>Remote</dt>
            <dd className="mono">
              {event.remoteAddress}
              {event.remotePort ? `:${event.remotePort}` : ''}
              {event.remoteHost ? ` (${event.remoteHost})` : ''}
            </dd>
          </>
        )}
        {(event.kind === 'file' || event.kind === 'persistence') && (
          <>
            <dt>Path</dt>
            <dd className="mono">{event.path}</dd>
          </>
        )}
      </dl>
    </div>
  );
}

/**
 * Asks Vigil to explain this alert now. The one place Vigil may use the
 * user's Claude plan, and only when they've turned it on in Settings › AI.
 */
/** The explainer's notebook entries for this alert: what it looked at and why it said so. */
function WhyButton({ alertId }: { alertId: string }) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <Button size="sm" kind="ghost" icon={<BookOpen size={13} />} onClick={() => setOpen(true)}>
        Why?
      </Button>
      {open && (
        <NotebookSheet
          title="Why the AI said this"
          filter={{ subject: { kind: 'alert', id: alertId } }}
          onClose={() => setOpen(false)}
        />
      )}
    </>
  );
}

function ExplainButton({ alertId, again = false }: { alertId: string; again?: boolean }) {
  const [plan] = useLive(async () => (await vigil.getAiPrefs()).claudePlan);
  const [busy, setBusy] = useState(false);
  const toast = useToast();
  const label = plan ? 'Explain with my Claude plan' : again ? 'Ask again' : 'Explain';
  return (
    <Button
      size="sm"
      kind="ghost"
      icon={<Sparkles size={13} />}
      disabled={busy}
      onClick={async () => {
        setBusy(true);
        try {
          const r = await vigil.explainAlert(alertId);
          if (!r.ok) toast({ text: r.error ?? 'No AI could explain it right now' });
        } finally {
          setBusy(false);
        }
      }}
    >
      {busy ? 'Asking…' : label}
    </Button>
  );
}
