import type { Alert, SensorEvent } from '@vigil/core';
import { Bell, RotateCcw, Sparkles } from 'lucide-react';
import { useState } from 'react';
import { useLive, vigil } from '../api';
import { DecisionControls, type Decided } from '../components/Decision';
import { useToast } from '../components/Toasts';
import { Button, Card, Chip, SectionHead, SeverityMark, StatusMark } from '../components/ui';
import { actorLabel, clock, describeAction, describeEvent, timeAgo } from '../format';
import { ExcludeFromAlert } from '../components/ExcludeFromAlert';
import { PageHead } from './AppShell';

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
  const list = (tab === 'open' ? open : resolved) ?? [];
  const current = selected ?? list[0]?.id;

  return (
    <div className="page">
      <PageHead
        title="Alerts"
        purpose="Everything Vigil flagged. Blocks happen first; you decide whether they stay."
      />
      <div className="tabs" role="tablist">
        <button
          type="button"
          role="tab"
          aria-selected={tab === 'open'}
          onClick={() => setTab('open')}
        >
          Open <span className="count">{open?.length ?? 0}</span>
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={tab === 'resolved'}
          onClick={() => setTab('resolved')}
        >
          Resolved <span className="count">{resolved?.length ?? 0}</span>
        </button>
      </div>
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
          {list.map((a) => (
            <AlertRow
              key={a.id}
              alert={a}
              current={a.id === current}
              onClick={() => go(`alerts/${a.id}`)}
            />
          ))}
        </div>
        <div className="split-detail">
          {current ? <AlertDetailView id={current} go={go} /> : null}
        </div>
      </div>
    </div>
  );
}

function AlertRow({
  alert,
  current,
  onClick,
}: {
  alert: Alert;
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
          <span>· {timeAgo(alert.createdAt)}</span>
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
      </Card>

      {alert.ai && (
        <Card>
          <SectionHead
            title="AI opinion"
            sub={`${alert.ai.provider}${alert.ai.model ? ` · ${alert.ai.model}` : ''} · advisory, may be wrong`}
            right={
              <div className="row">
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
          sub={`${events.length} event${events.length === 1 ? '' : 's'} from the sensors`}
        />
        {events.map((e) => (
          <EventBlock key={e.id} event={e} />
        ))}
      </Card>

      {rule && (
        <Card tight>
          <div className="row">
            <span className="t-label">Rule</span>
            <span className="grow t-h3">{rule.name}</span>
            <Chip>{rule.mode}</Chip>
            <Chip>{rule.fidelity} fidelity</Chip>
            {rule.origin === 'ai' && <Chip tone="ai">AI-drafted</Chip>}
          </div>
          <span className="t-small">{rule.description}</span>
        </Card>
      )}

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

function isUndoable(kind: string): boolean {
  return [
    'process.suspend',
    'network.block',
    'file.quarantine',
    'santa.rule.set',
    'persistence.disable',
  ].includes(kind);
}

function EventBlock({ event }: { event: SensorEvent }) {
  const p = 'process' in event ? event.process : undefined;
  return (
    <div className="event">
      <div className="row spread">
        <span className="t-h3">{describeEvent(event)}</span>
        <span className="t-small">
          {event.source} · {clock(event.ts)}
        </span>
      </div>
      <dl className="kv">
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
