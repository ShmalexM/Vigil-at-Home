import { CircleCheck, TriangleAlert } from 'lucide-react';
import { useState } from 'react';
import { useLive, vigil } from '../api';
import { homeMood } from '../components/AskScout';
import { NoticedList, WatchLine } from '../components/Attention';
import { Dog } from '../components/Dog';
import { Card, Chip, LevelPill, SectionHead, SeverityMark, StatusMark } from '../components/ui';
import { actorLabel, describeRecord, timeAgo } from '../format';
import { isNoticed, needsDecision } from '../../../shared/attention';
import { LEVEL_RULES } from '../../../shared/levels';
import { leadChat } from '../lead-chat';
import { PageHead } from './AppShell';
import { usePack } from './Pack';

const levelSentence = {
  good: 'Protection is on. Nothing needs you.',
  fair: 'Something needs a look.',
  poor: 'Something needs you now.',
};

export function HomeView({ go }: { go: (r: string) => void }) {
  const [status] = useLive(() => vigil.getStatus());
  const [alerts] = useLive(() => vigil.listAlerts('open'));
  const [actions] = useLive(() => vigil.listActions());
  const needs = (alerts ?? []).filter(needsDecision);
  const noticed = (alerts ?? []).filter(isNoticed);
  const allRunning = !!status && status.sensors.every((s) => s.state === 'ok');
  const [pack] = usePack({ settings: false });
  const lead = pack?.dogs.find((d) => d.role === 'lead');
  // Ears up for a decision, or for protection that has stopped; a layer that
  // was never installed is the status line's to explain, not a reason to fret.
  const scout = homeMood(pack, !!status && (status.needsYou > 0 || status.level === 'poor'));

  return (
    <div className="page">
      <PageHead
        title="Home"
        purpose="How your Mac is doing, and anything that needs your decision."
      />

      {status && (
        <Card>
          <div className="home-status">
            <LevelPill level={status.level} />
            <span className="t-h2">{levelSentence[status.level]}</span>
            {lead && (
              <button
                type="button"
                className="home-scout"
                title={`${lead.name}: ${scout.says}. Ask ${lead.name}`}
                aria-label={`Ask ${lead.name}`}
                onClick={leadChat.open}
              >
                <Dog breed={lead.breed} mood={scout.mood} size={96} />
              </button>
            )}
          </div>
          <WatchLine watch={status.watch} />
          {status.reasons.length > 0 && (
            <ul className="reasons">
              {status.reasons.map((r) => (
                <li key={r}>{r}</li>
              ))}
            </ul>
          )}
          <details className="level-rules">
            <summary>How is this worked out?</summary>
            <ul>
              {(['poor', 'fair', 'good'] as const).map((l) => (
                <li key={l} className={l === status.level ? 'current' : ''}>
                  <LevelPill level={l} small /> {LEVEL_RULES[l]}
                </li>
              ))}
            </ul>
            <p className="t-small">
              The first reason above is the one that sets the level. Protection layers are Santa,
              osquery and the Vigil helper.
            </p>
          </details>
          {status.dryRun && (
            <div className="attn fair">
              <TriangleAlert size={17} />
              <span>
                Blocks are simulated until the Vigil helper is installed. Vigil logs what it would
                have done.
              </span>
            </div>
          )}
        </Card>
      )}

      <div className="grid-2">
        <Card>
          <SectionHead title="Needs you" sub="Alerts waiting on your decision, newest first" />
          {needs.length === 0 ? (
            <div className="row t-small">
              <CircleCheck size={16} color="var(--good)" /> Nothing right now.
            </div>
          ) : (
            <div className="list">
              {needs.slice(0, 6).map((a) => (
                <button
                  key={a.id}
                  type="button"
                  className="list-row"
                  onClick={() => go(`alerts/${a.id}`)}
                >
                  <SeverityMark severity={a.severity} />
                  <span className="grow clamp-2 t-h3" title={a.title}>
                    {a.title}
                  </span>
                  {a.containment === 'active' && <Chip tone="good">Blocked</Chip>}
                  <span className="t-small nowrap">{timeAgo(a.createdAt)}</span>
                </button>
              ))}
            </div>
          )}
        </Card>

        <Card>
          <SectionHead title="Protection" sub="The layers that watch and block" />
          <details className="layers" open={!allRunning}>
            <summary className="row t-small">
              {allRunning ? (
                <>
                  <CircleCheck size={16} color="var(--good)" /> All {status?.sensors.length} layers
                  are running.
                </>
              ) : (
                'Layers'
              )}
            </summary>
            <div className="col">
              {status?.sensors.map((s) => (
                <div key={s.id} className="row">
                  <StatusMark
                    state={s.state === 'ok' ? 'done' : s.state === 'down' ? 'failed' : 'warn'}
                    label={s.state.replace('_', ' ')}
                  />
                  <div className="col grow" style={{ gap: 0 }}>
                    <span className="t-h3">{s.name}</span>
                    <span className="t-small">{s.detail}</span>
                  </div>
                  <span className="col" style={{ gap: 0, alignItems: 'flex-end' }}>
                    <span className="t-small">
                      {
                        {
                          ok: 'Running',
                          degraded: 'Needs attention',
                          down: 'Stopped',
                          not_installed: 'Not installed',
                        }[s.state]
                      }
                    </span>
                    {s.note && (
                      <span className="t-small" style={{ color: 'var(--tx3)', textAlign: 'right' }}>
                        {s.note}
                      </span>
                    )}
                    {s.id === 'helper' && s.state !== 'ok' && status.helperInstallable && (
                      <InstallHelper reinstall={s.state === 'down'} />
                    )}
                  </span>
                </div>
              ))}
            </div>
          </details>
        </Card>
      </div>

      {status && noticed.length > 0 && (
        <Card>
          <NoticedList
            alerts={noticed}
            view={status.alertView}
            open={(id) => go(`alerts/${id}`)}
            limit={8}
          />
        </Card>
      )}

      <Card>
        <SectionHead
          title="Recent actions"
          sub="What Vigil and you did"
          right={
            <button type="button" className="btn sm ghost" onClick={() => go('history')}>
              History
            </button>
          }
        />
        {(actions ?? []).length === 0 ? (
          <span className="t-small">No actions yet.</span>
        ) : (
          <div className="col">
            {(actions ?? []).slice(0, 5).map((r) => (
              <div key={r.id} className="row">
                <span className="grow ellipsis">{describeRecord(r)}</span>
                <span className="t-small">
                  {actorLabel(r.actor)} · {timeAgo(r.requestedAt)}
                </span>
              </div>
            ))}
          </div>
        )}
      </Card>
    </div>
  );
}

/** Installs the helper through macOS's own password dialog. */
function InstallHelper({ reinstall }: { reinstall: boolean }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const run = async () => {
    setBusy(true);
    setError(null);
    const r = await vigil.installHelper();
    setBusy(false);
    if (!r.ok && r.error !== 'cancelled') setError(r.error ?? 'Install failed');
  };
  return (
    <>
      <button
        type="button"
        className="btn sm"
        disabled={busy}
        title="macOS asks for your password once"
        onClick={() => void run()}
      >
        {busy ? 'Installing…' : reinstall ? 'Reinstall helper' : 'Install helper'}
      </button>
      {error && (
        <span className="t-small" style={{ color: 'var(--poor)', textAlign: 'right' }}>
          {error}
        </span>
      )}
    </>
  );
}
