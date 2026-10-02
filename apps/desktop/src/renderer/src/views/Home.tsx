import { CircleCheck, Eye, TriangleAlert } from 'lucide-react';
import { useState } from 'react';
import { useLive, vigil } from '../api';
import { NoticedList, WatchLine } from '../components/Attention';
import { Card, Chip, LevelPill, SectionHead, SeverityMark, StatusMark } from '../components/ui';
import { timeAgo } from '../format';
import { isNoticed, needsDecision } from '../../../shared/attention';
import { LEVEL_RULES } from '../../../shared/levels';
import { PageHead } from './AppShell';

const levelSentence = {
  good: 'Protection is on. Nothing needs you.',
  fair: 'Something needs a look.',
  poor: 'Something needs you now.',
};

export function HomeView({ go }: { go: (r: string) => void }) {
  const [status] = useLive(() => vigil.getStatus());
  const [alerts] = useLive(() => vigil.listAlerts('open'));
  const needs = (alerts ?? []).filter(needsDecision);
  const noticed = (alerts ?? []).filter(isNoticed);
  const allRunning = !!status && status.sensors.every((s) => s.state === 'ok');

  return (
    <div className="page">
      <PageHead
        title="Home"
        purpose="How your Mac is doing, and anything that needs your decision."
      />

      {status && (
        <Card>
          <div className="row" style={{ gap: 12 }}>
            <LevelPill level={status.level} />
            <span className="t-h2">{levelSentence[status.level]}</span>
          </div>
          <div className="row spread" style={{ flexWrap: 'wrap' }}>
            <WatchLine watch={status.watch} />
            <button type="button" className="btn sm ghost" onClick={() => go('history')}>
              What Vigil handled
            </button>
          </div>
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

      {needs.length > 0 && (
        <Card>
          <SectionHead title="Needs you" sub="Waiting on your decision, newest first" />
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
          {needs.length > 6 && (
            <button type="button" className="btn sm ghost" onClick={() => go('alerts')}>
              All {needs.length}
            </button>
          )}
        </Card>
      )}

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

      {status && noticed.length > 0 && status.alertView === 'more' && (
        <Card>
          <NoticedList alerts={noticed} view="more" open={(id) => go(`alerts/${id}`)} limit={8} />
        </Card>
      )}
      {status && noticed.length > 0 && status.alertView === 'less' && (
        <button type="button" className="row t-small noticed-hint" onClick={() => go('history')}>
          <Eye size={14} />
          Vigil also noticed {noticed.length === 1 ? 'one thing' : `${noticed.length} things`},
          probably you. Nothing was blocked. See History.
        </button>
      )}
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
