import { CircleCheck, Eye, TriangleAlert } from 'lucide-react';
import { useState } from 'react';
import { useLive, vigil } from '../api';
import { homeMood } from '../components/AskScout';
import { NeedsYouLine, needsRows, NoticedList, pileLine, WatchLine } from '../components/Attention';
import { Dog } from '../components/Dog';
import { NotebookSheet } from '../components/Notebook';
import { Card, Chip, LevelPill, SectionHead, SeverityMark, StatusMark } from '../components/ui';
import { timeAgo } from '../format';
import { isNoticed, needsDecision } from '../../../shared/attention';
import { LEVEL_RULES } from '../../../shared/levels';
import { diaryLines, pileWords, SCOUT_PILE_MIN, type PackView } from '../../../shared/pack';
import { leadChat } from '../lead-chat';
import { PageHead } from './AppShell';
import { usePack } from './Pack';

const levelSentence = {
  good: 'Protection is on.',
  fair: 'Protection is only partly on.',
  poor: 'Protection has stopped.',
};

export function HomeView({ go }: { go: (r: string) => void }) {
  const [status] = useLive(() => vigil.getStatus());
  const [alerts] = useLive(() => vigil.listAlerts('open'));
  const allNeeds = needsRows((alerts ?? []).filter(needsDecision));
  // The biggest pile gets Scout's card instead of a row.
  const bigPile = allNeeds.reduce<(typeof allNeeds)[number] | undefined>(
    (best, r) =>
      (r.count ?? 0) >= SCOUT_PILE_MIN && (r.count ?? 0) > (best?.count ?? 0) ? r : best,
    undefined,
  );
  const needs = allNeeds.filter((r) => r !== bigPile);
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
            <span className="t-h2">
              {levelSentence[status.level]}
              {status.needsYou === 0 && ' Nothing needs you.'}
            </span>
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
          {status.needsYou > 0 && <NeedsYouLine count={status.needsYou} />}
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
              The level is only about protection: Santa, osquery and the Vigil helper. Alerts
              waiting on you are counted separately, so they never make protection look broken.
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
          {pack && <PackDiary pack={pack} />}
        </Card>
      )}

      {(needs.length > 0 || bigPile) && (
        <Card>
          <SectionHead title="Needs you" sub="Waiting on your decision, newest first" />
          {bigPile && lead && pack && (
            <div className="scout-pile">
              <Dog breed={lead.breed} mood="waiting" size={64} className="still" />
              <div className="col grow" style={{ gap: 6, minWidth: 0 }}>
                <span className="t-small">
                  <b>{lead.name}:</b>{' '}
                  {pileWords(
                    {
                      who: bigPile.who ?? 'One program',
                      title: bigPile.title,
                      count: bigPile.count!,
                    },
                    pack.voice,
                  )}
                </span>
                <span className="row wrap" style={{ gap: 8 }}>
                  <button
                    type="button"
                    className="btn sm primary"
                    onClick={() => go(`alerts/${bigPile.id}`)}
                  >
                    Look at all {bigPile.count}
                  </button>
                  <SeverityMark severity={bigPile.severity} />
                  <span className="t-small nowrap">latest {timeAgo(bigPile.at)}</span>
                </span>
              </div>
            </div>
          )}
          <div className="list">
            {needs.slice(0, 6).map((r) => (
              <button
                key={r.id}
                type="button"
                className="list-row"
                onClick={() => go(`alerts/${r.id}`)}
              >
                <SeverityMark severity={r.severity} />
                <span className="grow col" style={{ gap: 2 }}>
                  <span className="clamp-2 t-h3" title={r.title}>
                    {r.title}
                  </span>
                  {pileLine(r) && <span className="t-small">{pileLine(r)}</span>}
                </span>
                {r.blocked && <Chip tone="good">Blocked</Chip>}
                <span className="t-small nowrap">{timeAgo(r.at)}</span>
              </button>
            ))}
          </div>
          {needs.length > 6 && (
            <button type="button" className="btn sm ghost" onClick={() => go('alerts')}>
              All {allNeeds.length}
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
                  {s.lastRefusal && (
                    <span className="t-small" style={{ color: 'var(--tx3)', textAlign: 'right' }}>
                      {s.lastRefusal.reason === 'handshake_failed'
                        ? 'A secure connection to Santa’s sync port failed'
                        : 'A connection without Vigil’s certificate was refused'}{' '}
                      at {new Date(s.lastRefusal.at).toLocaleTimeString()}
                    </span>
                  )}
                  {s.compatUntil !== undefined && (
                    <span className="t-small" style={{ color: 'var(--tx3)', textAlign: 'right' }}>
                      Santa syncs without its certificate until{' '}
                      {new Date(s.compatUntil).toLocaleDateString()}, or until it first uses it
                    </span>
                  )}
                  {s.repair === 'santa-sync' && <RepairSantaSync go={go} />}
                  {s.id === 'helper' &&
                    (s.state !== 'ok' || status.helperOutdated) &&
                    status.helperInstallable && (
                      <InstallHelper
                        kind={
                          status.helperOutdated
                            ? 'update'
                            : s.state === 'down'
                              ? 'reinstall'
                              : 'install'
                        }
                      />
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

/** Installs or updates the helper through the system's own password dialog. */
function InstallHelper({ kind }: { kind: 'install' | 'reinstall' | 'update' }) {
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
        title={
          kind === 'update'
            ? 'This version of Vigil ships a newer helper. Your password is asked once.'
            : 'Your password is asked once'
        }
        onClick={() => void run()}
      >
        {busy
          ? kind === 'update'
            ? 'Updating…'
            : 'Installing…'
          : { install: 'Install helper', reinstall: 'Reinstall helper', update: 'Update helper' }[
              kind
            ]}
      </button>
      {error && (
        <span className="t-small" style={{ color: 'var(--poor)', textAlign: 'right' }}>
          {error}
        </span>
      )}
    </>
  );
}

/**
 * When Santa's syncs fail: the helper issues Santa a new sync certificate and
 * takes Santa without one until it presents it, which asks for the admin
 * password. If Santa's profile predates the certificate, Setup then offers it.
 */
function RepairSantaSync({ go }: { go: (r: string) => void }) {
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const run = async () => {
    setBusy(true);
    setError(null);
    const r = await vigil.repairSantaSync();
    setBusy(false);
    if (r.ok) setDone(true);
    else if (r.error !== 'cancelled') setError(r.error ?? 'Repair failed');
  };
  if (done)
    return (
      <span className="t-small" style={{ textAlign: 'right' }}>
        Repaired. If Santa still can’t sync,{' '}
        <button type="button" className="btn sm ghost" onClick={() => go('settings')}>
          reinstall its profile
        </button>
      </span>
    );
  return (
    <>
      <button
        type="button"
        className="btn sm"
        disabled={busy}
        title="Gives Santa a new sync certificate. Your password is asked once."
        onClick={() => void run()}
      >
        {busy ? 'Repairing…' : 'Repair'}
      </button>
      {error && (
        <span className="t-small" style={{ color: 'var(--poor)', textAlign: 'right' }}>
          {error}
        </span>
      )}
    </>
  );
}

/**
 * What the pack did today, one line per dog that worked, each opening that
 * dog's notebook. Counted from the notebooks; the wording is fixed, not AI.
 */
function PackDiary({ pack }: { pack: PackView }) {
  const [open, setOpen] = useState<string | undefined>();
  const lines = diaryLines(pack.dogs, pack.today, pack.voice);
  if (lines.length === 0) return null;
  const dog = (id: string) => pack.dogs.find((d) => d.id === id);
  const shown = open ? dog(open) : undefined;
  return (
    <div className="pack-diary">
      <span className="t-label">Today the pack</span>
      <ul>
        {lines.map((l) => {
          const d = dog(l.dog)!;
          return (
            <li key={l.dog}>
              <button
                type="button"
                className="pack-diary-line"
                title={`Open ${d.name}’s notebook`}
                onClick={() => setOpen(l.dog)}
              >
                <Dog breed={d.breed} mood="idle" size={28} className="still" />
                <span className="t-small">
                  {l.text}
                  {l.failed > 0 && <span className="muted"> ({l.failed} didn’t finish)</span>}
                </span>
              </button>
            </li>
          );
        })}
      </ul>
      {shown && (
        <NotebookSheet
          title={`${shown.name}’s notebook`}
          filter={{ dog: shown.id }}
          onClose={() => setOpen(undefined)}
        />
      )}
    </div>
  );
}
