import type { ActionProposal, ActionRecord, Alert } from '@vigil/core';
import { ShieldAlert, ShieldCheck } from 'lucide-react';
import { useState } from 'react';
import { vigil } from '../api';
import {
  activeContainment,
  containLabel,
  refusalNote,
  keepLabel,
  releaseLabel,
  releaseStep,
  uncontainedAnswers,
} from '../decision';
import { releaseFailed } from '../format';
import { HoldButton } from './HoldButton';
import { Button } from './ui';

export type Decided = 'kept' | 'released' | 'contained' | 'threat' | 'fine' | 'expected';

/**
 * The one set of decision buttons, used by the alert page and the popup. Each
 * button names its effect, and a release lists what it will undo before the
 * hold-to-confirm. If a release doesn't go through, the alert stays open and
 * the failure is shown here; onDecided runs only when the choice took effect.
 */
export function DecisionControls({
  alert,
  actions,
  proposals,
  onDecided,
  full,
  blockTarget,
}: {
  alert: Alert;
  actions: readonly ActionRecord[];
  proposals: readonly ActionProposal[];
  onDecided: (d: Decided) => void;
  full?: boolean;
  blockTarget: string | undefined;
}) {
  const [failure, setFailure] = useState<{ id: string; text: string }>();
  const [notMeFor, setNotMeFor] = useState<string>();
  const pending = proposals.filter((p) => p.status === 'pending');
  const active = activeContainment(actions);
  const contained = alert.containment === 'active';
  // A quarantine an installer's ownership stopped: one calm line, here, instead of closing.
  const note = actions.map((r) => refusalNote(r, actions)).find(Boolean);
  const answers = uncontainedAnswers(alert.severity, pending.length);
  const askingNotMe = notMeFor === alert.id;

  const decide = async (
    verdict: 'malicious' | 'benign' | 'expected',
    release: boolean,
    d: Decided,
  ) => {
    const out = await vigil.decide(alert.id, { verdict, release });
    if (release && !out.decision) {
      setFailure({ id: alert.id, text: releaseFailed(out) });
      return;
    }
    onDecided(d);
  };
  const contain = async () => {
    let held = false;
    for (const p of pending) {
      const r = await vigil.approveProposal(p.id);
      if (r.result?.errorCode) held = true;
    }
    if (held) {
      // Recorded as malicious, but the view stays open so the line about the item is seen.
      await vigil.decide(alert.id, { verdict: 'malicious', release: false });
      return;
    }
    await decide('malicious', false, 'contained');
  };

  return (
    <div className="col decision" style={{ gap: 8 }}>
      {note && (
        <p className="t-small" style={{ margin: 0 }}>
          {note}
        </p>
      )}
      {failure?.id === alert.id && (
        <p role="alert" className="t-small" style={{ margin: 0, color: 'var(--poor)' }}>
          {failure.text}
        </p>
      )}
      <div className={full ? 'popup-actions' : 'row'} style={{ flexWrap: 'wrap' }}>
        {contained ? (
          <>
            <Button
              kind="primary"
              icon={<ShieldCheck size={15} />}
              onClick={() => void decide('malicious', false, 'kept')}
            >
              {keepLabel(active)}
            </Button>
            <HoldButton
              label={releaseLabel(active)}
              doneLabel="Done"
              onConfirm={() => void decide('benign', true, 'released')}
            />
          </>
        ) : (
          <>
            {pending.length > 0 && (
              <Button
                // A suggestion, not the default: only a serious alert leads with it.
                kind={answers.lead === 'contain' ? 'primary' : 'outline'}
                icon={<ShieldAlert size={15} />}
                onClick={() => void contain()}
              >
                {containLabel(pending)}
              </Button>
            )}
            {answers.notMe && (
              <Button
                kind={answers.lead === 'not-me' ? 'primary' : 'ghost'}
                aria-expanded={askingNotMe}
                onClick={() => setNotMeFor(askingNotMe ? undefined : alert.id)}
              >
                This wasn’t me
              </Button>
            )}
            <Button
              kind={answers.lead === 'that-was-me' ? 'primary' : 'outline'}
              title="You did this yourself. Closes the alert; nothing is allowed for next time."
              onClick={() => void decide('expected', false, 'expected')}
            >
              That was me
            </Button>
            <Button
              kind="ghost"
              title="It wasn’t you, but it’s harmless. Closes the alert; nothing is allowed for next time."
              onClick={() => void decide('benign', false, 'fine')}
            >
              Looks fine
            </Button>
          </>
        )}
      </div>
      {!contained && askingNotMe && (
        <div className="col release-scope" style={{ gap: 6 }}>
          {blockTarget ? (
            <>
              <span className="t-small">
                Vigil blocks this program from running again, so anything else that uses it stops
                working too:
              </span>
              <div className="subject mono">{blockTarget}</div>
              <span className="t-small">
                That may ask for your password. Your system’s own programs are never blocked, and
                Reopen on the alert takes this back.
              </span>
            </>
          ) : (
            <span className="t-small">
              There’s no program here to block, so this records your answer and closes the alert.
            </span>
          )}
          <div className="row">
            <Button kind="primary" onClick={() => void decide('malicious', false, 'threat')}>
              Treat as a threat
            </Button>
            <Button kind="ghost" onClick={() => setNotMeFor(undefined)}>
              Cancel
            </Button>
          </div>
        </div>
      )}
      {!contained && !full && !askingNotMe && (
        <span className="t-small">
          “That was me” and “Looks fine” both close it, and Vigil remembers which. Say “That was me”
          to the same thing a few times and Vigil offers “Don’t show this again” on the Rules page;
          when a whole rule keeps getting these answers, it suggests turning the rule down.
        </span>
      )}
      {contained && active.length > 0 && (
        <div className="col release-scope" style={{ gap: 2 }}>
          <span className="t-small">Holding “{releaseLabel(active)}” will:</span>
          <ul className="t-small" style={{ margin: 0, paddingLeft: 18 }}>
            {active.map((r) => (
              <li key={r.id}>{releaseStep(r)}</li>
            ))}
          </ul>
          <span className="t-small">This time only. It isn’t allowed for next time.</span>
        </div>
      )}
    </div>
  );
}
