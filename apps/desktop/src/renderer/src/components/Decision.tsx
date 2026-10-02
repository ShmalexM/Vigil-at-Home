import type { ActionProposal, ActionRecord, Alert } from '@vigil/core';
import { ShieldAlert, ShieldCheck } from 'lucide-react';
import { useState } from 'react';
import { vigil } from '../api';
import { activeContainment, containLabel, keepLabel, releaseLabel, releaseStep } from '../decision';
import { releaseFailed } from '../format';
import { HoldButton } from './HoldButton';
import { Button } from './ui';

export type Decided = 'kept' | 'released' | 'contained' | 'fine' | 'expected';

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
}: {
  alert: Alert;
  actions: readonly ActionRecord[];
  proposals: readonly ActionProposal[];
  onDecided: (d: Decided) => void;
  full?: boolean;
}) {
  const [failure, setFailure] = useState<{ id: string; text: string }>();
  const pending = proposals.filter((p) => p.status === 'pending');
  const active = activeContainment(actions);
  const contained = alert.containment === 'active';

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
    for (const p of pending) await vigil.approveProposal(p.id);
    await decide('malicious', false, 'contained');
  };

  return (
    <div className="col decision" style={{ gap: 8 }}>
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
                kind="primary"
                icon={<ShieldAlert size={15} />}
                onClick={() => void contain()}
              >
                {containLabel(pending)}
              </Button>
            )}
            <Button
              kind={pending.length > 0 ? 'outline' : 'primary'}
              onClick={() => void decide('expected', false, 'expected')}
            >
              That was me
            </Button>
            <Button kind="ghost" onClick={() => void decide('benign', false, 'fine')}>
              Looks fine
            </Button>
          </>
        )}
      </div>
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
