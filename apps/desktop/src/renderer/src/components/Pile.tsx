import type { Alert } from '@vigil/core';
import { useState } from 'react';
import { useLive, vigil } from '../api';
import { clock } from '../format';
import { commonFolder, pileMates } from '../../../shared/piles';
import { HoldButton } from './HoldButton';
import { Button } from './ui';

const SHOWN = 6;

/**
 * Shown on an alert that is one of a pile: how many like it, what each was
 * about, and one decision for all of them. Each alert is still decided (and
 * recorded) on its own.
 */
export function PileBox({ alert, onDone }: { alert: Alert; onDone: (n: number) => void }) {
  const [open] = useLive(() => vigil.listAlerts('open'));
  const [all, setAll] = useState(false);
  const [busy, setBusy] = useState(false);
  const mates = open ? pileMates(alert, open) : [alert];
  if (mates.length < 2) return null;
  const n = mates.length;
  const first = Math.min(...mates.map((a) => a.createdAt));
  const last = Math.max(...mates.map((a) => a.createdAt));
  const whats = [...new Set(mates.map((a) => a.pile?.what).filter((w): w is string => !!w))];
  const base = commonFolder(whats);
  const shown = (all ? whats : whats.slice(0, SHOWN)).map((w) => w.slice(base.length));

  const decideAll = async (verdict: 'expected' | 'benign') => {
    setBusy(true);
    let done = 0;
    try {
      for (const a of mates) {
        await vigil.decide(a.id, { verdict, release: false });
        done++;
      }
    } finally {
      setBusy(false);
      onDone(done);
    }
  };

  return (
    <div className="pile col" style={{ gap: 8 }}>
      <span className="t-h3">
        One of {n} alerts like this from {alert.pile?.who}, {clock(first)} to {clock(last)}
      </span>
      {base && <span className="t-small mono pile-base">In {base}</span>}
      {whats.length > 0 && (
        <ul className="pile-list mono t-small">
          {shown.map((w) => (
            <li key={w}>{w}</li>
          ))}
        </ul>
      )}
      {whats.length > SHOWN && (
        <Button size="sm" kind="ghost" onClick={() => setAll(!all)}>
          {all ? 'Show fewer' : `Show all ${whats.length}`}
        </Button>
      )}
      <div className="row wrap">
        <HoldButton
          label={`That was me, all ${n}`}
          calm
          disabled={busy}
          onConfirm={() => void decideAll('expected')}
        />
        <HoldButton
          label={`Looks fine, all ${n}`}
          calm
          disabled={busy}
          onConfirm={() => void decideAll('benign')}
        />
      </div>
      <span className="t-small">
        This only closes these {n}. It doesn’t allow anything next time.
      </span>
    </div>
  );
}
