/*
 * The one-at-a-time stack and rolling counter are adapted from Beautiful UI's
 * ApprovalCard (https://github.com/slev12397/beautiful-ui), Copyright (c) 2026
 * Shane Levine, MIT License. See THIRD_PARTY_NOTICES.md.
 */
import { Check, ChevronLeft, ChevronRight, X } from 'lucide-react';
import { useEffect, useState } from 'react';
import type { PackView, ToolApproval, ToolDecision } from '../../../shared/pack';
import { nextIndex } from '../agent-ui';
import { vigil } from '../api';
import '../styles/agent-ui.css';
import { Dog } from './Dog';
import { Button } from './ui';

type PackDog = PackView['dogs'][number];

const WHY: Record<ToolApproval['why'], string> = {
  mode: 'You asked to approve tools that can change things.',
  'always-ask': 'You set this tool to always ask.',
  rule: 'A Vigil rule asks about this call.',
  'judged-risky': 'Your AI rated this call risky.',
  'no-judge': 'No AI could rate this call, so it asks.',
};

/** How long the "Allowed once" or "Denied" receipt shows before the next ask. */
const RECEIPT_MS = 900;

/**
 * Tool calls waiting on the person, one at a time so there's only ever one
 * decision in front of them. A counter rolls between them when there are
 * several, and each decision leaves a short receipt before the next slides in.
 */
export function ApprovalStack({
  approvals,
  dogs,
  reload,
}: {
  approvals: ToolApproval[];
  dogs: Map<string, PackDog>;
  reload: () => void;
}) {
  // The ask on screen, by id so a reload that adds or removes asks keeps it.
  const [shown, setShown] = useState<{ id: string | undefined; index: number }>({
    id: undefined,
    index: 0,
  });
  const [dir, setDir] = useState<'next' | 'prev'>('next');
  const [receipt, setReceipt] = useState<{ id: string; decision: ToolDecision } | null>(null);
  const at = nextIndex(
    approvals.map((x) => x.id),
    shown.id,
    shown.index,
  );
  const a = approvals[at];

  useEffect(() => {
    if (!receipt) return;
    const t = setTimeout(() => {
      setReceipt(null);
      setDir('next');
      reload();
    }, RECEIPT_MS);
    return () => clearTimeout(t);
  }, [receipt, reload]);

  if (receipt)
    return (
      <div className={`approval-receipt ${receipt.decision}`} role="status">
        <span className="approval-receipt-dot">
          {receipt.decision === 'deny' ? <X size={11} /> : <Check size={11} />}
        </span>
        {receipt.decision === 'deny' ? 'Denied' : 'Allowed once'}
      </div>
    );
  if (!a) return null;

  const dog = dogs.get(a.dogId);
  const go = (to: number) => {
    setDir(to < at ? 'prev' : 'next');
    setShown({ id: approvals[to]?.id, index: to });
  };
  const decide = (d: ToolDecision) =>
    void vigil.decidePackTool(a.id, d).then(() => setReceipt({ id: a.id, decision: d }));

  return (
    <div className="approval-stack">
      {approvals.length > 1 && (
        <div className="approval-nav t-small muted">
          <button
            type="button"
            className="approval-step"
            aria-label="Previous ask"
            disabled={at === 0}
            onClick={() => go(at - 1)}
          >
            <ChevronLeft size={14} />
          </button>
          <span className="tabular" aria-live="polite">
            <RollingDigits value={`${at + 1} / ${approvals.length}`} />
            <span className="sr-only"> waiting on you</span>
          </span>
          <button
            type="button"
            className="approval-step"
            aria-label="Next ask"
            disabled={at === approvals.length - 1}
            onClick={() => go(at + 1)}
          >
            <ChevronRight size={14} />
          </button>
        </div>
      )}
      <div key={a.id} className={`approval-card slide-${dir}`}>
        {dog && <Dog breed={dog.breed} mood="waiting" size={58} />}
        <div className="col grow" style={{ gap: 4, minWidth: 0 }}>
          <span className="t-label">
            {dog?.name ?? 'A dog'} wants to use {a.toolTitle}
          </span>
          <code className="approval-args mono">{a.args}</code>
          <span className="t-small muted">
            {WHY[a.why]}
            {a.reason ? ` ${a.reason}` : ''}
          </span>
        </div>
        <span className="col" style={{ gap: 6 }}>
          <Button size="sm" kind="primary" onClick={() => decide('allow-once')}>
            Allow once
          </Button>
          <Button size="sm" kind="ghost" onClick={() => decide('deny')}>
            Deny
          </Button>
        </span>
      </div>
    </div>
  );
}

const ROLL_MS = 350;

/** Odometer digits: each character that changes rolls up, or down going back. */
function RollingDigits({ value }: { value: string }) {
  const [prev, setPrev] = useState(value);
  const [from, setFrom] = useState(value);
  const [down, setDown] = useState(false);
  if (value !== prev) {
    setDown(parseInt(value, 10) < parseInt(prev, 10));
    setFrom(prev);
    setPrev(value);
  }
  useEffect(() => {
    if (from === value) return;
    const t = setTimeout(() => setFrom(value), ROLL_MS);
    return () => clearTimeout(t);
  }, [from, value]);

  return (
    <>
      {[...value].map((ch, i) => {
        const old = from[i] ?? '';
        if (from === value || old === ch) return <span key={`${i}-${ch}`}>{ch}</span>;
        return (
          <span key={`${i}-${old}-${ch}`} className="roll">
            <span className={`roll-track ${down ? 'down' : 'up'}`}>
              <span>{down ? ch : old}</span>
              <span>{down ? old : ch}</span>
            </span>
          </span>
        );
      })}
    </>
  );
}
