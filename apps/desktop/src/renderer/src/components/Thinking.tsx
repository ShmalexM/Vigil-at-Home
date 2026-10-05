/*
 * Adapted from Beautiful UI's ThinkingState (https://github.com/slev12397/beautiful-ui),
 * Copyright (c) 2026 Shane Levine, MIT License. See THIRD_PARTY_NOTICES.md.
 */
import { Check, ChevronDown, Sparkles } from 'lucide-react';
import { useId, useState } from 'react';
import '../styles/agent-ui.css';

export interface TraceRow {
  primary: string;
  secondary?: string;
  mono?: boolean;
}

/**
 * A dog's working trace: a shimmering label while it works, then a quiet
 * summary that opens to show what it looked at. Shows only what really
 * happened; while working with nothing to show yet, it has no rows.
 */
export function Thinking({
  working,
  active,
  done,
  rows = [],
  prose = false,
  defaultOpen = false,
}: {
  working: boolean;
  /** The label while working, e.g. "Scout is sniffing around". */
  active: string;
  /** The label once settled, e.g. "Sniffed 3 things". */
  done: string;
  rows?: TraceRow[];
  /** Rows are sentences of reasoning rather than short steps. */
  prose?: boolean;
  defaultOpen?: boolean;
}) {
  const [open, setOpen] = useState(defaultOpen);
  const id = useId();
  const canOpen = rows.length > 0;
  const expanded = canOpen && open;
  return (
    <div className={`thinking ${working ? 'working' : ''}`}>
      <button
        type="button"
        className="thinking-head"
        aria-expanded={canOpen ? expanded : undefined}
        aria-controls={canOpen ? id : undefined}
        disabled={!canOpen}
        onClick={() => setOpen((o) => !o)}
      >
        <Sparkles size={14} className="thinking-icon" aria-hidden />
        <span role="status" className={working ? 'thinking-shimmer' : 'thinking-done'}>
          {working ? active : done}
        </span>
        {canOpen && <ChevronDown size={14} className="thinking-chevron" aria-hidden />}
      </button>
      {canOpen && (
        <div id={id} className={`thinking-body ${expanded ? 'open' : ''}`} hidden={!expanded}>
          <div className="thinking-trace">
            {rows.map((row, i) => (
              <div
                key={`${i}-${row.primary}`}
                className={`thinking-row ${prose ? 'prose' : ''}`}
                style={{ animationDelay: `${i * 80}ms` }}
              >
                {!prose &&
                  (working && i === rows.length - 1 ? (
                    <span className="thinking-spin" aria-hidden />
                  ) : (
                    <Check size={13} className="thinking-check" aria-hidden />
                  ))}
                <span className="thinking-primary">{row.primary}</span>
                {row.secondary && (
                  <span className={`thinking-secondary ${row.mono ? 'mono' : ''}`}>
                    {row.secondary}
                  </span>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
