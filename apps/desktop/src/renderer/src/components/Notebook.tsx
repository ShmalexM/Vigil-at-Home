import { BookOpen, Braces, ChevronDown, Copy, X } from 'lucide-react';
import { useCallback, useEffect, useId, useRef, useState, type ReactNode } from 'react';
import { createPortal } from 'react-dom';
import type { DogNote, NotesFilter, NoteToolCall } from '../../../shared/pack';
import { vigil } from '../api';
import { timeAgo } from '../format';
import { CALL_OUTCOME, NOTE_KIND, notesJson, notesMarkdown, usageWords } from '../notebook-export';
import '../styles/pack.css';
import { useDialogFocus } from './dialog-focus';
import { Thinking } from './Thinking';
import { useToast } from './Toasts';
import { Button, Chip } from './ui';

/**
 * A dog's notebook: what each AI run was asked, what it looked at, what it
 * answered and the reasons it wrote down. Only the reasons the model put in
 * its answer, plus a reasoning summary where the provider's API returns one;
 * nothing hidden is ever pulled out of a model. Read-only.
 */
export function NotebookSheet({
  title,
  filter,
  names,
  onClose,
}: {
  title: string;
  filter: NotesFilter;
  /** Dog names by id, shown when the notes come from more than one dog. */
  names?: Record<string, string>;
  onClose: () => void;
}) {
  const [notes, setNotes] = useState<DogNote[] | undefined>();
  const key = JSON.stringify(filter);
  const load = useCallback(() => {
    void vigil.listPackNotes(JSON.parse(key) as NotesFilter).then(setNotes);
  }, [key]);
  useEffect(() => {
    load();
    return vigil.on('pack', load);
  }, [load]);
  const box = useRef<HTMLDivElement>(null);
  useDialogFocus(box, onClose);
  const toast = useToast();
  // Every note the notebook keeps (up to 200), not only the ones on screen.
  const copy = async (as: 'md' | 'json') => {
    const all = await vigil.listPackNotes({ ...(JSON.parse(key) as NotesFilter), limit: 200 });
    await navigator.clipboard.writeText(
      as === 'md' ? notesMarkdown(title, all, names ? { names } : {}) : notesJson(filter.dog, all),
    );
    toast({ text: as === 'md' ? 'Copied as Markdown' : 'Copied as JSON' });
  };

  // On body: inside a sticky parent such as the Lead panel, the scrim would sit under the drag strip.
  return createPortal(
    <div className="scrim" onClick={onClose}>
      <div
        ref={box}
        className="sheet notebook card"
        onClick={(e) => e.stopPropagation()}
        role="dialog"
        aria-modal="true"
        aria-label={title}
        tabIndex={-1}
      >
        <div className="row spread">
          <h2 className="t-h2 row" style={{ gap: 8 }}>
            <BookOpen size={18} /> {title}
          </h2>
          <button type="button" className="btn ghost icon-btn" aria-label="Close" onClick={onClose}>
            <X size={16} />
          </button>
        </div>
        <p className="t-small muted" style={{ margin: 0 }}>
          The reasons each answer gave, in the model’s own words. Kept on this Mac for 30 days.
          Notes never decide anything.
        </p>
        {notes === undefined ? null : notes.length === 0 ? (
          <p className="t-small muted">Nothing written down yet.</p>
        ) : (
          <ol className="notes">
            {notes.map((n) => (
              <NoteEntry key={n.id} note={n} who={filter.dog ? undefined : names?.[n.dog]} />
            ))}
          </ol>
        )}
        {notes && notes.length > 0 && (
          <div className="row" style={{ gap: 6 }}>
            <Button
              size="sm"
              kind="ghost"
              icon={<Copy size={13} />}
              onClick={() => void copy('md')}
            >
              Copy as Markdown
            </Button>
            <Button
              size="sm"
              kind="ghost"
              icon={<Braces size={13} />}
              onClick={() => void copy('json')}
            >
              Copy JSON
            </Button>
          </div>
        )}
      </div>
    </div>,
    document.body,
  );
}

function NoteEntry({ note: n, who }: { note: DogNote; who?: string | undefined }) {
  return (
    <li className={`note ${n.ok ? '' : 'failed'}`}>
      <span className="row t-small muted" style={{ gap: 6 }}>
        <Chip>{NOTE_KIND[n.kind]}</Chip>
        {who && <b>{who}</b>}
        <span>{timeAgo(n.at)}</span>
        {(n.provider || n.model) && (
          <span className="ellipsis">· {[n.provider, n.model].filter(Boolean).join(' · ')}</span>
        )}
      </span>
      <Field label="Asked">{n.ask}</Field>
      {n.lookedAt.length > 0 && (
        <Field label="Looked at">
          <span className="row wrap" style={{ gap: 4 }}>
            {n.lookedAt.map((l, i) => (
              <Chip key={i}>{l}</Chip>
            ))}
          </span>
        </Field>
      )}
      <Field label={n.ok ? 'Answered' : 'What happened'}>{n.answer}</Field>
      {n.reasons.length > 0 && (
        <Field label="Reasons given">
          <ul className="note-reasons">
            {n.reasons.map((r, i) => (
              <li key={i}>{r}</li>
            ))}
          </ul>
        </Field>
      )}
      {n.thinking && (
        <Thinking
          working={false}
          active=""
          done="Thinking summary (from the provider)"
          rows={n.thinking
            .split(/\n\s*\n/)
            .filter((p) => p.trim())
            .map((p) => ({ primary: p.trim() }))}
          prose
        />
      )}
      <NoteDetails note={n} />
    </li>
  );
}

/**
 * For whoever wants to dig: each tool call with its (redacted) arguments and
 * the start of its result, and what the run cost. Closed until opened.
 */
function NoteDetails({ note: n }: { note: DogNote }) {
  const [open, setOpen] = useState(false);
  const id = useId();
  const calls = n.calls ?? [];
  // Older notes kept no calls or usage; a judge's note never has calls.
  if (calls.length === 0 && !n.model && !n.usage) return null;
  return (
    <div className="note-details">
      <button
        type="button"
        className="note-details-head t-small"
        aria-expanded={open}
        aria-controls={id}
        onClick={() => setOpen(!open)}
      >
        <ChevronDown size={13} aria-hidden className={open ? 'open' : ''} />
        Details
        {calls.length > 0 && (
          <span className="muted">
            · {calls.length} tool {calls.length === 1 ? 'call' : 'calls'}
          </span>
        )}
      </button>
      {open && (
        <div id={id} className="note-details-body">
          {calls.length > 0 && (
            <ol className="note-calls">
              {calls.map((c, i) => (
                <CallRow key={i} call={c} />
              ))}
            </ol>
          )}
          <Field label="Model">
            {n.model ?? 'Not recorded'}
            {n.usage && <span className="muted"> · {usageWords(n.usage)}</span>}
          </Field>
        </div>
      )}
    </div>
  );
}

function CallRow({ call: c }: { call: NoteToolCall }) {
  return (
    <li className={`note-call ${c.outcome}`}>
      <span className="row wrap t-small" style={{ gap: 6 }}>
        <b>{c.title}</b>
        <Chip tone={c.outcome === 'ran' ? undefined : c.outcome === 'failed' ? 'poor' : 'fair'}>
          {CALL_OUTCOME[c.outcome]}
        </Chip>
        {c.reason && <span className="muted">{c.reason}</span>}
      </span>
      <Field label="Arguments">
        <code className="note-code">{c.args}</code>
      </Field>
      {c.result !== undefined && (
        <Field label="Result">
          <code className="note-code">{c.result || '(empty)'}</code>
        </Field>
      )}
    </li>
  );
}

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="note-field">
      <span className="t-label">{label}</span>
      <div className="t-small">{children}</div>
    </div>
  );
}
