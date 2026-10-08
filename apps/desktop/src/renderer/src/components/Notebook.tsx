import { BookOpen, X } from 'lucide-react';
import { useCallback, useEffect, useRef, useState, type ReactNode } from 'react';
import type { DogNote, DogNoteKind, NotesFilter } from '../../../shared/pack';
import { vigil } from '../api';
import { timeAgo } from '../format';
import '../styles/pack.css';
import { useDialogFocus } from './dialog-focus';
import { Thinking } from './Thinking';
import { Chip } from './ui';

const KIND: Record<DogNoteKind, string> = {
  chat: 'Chat',
  job: 'Job',
  judge: 'Risk check',
  explain: 'Explanation',
  label: 'Labels',
  review: 'Rule review',
};

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

  return (
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
      </div>
    </div>
  );
}

function NoteEntry({ note: n, who }: { note: DogNote; who?: string | undefined }) {
  return (
    <li className={`note ${n.ok ? '' : 'failed'}`}>
      <span className="row t-small muted" style={{ gap: 6 }}>
        <Chip>{KIND[n.kind]}</Chip>
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
      {n.fromOutside && (
        <p className="t-small muted">
          Part of this answer came from what it read, which anyone could have written.
        </p>
      )}
      {n.reasons.length > 0 && (
        <Field label="Reasons given">
          <ul className="note-reasons">
            {n.reasons.map((r, i) => (
              <li key={i}>{r}</li>
            ))}
          </ul>
        </Field>
      )}
      {n.readReasons && n.readReasons.length > 0 && (
        <Field label="From what it read">
          <ul className="note-reasons">
            {n.readReasons.map((r, i) => (
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
