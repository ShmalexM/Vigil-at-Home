import { Brain, Check, Copy, Plus, Trash2, X } from 'lucide-react';
import { useCallback, useEffect, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import {
  MEMORY_TOPIC_LABEL,
  MemoryTopic,
  type MemoryChange,
  type MemoryEntry,
} from '../../../shared/pack';
import { vigil } from '../api';
import { timeAgo } from '../format';
import '../styles/pack.css';
import { useDialogFocus } from './dialog-focus';
import { useToast } from './Toasts';
import { Button, Chip } from './ui';

/**
 * What the pack remembers: lasting facts from the person's own words, one
 * line each, grouped by topic. The person can add, forget or copy them as a
 * MEMORY.md. Background for the dogs' answers; never a decision.
 */
export function MemorySheet({ onClose }: { onClose: () => void }) {
  const [entries, setEntries] = useState<MemoryEntry[] | undefined>();
  const [fact, setFact] = useState('');
  const [topic, setTopic] = useState<MemoryTopic>('you');
  const [sure, setSure] = useState(false);
  const toast = useToast();
  const load = useCallback(() => void vigil.listPackMemory().then(setEntries), []);
  useEffect(() => {
    load();
    return vigil.on('pack', load);
  }, [load]);
  const box = useRef<HTMLDivElement>(null);
  useDialogFocus(box, onClose);

  const add = async () => {
    const r = await vigil.addPackMemory({ fact, topic });
    if (r.ok) setFact('');
    else toast({ text: r.error ?? 'It couldn’t be kept' });
    load();
  };
  const forget = (e: MemoryEntry) =>
    void vigil.forgetPackMemory(e.id).then(() => {
      load();
      toast({
        text: 'Forgotten',
        undo: () => void vigil.addPackMemory({ fact: e.fact, topic: e.topic }).then(load),
      });
    });

  // On body: inside a sticky parent such as the Lead panel, the scrim would sit under the drag strip.
  return createPortal(
    <div className="scrim" onClick={onClose}>
      <div
        ref={box}
        className="sheet notebook memory card"
        onClick={(e) => e.stopPropagation()}
        role="dialog"
        aria-modal="true"
        aria-label="What the pack remembers"
        tabIndex={-1}
      >
        <div className="row spread">
          <h2 className="t-h2 row" style={{ gap: 8 }}>
            <Brain size={18} /> What the pack remembers
          </h2>
          <button type="button" className="btn ghost icon-btn" aria-label="Close" onClick={onClose}>
            <X size={16} />
          </button>
        </div>
        <p className="t-small muted" style={{ margin: 0 }}>
          Things you told the pack, so you don’t have to say them twice. Only your own words go in:
          when an answer leaned on an alert or a tool, the Lead dog asks first. Memory never makes
          anything safe or allowed, and it stays on this Mac.
        </p>
        <form
          className="row memory-add"
          onSubmit={(e) => {
            e.preventDefault();
            if (fact.trim()) void add();
          }}
        >
          <select
            className="field"
            aria-label="Topic"
            value={topic}
            onChange={(e) => setTopic(e.target.value as MemoryTopic)}
          >
            {MemoryTopic.options.map((t) => (
              <option key={t} value={t}>
                {MEMORY_TOPIC_LABEL[t]}
              </option>
            ))}
          </select>
          <input
            className="field grow"
            maxLength={200}
            value={fact}
            placeholder="For example: I use Tailscale at home"
            onChange={(e) => setFact(e.target.value)}
          />
          <Button size="sm" kind="primary" icon={<Plus size={14} />} disabled={!fact.trim()}>
            Remember
          </Button>
        </form>
        {entries === undefined ? null : entries.length === 0 ? (
          <p className="t-small muted">
            Nothing yet. Tell the Lead dog “remember that…” or add a line above.
          </p>
        ) : (
          MemoryTopic.options.map((t) => {
            const mine = entries.filter((e) => e.topic === t);
            if (mine.length === 0) return null;
            return (
              <section key={t} className="col" style={{ gap: 6 }}>
                <span className="t-label">{MEMORY_TOPIC_LABEL[t]}</span>
                <ul className="memory-list">
                  {mine.map((e) => (
                    <li key={e.id} className="memory-entry">
                      <span className="grow">{e.fact}</span>
                      <span className="t-small muted nowrap">
                        {e.from === 'you' ? 'You' : 'Lead dog'} · {timeAgo(e.added)}
                      </span>
                      <button
                        type="button"
                        className="btn ghost icon-btn"
                        aria-label={`Forget: ${e.fact}`}
                        title="Forget"
                        onClick={() => forget(e)}
                      >
                        <Trash2 size={14} />
                      </button>
                    </li>
                  ))}
                </ul>
              </section>
            );
          })
        )}
        {entries && entries.length > 0 && (
          <div className="row" style={{ gap: 6 }}>
            <Button
              size="sm"
              kind="ghost"
              icon={<Copy size={13} />}
              onClick={async () => {
                await navigator.clipboard.writeText(await vigil.packMemoryMarkdown());
                toast({ text: 'Copied as MEMORY.md' });
              }}
            >
              Copy as Markdown
            </Button>
            <Button
              size="sm"
              kind={sure ? 'danger' : 'ghost'}
              icon={<Trash2 size={13} />}
              onClick={() => {
                if (!sure) return setSure(true);
                setSure(false);
                void vigil.forgetPackMemory().then(load);
              }}
              onBlur={() => setSure(false)}
            >
              {sure ? 'Yes, forget everything' : 'Forget everything'}
            </Button>
          </div>
        )}
      </div>
    </div>,
    document.body,
  );
}

/** A memory change in the Lead dog's reply: done with an Undo, or waiting for an OK. */
export function MemoryChangeCard({
  c,
  msgId,
  reload,
}: {
  c: MemoryChange;
  msgId: string;
  reload: () => void;
}) {
  const decide = (ok: boolean) => void vigil.decideLeadMemory(msgId, c.id, ok).then(reload);
  const verb =
    c.op === 'remember'
      ? c.status === 'pending'
        ? 'Remember this?'
        : 'Remembered'
      : c.status === 'pending'
        ? 'Forget this?'
        : 'Forgot';
  return (
    <div className={`action-card memory-card ${c.status}`}>
      <Brain size={18} className="memory-icon" />
      <div className="col grow" style={{ gap: 3, minWidth: 0 }}>
        <span className="t-label">{verb}</span>
        <span className={`t-small ${c.op === 'forget' ? 'struck' : ''}`}>{c.fact}</span>
        {c.note && <span className="t-small muted">{c.note}</span>}
      </div>
      {c.status === 'pending' ? (
        <span className="row" style={{ gap: 6 }}>
          <Button size="sm" kind="ghost" onClick={() => decide(false)}>
            Not now
          </Button>
          <Button size="sm" kind="primary" icon={<Check size={14} />} onClick={() => decide(true)}>
            {c.op === 'remember' ? 'Keep' : 'Forget'}
          </Button>
        </span>
      ) : c.status === 'done' && c.op === 'remember' ? (
        <Button size="sm" kind="ghost" onClick={() => decide(false)}>
          Undo
        </Button>
      ) : (
        <Chip tone={c.status === 'failed' ? 'poor' : c.status === 'done' ? 'good' : undefined}>
          {c.status === 'failed' ? 'Couldn’t' : c.status === 'done' ? 'Done' : 'Not kept'}
        </Chip>
      )}
    </div>
  );
}
