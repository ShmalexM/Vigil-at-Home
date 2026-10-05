/*
 * Adapted from Beautiful UI's StreamingText (https://github.com/slev12397/beautiful-ui),
 * Copyright (c) 2026 Shane Levine, MIT License. See THIRD_PARTY_NOTICES.md.
 */
import { useEffect, useRef, useState } from 'react';
import { WORD_MS, splitWords, wordsPerTick } from '../agent-ui';
import '../styles/agent-ui.css';

const reducedMotion = () => window.matchMedia?.('(prefers-reduced-motion: reduce)').matches;

/**
 * A just-arrived answer that resolves word by word, out of a soft blur, then
 * calls onDone so what follows it (action cards, the time) can appear.
 * The answer is already complete: this is only how it comes in. Screen
 * readers get the whole text at once.
 */
export function StreamingText({
  text,
  animate,
  onDone,
}: {
  text: string;
  /** False for answers that were already there when the chat opened. */
  animate: boolean;
  onDone?: () => void;
}) {
  const words = splitWords(text);
  const run = animate && !reducedMotion();
  const [count, setCount] = useState(run ? 0 : words.length);
  const done = count >= words.length;
  const finished = useRef(false);

  useEffect(() => {
    if (done) {
      if (!finished.current) {
        finished.current = true;
        onDone?.();
      }
      return;
    }
    const step = wordsPerTick(words.length);
    const t = setTimeout(() => setCount((c) => Math.min(words.length, c + step)), WORD_MS);
    return () => clearTimeout(t);
  }, [count, done, words.length, onDone]);

  if (!run) return <>{text}</>;
  return (
    <>
      <span className="sr-only">{text}</span>
      <span aria-hidden>
        {words.slice(0, count).map((w, i) => (
          <span key={i} className="stream-word">
            {w}
          </span>
        ))}
        {!done && <span className="stream-caret" />}
      </span>
    </>
  );
}
