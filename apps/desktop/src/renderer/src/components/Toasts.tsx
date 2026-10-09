import { createContext, useCallback, useContext, useRef, useState, type ReactNode } from 'react';
import { CircleCheck, TriangleAlert } from 'lucide-react';

interface Toast {
  id: number;
  text: string;
  undo?: (() => void) | undefined;
  /** A failure gets a warning mark, never the green check that means it worked. */
  tone?: 'error' | undefined;
  ms: number;
}

const Ctx = createContext<(t: Omit<Toast, 'id' | 'ms'> & { ms?: number }) => void>(() => {});

/** Confirmations with Undo. The fuse under each one burns down the undo window. */
export function Toaster({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const next = useRef(1);
  const dismiss = useCallback((id: number) => setToasts((ts) => ts.filter((t) => t.id !== id)), []);
  const push = useCallback(
    (t: Omit<Toast, 'id' | 'ms'> & { ms?: number }) => {
      const id = next.current++;
      // Failures stay up longer: they usually say what to do next.
      const ms = t.ms ?? (t.tone === 'error' ? 9000 : 6000);
      setToasts((ts) => [...ts.slice(-2), { ...t, id, ms }]);
      setTimeout(() => dismiss(id), ms);
    },
    [dismiss],
  );
  return (
    <Ctx.Provider value={push}>
      {children}
      <div className="toasts" role="status" aria-live="polite">
        {toasts.map((t) => (
          <div key={t.id} className={t.tone === 'error' ? 'toast error' : 'toast'}>
            {t.tone === 'error' ? (
              <TriangleAlert size={16} color="var(--poor)" aria-hidden />
            ) : (
              <CircleCheck size={16} color="var(--good)" aria-hidden />
            )}
            <span className="grow">{t.text}</span>
            {t.undo && (
              <button
                type="button"
                className="btn sm ghost"
                onClick={() => {
                  t.undo?.();
                  dismiss(t.id);
                }}
              >
                Undo
              </button>
            )}
            <span className="fuse" style={{ animationDuration: `${t.ms}ms` }} aria-hidden />
          </div>
        ))}
      </div>
    </Ctx.Provider>
  );
}

export const useToast = () => useContext(Ctx);
