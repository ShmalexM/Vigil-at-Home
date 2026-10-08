import { useEffect, useRef, useState } from 'react';

export const vigil = window.vigil;

/**
 * Load data from main and reload whenever main says something changed, or
 * when `key` changes. Returns `undefined` until the first load finishes.
 * `also`: another push to reload on, such as `agents` for views of agent
 * activity, which main sends apart so busy agents don't reload every page.
 */
export function useLive<T>(
  load: () => Promise<T>,
  key: unknown = null,
  also?: 'agents',
): [T | undefined, () => void] {
  const [data, setData] = useState<T>();
  const loader = useRef(load);
  loader.current = load;
  // Each load gets a number and only the newest may land, so a slow answer
  // to an older load (or for the previous key) never replaces a newer one.
  const latest = useRef(0);
  const reload = useRef(() => {
    const n = ++latest.current;
    loader.current().then(
      (value) => {
        if (n === latest.current) setData(() => value);
      },
      (err: unknown) => console.error(err),
    );
  }).current;
  useEffect(() => {
    // Don't show the previous key's data while this key's loads.
    setData(undefined);
    reload();
    const off = vigil.on('changed', reload);
    const offAlso = also ? vigil.on(also, reload) : undefined;
    return () => {
      off();
      offAlso?.();
    };
  }, [key, reload, also]);
  return [data, reload];
}

/**
 * Re-renders every `ms` and whenever the window is shown or focused, so
 * relative times ("5 min ago") stay right in a window that stays loaded.
 */
export function useClock(ms = 30_000): void {
  const [, tick] = useState(0);
  useEffect(() => {
    const bump = () => tick((n) => n + 1);
    const timer = setInterval(bump, ms);
    const onVisible = () => document.visibilityState === 'visible' && bump();
    window.addEventListener('focus', bump);
    document.addEventListener('visibilitychange', onVisible);
    return () => {
      clearInterval(timer);
      window.removeEventListener('focus', bump);
      document.removeEventListener('visibilitychange', onVisible);
    };
  }, [ms]);
}
