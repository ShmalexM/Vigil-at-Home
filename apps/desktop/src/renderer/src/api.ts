import { useEffect, useRef, useState } from 'react';

export const vigil = window.vigil;

/**
 * Load data from main and reload whenever main says something changed, or
 * when `key` changes. Returns `undefined` until the first load finishes.
 */
export function useLive<T>(
  load: () => Promise<T>,
  key: unknown = null,
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
    return vigil.on('changed', reload);
  }, [key, reload]);
  return [data, reload];
}
