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
  const reload = useRef(() => {
    loader.current().then(setData, (err: unknown) => console.error(err));
  }).current;
  useEffect(() => {
    reload();
    return vigil.on('changed', reload);
  }, [key, reload]);
  return [data, reload];
}
