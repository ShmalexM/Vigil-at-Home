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
  const reload = useRef(() => {
    loader.current().then(setData, (err: unknown) => console.error(err));
  }).current;
  useEffect(() => {
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
