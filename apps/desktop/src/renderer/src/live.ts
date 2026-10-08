// The reload logic behind useLive, apart from React so it can be tested.

/**
 * Reloads with at most one load in flight. A reload asked for while one is
 * running waits and runs once that one is done, however many were asked for.
 * So every answer for the current key lands: under a steady stream of
 * reloads (a busy Mac sends a batch of events every second) a slow load is
 * never dropped in favour of a newer one that will be dropped in turn, and
 * main never gets a pile of identical requests. `reset` starts a new key: an
 * answer still on its way for the old one is thrown away.
 */
export function liveLoader<T>(
  load: () => Promise<T>,
  land: (value: T) => void,
  onError: (err: unknown) => void = (err) => console.error(err),
): { reload: () => void; reset: () => void } {
  let generation = 0;
  let inFlight = false;
  let again = false;
  const run = () => {
    inFlight = true;
    again = false;
    const g = generation;
    load()
      .then((value) => {
        if (g === generation) land(value);
      }, onError)
      .finally(() => {
        inFlight = false;
        if (again) run();
      });
  };
  const reload = () => {
    if (inFlight) again = true;
    else run();
  };
  return {
    reload,
    reset: () => {
      generation++;
      reload();
    },
  };
}
