// The reload logic behind useLive, apart from React so it can be tested.

/** A load still running after this stops holding back the next one. */
export const LOAD_TIMEOUT_MS = 15_000;

/**
 * Reloads with at most one load in flight. A reload asked for while one is
 * running waits and runs once that one is done, however many were asked for.
 * So every answer for the current key lands: under a steady stream of
 * reloads (a busy Mac sends a batch of events every second) a slow load is
 * never dropped in favour of a newer one that will be dropped in turn, and
 * main never gets a pile of identical requests. `invalidate` starts a new
 * key: an answer still on its way for the old one is thrown away and no
 * longer holds back loads for the new one. `reset` does that and loads.
 * A load that hangs holds the others back for at most `timeoutMs`; an answer
 * older than one already shown never replaces it.
 */
export function liveLoader<T>(
  load: () => Promise<T>,
  land: (value: T) => void,
  onError: (err: unknown) => void = (err) => console.error(err),
  timeoutMs = LOAD_TIMEOUT_MS,
): {
  reload: () => void;
  reset: () => void;
  invalidate: () => void;
  /** For a load made elsewhere (an older page): true while its key is still the current one. */
  guard: () => () => boolean;
} {
  let generation = 0;
  /** The request holding the gate, if any. */
  let inFlight: number | undefined;
  let again = false;
  let started = 0;
  let landed = 0;
  const release = (id: number) => {
    if (inFlight !== id) return;
    inFlight = undefined;
    if (again) run();
  };
  const run = () => {
    const id = ++started;
    inFlight = id;
    again = false;
    const g = generation;
    const timer = setTimeout(() => release(id), timeoutMs);
    // A load that throws instead of rejecting must not wedge the gate.
    new Promise<T>((resolve) => resolve(load()))
      .then((value) => {
        if (g === generation && id > landed) {
          landed = id;
          land(value);
        }
      }, onError)
      .finally(() => {
        clearTimeout(timer);
        release(id);
      });
  };
  const reload = () => {
    if (inFlight !== undefined) again = true;
    else run();
  };
  const invalidate = () => {
    generation++;
    inFlight = undefined;
    again = false;
  };
  return {
    reload,
    reset: () => {
      invalidate();
      reload();
    },
    invalidate,
    guard: () => {
      const g = generation;
      return () => g === generation;
    },
  };
}
