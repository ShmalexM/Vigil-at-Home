import { findExecutable } from './executable.js';
import type { AiRunner } from './runner.js';
import type { ProviderStatus } from './types.js';

/**
 * AI apps Vigil looks for. Copilot is detected so setup can mention it, but
 * Vigil can't use it until its adapter lands.
 */
export interface AiAppsSnapshot {
  readonly providers: readonly ProviderStatus[];
  readonly copilot: { readonly installed: boolean; readonly supported: false };
}

export interface WatchAiAppsOptions {
  /** How often to look again. Default one minute. */
  readonly intervalMs?: number;
  readonly onChange: (snapshot: AiAppsSnapshot) => void;
  /** For tests. */
  readonly findCopilot?: () => Promise<string | undefined>;
}

function key(snapshot: AiAppsSnapshot): string {
  return JSON.stringify([
    snapshot.providers.map((p) => [p.provider, p.state, p.version, p.account, p.canSignIn]),
    snapshot.copilot.installed,
  ]);
}

export async function detectAiApps(
  runner: AiRunner,
  findCopilot: () => Promise<string | undefined> = () => findExecutable('copilot'),
): Promise<AiAppsSnapshot> {
  const [providers, copilot] = await Promise.all([runner.status(), findCopilot()]);
  return { providers, copilot: { installed: copilot !== undefined, supported: false } };
}

/**
 * Keeps checking which AI apps are installed and signed in, and reports each
 * change (installed, signed in or out, updated to a binary from a different
 * signer). The runner uses whatever is ready on its next task, so nothing
 * needs setting up; this is for the settings screen and the menu bar.
 * Returns a function that stops watching.
 */
export function watchAiApps(runner: AiRunner, options: WatchAiAppsOptions): () => void {
  const interval = options.intervalMs ?? 60_000;
  let last: string | undefined;
  let stopped = false;
  let timer: ReturnType<typeof setTimeout> | undefined;

  const tick = async () => {
    try {
      const snapshot = await detectAiApps(runner, options.findCopilot);
      const k = key(snapshot);
      if (!stopped && k !== last) {
        last = k;
        options.onChange(snapshot);
      }
    } catch {
      // A failed check is retried on the next tick.
    }
    if (!stopped) timer = setTimeout(() => void tick(), interval);
  };
  void tick();
  return () => {
    stopped = true;
    if (timer) clearTimeout(timer);
  };
}
