// Which helper socket and profile a development build uses under the e2e
// harness (apps/desktop/e2e/harness.mjs, docs/e2e-safety.md). A packaged app
// ignores all of this: it always talks to the installed helper.

import { defaultPaths } from '@vigil/helper';

type Env = Record<string, string | undefined>;

/** A socket nothing listens on: the app stays unconnected and only simulates actions. */
export const NO_HELPER_SOCKET = '/nonexistent/vigil-e2e/helper.sock';

/**
 * The helper socket the app connects to. In a development build,
 * VIGIL_HELPER_SOCKET points it at an isolated helper. Under the e2e harness
 * (VIGIL_E2E) without one, the app talks to the installed helper only when
 * the run opted in to real enforcement; otherwise it connects to nothing.
 */
export function helperSocketFor(packaged: boolean, env: Env): string {
  const real = defaultPaths().socket;
  if (packaged) return real;
  const isolated = env['VIGIL_HELPER_SOCKET'];
  if (isolated) return isolated;
  if (env['VIGIL_E2E'] && env['VIGIL_ALLOW_REAL_ENFORCEMENT'] !== '1') return NO_HELPER_SOCKET;
  return real;
}

/** A throwaway profile folder for a development build (VIGIL_USER_DATA), so tests never open the real vigil.db. */
export function userDataFor(packaged: boolean, env: Env): string | undefined {
  return packaged ? undefined : env['VIGIL_USER_DATA'] || undefined;
}
