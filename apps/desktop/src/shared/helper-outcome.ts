import type { HelperOutcome } from './ipc.js';

/** Shown when a rule change was not made because the admin password was cancelled. */
export const PASSWORD_CANCELLED = 'Not changed: the admin password was cancelled';

/** What to tell the person when the helper turned a change down; undefined when it went through. */
export function notChangedText(helper: HelperOutcome, reason?: string): string | undefined {
  if (helper === 'declined') return PASSWORD_CANCELLED;
  if (helper === 'failed') return `Not changed: ${reason ?? 'the background helper refused it'}`;
  return undefined;
}
