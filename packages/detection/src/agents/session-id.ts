import { createHash } from 'node:crypto';

/**
 * One run of an agent, named after its root process: 16 hex characters of
 * sha256 over the agent, the root's pid and when it started, to the second.
 * A launch event and `ps` can put the same start in different seconds, so
 * when `ps` finds a root again (after it was forgotten, or after a restart)
 * the tracker reuses the start time the session was announced with, and the
 * id stays the same.
 */
export function sessionId(agentId: string, rootPid: number, rootStartTs: number): string {
  const startSec = Math.floor(rootStartTs / 1000);
  return createHash('sha256')
    .update(`${agentId}\0${rootPid}\0${startSec}`)
    .digest('hex')
    .slice(0, 16);
}
