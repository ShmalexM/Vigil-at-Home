import { createHash } from 'node:crypto';

/**
 * One run of an agent, named after its root process: 16 hex characters of
 * sha256 over the agent, the root's pid and when it started. The start is
 * taken to the second, so a session Vigil finds again through `ps` after a
 * restart (which reports seconds) keeps the id it had from the launch.
 */
export function sessionId(agentId: string, rootPid: number, rootStartTs: number): string {
  const startSec = Math.floor(rootStartTs / 1000);
  return createHash('sha256')
    .update(`${agentId}\0${rootPid}\0${startSec}`)
    .digest('hex')
    .slice(0, 16);
}
