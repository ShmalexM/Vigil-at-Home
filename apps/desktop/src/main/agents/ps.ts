// Reads the process table with `ps`, so the agent tracker knows what was
// already running when Vigil started (an agent launched earlier, say) and can
// fill holes the sensors left. Two spawns, at start and at most every 30 s on
// a miss; never per event. The parsing is in @vigil/detection (ps-table.ts).

import { execFile } from 'node:child_process';
import { mergePsArgs, parsePsComm, type PsRow } from '@vigil/detection';

const PS = '/bin/ps';
const TIMEOUT_MS = 3000;
const MAX_BUFFER = 8 * 1024 * 1024;

/** One `ps` run's output. The C locale fixes the `lstart` format the parser reads. */
export type RunPs = (args: string[]) => Promise<string>;

const runPs: RunPs = (args) =>
  new Promise((resolve, reject) =>
    execFile(
      PS,
      args,
      { env: { LC_ALL: 'C' }, timeout: TIMEOUT_MS, maxBuffer: MAX_BUFFER },
      (err, stdout) => (err ? reject(err) : resolve(String(stdout))),
    ),
  );

/**
 * Every process with its parent, start time, program and command line. The
 * command lines stay in memory (the tracker keeps them only where they decide
 * an agent match); nothing here is stored.
 */
export async function readProcessTable(run: RunPs = runPs): Promise<PsRow[]> {
  const comm = await run(['-axww', '-o', 'pid=,ppid=,lstart=,comm=']);
  const args = await run(['-axww', '-o', 'pid=,args=']);
  return mergePsArgs(parsePsComm(comm), args);
}
