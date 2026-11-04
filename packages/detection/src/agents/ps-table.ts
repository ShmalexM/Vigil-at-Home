/**
 * Parsing `ps` output, to learn the processes that were already running when
 * Vigil started (an agent launched earlier, say). Pure: the app spawns `ps`
 * with LC_ALL=C and hands the text here.
 */

export interface PsRow {
  pid: number;
  ppid: number;
  /** When the process started, in ms (ps reports whole seconds, local time). */
  startedAt: number;
  /**
   * What `comm` prints. On macOS that is argv[0] (`-zsh`, `node`, `claude`, a
   * full path only when the program was started by path), or a short name for
   * another user's process: a hint, not the executable a sensor reports.
   */
  path: string;
  /** From a second `ps` run. Kept in memory only, never stored. */
  args?: string[];
}

/** Longest command line kept per process. */
export const MAX_PS_ARGS = 1024;

const MONTHS: Record<string, number> = {
  Jan: 0,
  Feb: 1,
  Mar: 2,
  Apr: 3,
  May: 4,
  Jun: 5,
  Jul: 6,
  Aug: 7,
  Sep: 8,
  Oct: 9,
  Nov: 10,
  Dec: 11,
};

// `lstart` in the C locale is always 24 characters: "Wed Oct  1 20:53:59 2026".
const LSTART = String.raw`[A-Z][a-z]{2} ([A-Z][a-z]{2}) ([ \d]\d) (\d\d):(\d\d):(\d\d) (\d{4})`;
const COMM_LINE = new RegExp(String.raw`^\s*(\d+)\s+(\d+)\s+${LSTART} (.+)$`);
const START_LINE = new RegExp(String.raw`^\s*${LSTART}\s*$`);

/** The time an `lstart` names, in ms (local time), from its captured parts. */
function lstartMs(parts: string[]): number | undefined {
  const [mon, day, hh, mm, ss, year] = parts;
  const month = MONTHS[mon!];
  if (month === undefined) return undefined;
  return new Date(
    Number(year),
    month,
    Number(day!.trim()),
    Number(hh),
    Number(mm),
    Number(ss),
  ).getTime();
}

/** Rows of `ps -axww -o pid=,ppid=,lstart=,comm=`. Lines that do not parse are skipped. */
export function parsePsComm(text: string): PsRow[] {
  const rows: PsRow[] = [];
  for (const line of text.split('\n')) {
    const m = COMM_LINE.exec(line.replace(/\r$/, ''));
    if (!m) continue;
    const [, pid, ppid, mon, day, hh, mm, ss, year, comm] = m;
    // ps pads the column, so a bare name (`-zsh`, `claude`) can come with spaces before it.
    const path = comm!.trim();
    const startedAt = lstartMs([mon!, day!, hh!, mm!, ss!, year!]);
    if (startedAt === undefined || path === '') continue;
    rows.push({ pid: Number(pid), ppid: Number(ppid), startedAt, path });
  }
  return rows;
}

/** The start time from `ps -o lstart= -p <pid>`, in ms as parsePsComm gives it. */
export function parsePsStart(text: string): number | undefined {
  const m = START_LINE.exec(text.replace(/\r?\n$/, ''));
  return m ? lstartMs(m.slice(1)) : undefined;
}

/**
 * Add command lines from `ps -axww -o pid=,args=` to the rows. `ps` cannot
 * tell an argument's own spaces from the separators, so the line is split on
 * single spaces: joining the parts gives the line back exactly, which is all
 * agent matching needs.
 */
export function mergePsArgs(rows: PsRow[], argsText: string): PsRow[] {
  const byPid = new Map<number, string>();
  for (const line of argsText.split('\n')) {
    const m = /^\s*(\d+) (.*)$/.exec(line.replace(/\r$/, ''));
    if (!m || m[2]!.trim() === '') continue;
    byPid.set(Number(m[1]), m[2]!.trimEnd().slice(0, MAX_PS_ARGS));
  }
  return rows.map((r) => {
    const args = byPid.get(r.pid);
    return args === undefined ? r : { ...r, args: args.split(' ') };
  });
}
