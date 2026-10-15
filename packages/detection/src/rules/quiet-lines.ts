/**
 * Exact command lines the download-run rule stays quiet on.
 *
 * Claude Code's Bash tool reads local services' JSON with lines like
 * `S=$(curl -s http://127.0.0.1:17010/api/status | python3 -c "…")`. The
 * download-run rule fires on `$(curl`, so these raised alerts on a real
 * developer Mac. Rather than judge what a command does, this keeps a short
 * list of those real lines and matches the whole command, anchored, against
 * them. Anything else, including a real line with one character added,
 * removed or changed, falls through to the rule unchanged.
 *
 * The only free slots are a loopback host, a port made of digits and a JSON
 * key from a fixed set. The forms Claude Code's harness wraps a line in
 * (`eval '…'`, and `source <snapshot> && eval '…' < /dev/null && pwd -P >| <file>`)
 * are separate exact templates, built here from the same text. Their path
 * slots are pinned to the harness's real layout and hold no spaces or shell
 * metacharacters. Nothing is unquoted, unwrapped or normalized before
 * matching, and the shell must be a system shell started with an exact argv.
 */

const HOST = '(?:127\\.0\\.0\\.1|localhost)';
const PORT = '[0-9]{2,5}';
/** JSON keys the real lines read. */
const KEY = '(?:token|state|models|name|id)';
/**
 * The harness's shell snapshot: `~/.claude/shell-snapshots/snapshot-<shell>-<digits>-<id>.sh`
 * in the home of the user the shell runs as (checked in `isQuietLine`). This
 * does not vouch for the snapshot's contents, and the path is matched as
 * spelled, so a symlink there could point anywhere. Whoever can write that
 * file or link can already run code through any line main never alerts on,
 * and the cwd write is the harness's own, so accepting the wrapper opens no
 * new path.
 */
const SNAPSHOT =
  '/(?:Users|home)/(?<home>[A-Za-z0-9_-][A-Za-z0-9._-]*)/\\.claude/shell-snapshots/snapshot-(?:zsh|bash)-[0-9]+-[a-z0-9]+\\.sh';
/** Where the harness records the cwd: the macOS per-user temp folder, or /tmp. */
const CWD_FILE = '(?:/var/folders/[A-Za-z0-9_+-]{2}/[A-Za-z0-9_+-]+/T|/tmp)/claude-[0-9a-f]+-cwd';

/** The real lines, with {HOST}, {PORT} and {KEY} marking the free slots. */
const LINES = [
  `T=$(curl -s http://{HOST}:{PORT}/api/bootstrap | python3 -c "import json,sys;print(json.load(sys.stdin)['{KEY}'])") && for code in a b; do python3 -c "import urllib.request; urllib.request.urlopen('http://{HOST}:{PORT}/api/run')"; done`,
  `for i in 1 2 3; do S=$(curl -s -m 8 http://{HOST}:{PORT}/api/status | python3 -c "import json,sys; print(json.load(sys.stdin)['{KEY}'])"); echo $S; sleep 2; done`,
  `for i in 1 2 3; do curl -s -m 8 http://{HOST}:{PORT}/api/ps | python3 -c "import json,sys; d=json.load(sys.stdin); print([m['{KEY}'] for m in d.get('{KEY}',[])])"; sleep 2; done`,
  `curl -s -m 3 http://{HOST}:{PORT}/api/tags | python3 -c "import sys,json; print(json.load(sys.stdin))"`,
];

const SLOTS: Record<string, string> = { HOST, PORT, KEY };

/** A line's text as a regex: literal text escaped, slots filled in. */
function pattern(line: string): string {
  return line
    .split(/(\{HOST\}|\{PORT\}|\{KEY\})/)
    .map((part, i) =>
      i % 2 === 1 ? SLOTS[part.slice(1, -1)]! : part.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'),
    )
    .join('');
}

/**
 * The two exact wrappers Claude Code's harness puts a command in, as anchored
 * regex sources around `quoted` (a pattern for the command with each ' written
 * '\''). The download-then-run rule unwraps these same shapes.
 */
export function harnessWrappers(quoted: string): string[] {
  return [
    `^eval '${quoted}'$`,
    `^source ${SNAPSHOT} && eval '${quoted}' < /dev/null && pwd -P >\\| ${CWD_FILE}$`,
  ];
}

const TEMPLATES: RegExp[] = LINES.flatMap((line) => {
  const raw = pattern(line);
  // Inside the harness's single quotes each ' is written '\''.
  const quoted = pattern(line.replace(/'/g, `'\\''`));
  return [`^${raw}$`, ...harnessWrappers(quoted)].map((src) => new RegExp(src));
});

/**
 * The whole string is one of the quiet templates. The snapshot form also
 * needs the shell's user, and its snapshot must be in that user's own home
 * (never /Users/Shared); without a user it is not quiet.
 */
export function isQuietLine(cmd: string, user?: string): boolean {
  return TEMPLATES.some((re) => {
    const m = re.exec(cmd);
    if (!m) return false;
    const home = m.groups?.home;
    return home === undefined || (home === user && home !== 'Shared');
  });
}

/** System shells only: no Homebrew or home-folder copies. */
const SYSTEM_SHELLS = new Set([
  '/bin/bash',
  '/bin/zsh',
  '/bin/sh',
  '/usr/bin/bash',
  '/usr/bin/zsh',
  '/usr/bin/sh',
]);

/**
 * The process is a system shell, with argv[0] the same path as the program,
 * started with exactly one of `-c <line>`, `-lc <line>` or `-l -c <line>`,
 * and <line> is a quiet template for the shell's user. Arguments are compared one by one, never
 * joined, and any extra argument fails.
 */
export function runsQuietLine(
  path: string | undefined,
  args: readonly string[] | undefined,
  user?: string,
): boolean {
  if (!path || !args || !SYSTEM_SHELLS.has(path) || args[0] !== path) return false;
  const line =
    args.length === 3 && (args[1] === '-c' || args[1] === '-lc')
      ? args[2]
      : args.length === 4 && args[1] === '-l' && args[2] === '-c'
        ? args[3]
        : undefined;
  return line !== undefined && isQuietLine(line, user);
}
