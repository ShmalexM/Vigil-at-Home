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
 * slots hold no spaces or shell metacharacters. Nothing is unquoted,
 * unwrapped or normalized before matching.
 */

const HOST = '(?:127\\.0\\.0\\.1|localhost)';
const PORT = '[0-9]{2,5}';
/** JSON keys the real lines read. */
const KEY = '(?:token|state|models|name|id)';
/** The harness's shell snapshot and its cwd record file. */
export const SNAPSHOT =
  '(?:/Users|/home)/[A-Za-z0-9._-]+/\\.claude/shell-snapshots/snapshot-(?:zsh|bash)-[0-9]+-[a-z0-9]+\\.sh';
export const CWD_FILE = '(?:/private)?(?:/var/folders/[A-Za-z0-9_+/-]+|/tmp)/claude-[0-9a-f]+-cwd';

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

const TEMPLATES: RegExp[] = LINES.flatMap((line) => {
  const raw = pattern(line);
  // Inside the harness's single quotes each ' is written '\''.
  const quoted = pattern(line.replace(/'/g, `'\\''`));
  return [
    `^${raw}$`,
    `^eval '${quoted}'$`,
    `^source ${SNAPSHOT} && eval '${quoted}' < /dev/null && pwd -P >\\| ${CWD_FILE}$`,
  ].map((src) => new RegExp(src));
});

/** The whole string is one of the quiet templates. */
export function isQuietLine(cmd: string): boolean {
  return TEMPLATES.some((re) => re.test(cmd));
}

/** The flag spellings a shell may be started with before its command. */
const COMMAND_FLAGS = ['-c', '-c -l', '-l -c', '-lc'];

/**
 * The process is a shell started as exactly `<shell> -c <line>` (or with a
 * login flag) and <line> is a quiet template. Any extra argument fails.
 */
export function runsQuietLine(args: readonly string[] | undefined): boolean {
  if (!args || args.length < 3 || args.length > 4) return false;
  const flags = args.slice(1, -1).join(' ');
  return COMMAND_FLAGS.includes(flags) && isQuietLine(args[args.length - 1]!);
}
