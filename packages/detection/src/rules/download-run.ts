/**
 * A shell command line that downloads something and has any way to run code.
 *
 * The download-then-run rule (shadow) uses this. It does not try to work out
 * whether the downloaded bytes reach the code runner, or whether the code is
 * harmless. It only asks two questions of the whole line, and answers yes
 * whenever it is unsure:
 *
 * 1. Does a downloader word (curl, wget, aria2c, http, or fetch run as a
 *    command) appear anywhere, including inside quotes, eval arguments,
 *    function bodies and substitutions?
 * 2. Does any execution vector appear anywhere: an interpreter or shell name,
 *    eval or source, process substitution, a here-string, find -exec, tar
 *    --to-command, awk system(), a git `!` alias, xargs, env -S, exec -a,
 *    sed's e flag, a substitution used as a program name, or a pipe into
 *    anything other than a short list of programs that only read or print?
 *
 * Both questions are asked of the raw text and of a lightly cleaned copy:
 * quotes and backslashes dropped, backslash-newlines joined and ${IFS}
 * turned into a space. That is only to find words someone broke up; it is
 * not a shell parser.
 *
 * Claude Code's harness wraps each command as `eval '<command>'` (optionally
 * after sourcing its shell snapshot). The wrapper's eval only runs the quoted
 * text, so an exact wrapper is replaced by the text it runs before the
 * questions are asked. Anything else that looks like a wrapper is not
 * unwrapped, and its eval counts as an execution vector.
 */

import { CWD_FILE, SNAPSHOT } from './quiet-lines.js';

/** Characters a word may start after (`/` for full paths, `=` and `!` for aliases). */
const BEFORE = '(?:^|[\\s;&|(){}<>`\'"=/!])';
/** Characters a word may end before. */
const AFTER = '(?=$|[\\s;&|(){}<>`\'"])';
/** The start of a simple command: line start, after an operator, or in a substitution. */
const COMMAND = '(?:^|[;&|({\\n`]|\\$\\(|(?:then|do|else)\\s)\\s*';

const word = (alts: string) => new RegExp(`${BEFORE}(?:${alts})${AFTER}`);

const DOWNLOADERS = [word('curl|wget|aria2c|http'), new RegExp(`${COMMAND}fetch${AFTER}`)];

export const INTERPRETERS = [
  'sh',
  'bash',
  'zsh',
  'dash',
  'ksh',
  'fish',
  'python[0-9.]*',
  'node',
  'perl',
  'ruby',
  'php',
  'osascript',
];

const VECTORS: RegExp[] = [
  word(INTERPRETERS.join('|')),
  word('eval|source'),
  new RegExp(`${COMMAND}\\.(?=\\s)`),
  /[<>]\(/, // process substitution
  /<<</, // here-string
  word('-exec|-execdir|-ok|-okdir'),
  /--to-command/,
  /\bsystem\s*\(/,
  /\balias\.[^\s=]*\s*=\s*!/,
  word('xargs'),
  new RegExp(`${BEFORE}env(?:\\s+-\\S+)*\\s+(?:-[A-Za-z]*S|--split-string)`),
  new RegExp(`${BEFORE}exec\\s+(?:-\\S+\\s+)*-[A-Za-z]*a${AFTER}`),
  // sed's e flag on an s command, or its e command.
  new RegExp(
    `${BEFORE}sed${AFTER}.*?s([^\\s\\w\\\\])(?:(?!\\1).)*\\1(?:(?!\\1).)*\\1[A-Za-z0-9]*e`,
  ),
  new RegExp(`${BEFORE}sed${AFTER}[^|;&\\n]*[\\s;{][0-9$,]*e(?=\\s|$)`),
  // A substitution used as (part of) the program name.
  new RegExp(`/\\$\\(|/\`|${COMMAND}\\$\\(|${COMMAND}\``),
];

/** Programs that only read, filter or print what is piped into them. */
const READERS = new Set([
  'jq',
  'yq',
  'head',
  'tail',
  'grep',
  'egrep',
  'fgrep',
  'rg',
  'less',
  'more',
  'cat',
  'wc',
  'sort',
  'uniq',
  'cut',
  'tr',
  'tee',
  'column',
  'fold',
  'nl',
  'sha256sum',
  'sha1sum',
  'shasum',
  'md5sum',
  'md5',
  'xxd',
  'hexdump',
  'od',
  'pbcopy',
]);

/** Each single `|` (or `|&`, never `||`) and the word after it. */
const PIPE = /(?:^|[^|])\|&?(?!\|)\s*([^\s;&|()<>]*)/g;

function pipesIntoRunner(text: string): boolean {
  for (const m of text.matchAll(PIPE)) {
    const consumer = m[1]!;
    const name = consumer.slice(consumer.lastIndexOf('/') + 1);
    if (!READERS.has(name)) return true;
  }
  return false;
}

/** Quotes and backslashes dropped, backslash-newlines joined, ${IFS} as a space. */
export function deobfuscate(text: string): string {
  return text
    .replace(/\\\r?\n/g, '')
    .replace(/\$\{IFS\}|\$IFS\b/g, ' ')
    .replace(/['"\\]/g, '');
}

/** Single-quoted text in which each ' is written '\''. */
const QUOTED = "((?:[^']|'\\\\'')*)";
const HARNESS = [
  new RegExp(`^eval '${QUOTED}'$`),
  new RegExp(`^source ${SNAPSHOT} && eval '${QUOTED}' < /dev/null && pwd -P >\\| ${CWD_FILE}$`),
];

/** The command an exact Claude Code wrapper runs, else the text unchanged. */
export function unwrapHarness(text: string): string {
  for (const re of HARNESS) {
    const m = re.exec(text);
    if (m) return m[1]!.replace(/'\\''/g, "'");
  }
  return text;
}

/** The text downloads something and has a way to run code. */
export function downloadsAndRuns(text: string): boolean {
  const forms = [text, deobfuscate(text)];
  const downloads = forms.some((t) => DOWNLOADERS.some((re) => re.test(t)));
  if (!downloads) return false;
  return forms.some((t) => VECTORS.some((re) => re.test(t)) || pipesIntoRunner(t));
}

/**
 * A shell's arguments after its own name, without bare flags like `-c` or
 * `-lc`, each unwrapped from Claude Code's harness when it matches exactly.
 */
export function shellScript(args: readonly string[] | undefined): string | undefined {
  if (!args || args.length < 2) return undefined;
  return args
    .slice(1)
    .filter((a) => !/^-[A-Za-z]+$/.test(a))
    .map(unwrapHarness)
    .join(' ');
}

/** A shell started with these arguments downloads something and can run code. */
export function shellDownloadsAndRuns(args: readonly string[] | undefined): boolean {
  const script = shellScript(args);
  return script !== undefined && downloadsAndRuns(script);
}
