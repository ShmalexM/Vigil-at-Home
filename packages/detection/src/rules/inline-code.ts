// Does a shell command run something it downloads with curl or wget? Backs the
// `process.pipesDownloadIntoCode` field (fields.ts), which the download-run
// rules key on.
//
// The decision is fail-closed. The command line is read with a small shell
// lexer (quotes, escapes, $( ), backticks, <( ), wrapper commands, `eval` and
// `sh -c` bodies), never run. A download (curl or wget in a program position)
// anywhere in it — including inside a substitution, an assignment value, or an
// `eval` body — together with any interpreter, shell or `eval` in a program
// position anywhere in it, is treated as running the download. A program name
// that cannot be resolved (a variable, a substitution, an unknown wrapper
// option) counts as an interpreter. Nothing tries to prove the downloaded code
// harmless.
//
// Two things stay quiet: a download whose consumers are all ordinary
// non-executing tools (so no interpreter appears anywhere), and a small set of
// real Claude Code command lines matched as exact templates over the
// normalized form (see TEMPLATES), including the harness wrapper Claude Code
// runs them through.

/** How deep the reader follows substitutions and nested shells. */
const MAX_DEPTH = 8;
/** Longest command read; a longer one is treated as running. */
const MAX_COMMAND = 64 * 1024;

const DOWNLOADERS = new Set(['curl', 'wget']);
/** Programs that run code given to them: a download reaching one is run. */
const INTERPRETERS = new Set([
  'sh',
  'bash',
  'zsh',
  'dash',
  'ksh',
  'fish',
  'python',
  'node',
  'perl',
  'ruby',
  'php',
  'osascript',
  'eval',
  'source',
  '.',
]);
/** Shells that take a command with -c, whose argument is read as a command. */
const SHELLS = new Set(['sh', 'bash', 'zsh', 'dash', 'ksh', 'fish']);
/** Shell reserved words that stand before a command, not a program themselves. */
const KEYWORDS = new Set([
  'for',
  'while',
  'until',
  'if',
  'elif',
  'then',
  'else',
  'do',
  'done',
  'fi',
  'case',
  'esac',
  'in',
  'select',
  'function',
  'then',
  '{',
  '}',
  '!',
]);
/**
 * Programs that run the program named after them. Each lists the options that
 * take a value; any other option is left for the reader to reject as unknown.
 */
const WRAPPERS: Record<string, { value: Set<string>; flag?: Set<string> }> = {
  env: { value: new Set(['-u', '-C', '-P', '--unset', '--chdir']) },
  sudo: {
    value: new Set([
      '-u',
      '-g',
      '-p',
      '-C',
      '-U',
      '-r',
      '-t',
      '-h',
      '-D',
      '-R',
      '--user',
      '--group',
    ]),
  },
  nice: { value: new Set(['-n', '--adjustment']) },
  ionice: { value: new Set(['-c', '-n', '-p', '-P', '-u']) },
  stdbuf: { value: new Set(['-i', '-o', '-e', '--input', '--output', '--error']) },
  doas: { value: new Set(['-u', '-C', '-a']) },
  timeout: { value: new Set(['-s', '-k', '--signal', '--kill-after']) },
  nohup: { value: new Set() },
  command: { value: new Set() },
  exec: { value: new Set() },
  builtin: { value: new Set() },
  time: { value: new Set() },
  setsid: { value: new Set() },
  xargs: { value: new Set(['-I', '-n', '-P', '-d', '-E', '-s', '-a', '-L']) },
};
const ASSIGNMENT_RE = /^[A-Za-z_][A-Za-z0-9_]*=/;
/** A shell's command option: -c, and the ones that may precede it (-l, -i, -e, -x, -s). */
const SHELL_C_RE = /^-[A-Za-z]*c[A-Za-z]*$/;

function basename(p: string): string {
  const i = p.lastIndexOf('/');
  return i === -1 ? p : p.slice(i + 1);
}

/** python3.12 and python2 are python; the rest keep their name. */
function family(name: string): string {
  const m = /^(python|perl|ruby|node|bash|zsh|dash|ksh|sh|fish|php|curl|wget)[0-9.]*$/.exec(name);
  return m ? m[1]! : name;
}

/**
 * Fold away two spellings before lexing: a backslash before a newline joins
 * the two lines (so a word split across lines reads as one), and ${IFS} or
 * $IFS (the field separator, a space by default) becomes a space.
 */
function preprocess(cmd: string): string {
  return cmd
    .replace(/\\\r?\n/g, '')
    .replace(/\$\{IFS\}/g, ' ')
    .replace(/\$IFS(?![A-Za-z0-9_])/g, ' ');
}

// ------------------------------------------------------------------ shell lexer

interface Word {
  /** The literal text, with substitutions left out and quotes removed. */
  text: string;
  /** The bodies of the $( ), ` ` and <( ) substitutions inside this word. */
  subs: string[];
  /** A quote or expansion this reader could not resolve, so the word is not trustworthy. */
  unsure: boolean;
}

type Token = { word: Word } | { op: string };

/** Index just past the `)` that closes the `(` before `i`, skipping quoted text. */
function closeParen(s: string, i: number): number | undefined {
  let depth = 1;
  while (i < s.length) {
    const c = s[i]!;
    if (c === '\\') i += 2;
    else if (c === "'") {
      const end = s.indexOf("'", i + 1);
      if (end === -1) return undefined;
      i = end + 1;
    } else if (c === '"') {
      i++;
      while (i < s.length && s[i] !== '"') i += s[i] === '\\' ? 2 : 1;
      if (i >= s.length) return undefined;
      i++;
    } else {
      if (c === '(') depth++;
      else if (c === ')' && --depth === 0) return i + 1;
      i++;
    }
  }
  return undefined;
}

/** Words and operators of a shell command, or undefined when a quote is left open. */
function lex(s: string): Token[] | undefined {
  const toks: Token[] = [];
  let text: string | undefined;
  let subs: string[] = [];
  let unsure = false;
  const end = () => {
    if (text !== undefined || subs.length || unsure) {
      toks.push({ word: { text: text ?? '', subs, unsure } });
      text = undefined;
      subs = [];
      unsure = false;
    }
  };
  const op = (o: string) => {
    end();
    toks.push({ op: o });
  };
  let i = 0;
  while (i < s.length) {
    const c = s[i]!;
    if (c === ' ' || c === '\t') {
      end();
      i++;
    } else if (c === '#' && text === undefined && subs.length === 0) {
      while (i < s.length && s[i] !== '\n') i++;
    } else if (c === '\n' || c === ';' || c === '&' || c === '|') {
      const two = s.slice(i, i + 2);
      const known = ['&&', '||', ';;', '|&'].includes(two) ? two : c === '\n' ? ';' : c;
      op(known);
      i += known.length === 2 ? 2 : 1;
    } else if ((c === '<' || c === '>') && s[i + 1] === '(') {
      const close = closeParen(s, i + 2);
      if (close === undefined) return undefined;
      subs.push(s.slice(i + 2, close - 1));
      unsure = true; // its output becomes a path; nothing good uses it as a program
      i = close;
    } else if (c === '(' || c === ')') {
      // A subshell grouping; its contents are judged as their own command.
      end();
      i++;
    } else if (c === '<' || c === '>') {
      // A redirection and its target are not part of any command's program.
      op('redir');
      let j = i + 1;
      while (j < s.length && '<>&|'.includes(s[j]!)) j++;
      i = j;
    } else if (c === "'") {
      const close = s.indexOf("'", i + 1);
      if (close === -1) return undefined;
      text = (text ?? '') + s.slice(i + 1, close);
      i = close + 1;
    } else if (c === '$' && s[i + 1] === "'") {
      // ANSI-C quoting, whose escapes this reader does not decode.
      const close = s.indexOf("'", i + 2);
      if (close === -1) return undefined;
      const body = s.slice(i + 2, close);
      if (/\\/.test(body)) unsure = true;
      else text = (text ?? '') + body;
      i = close + 1;
    } else if (c === '"') {
      i++;
      for (;;) {
        if (i >= s.length) return undefined;
        const d = s[i]!;
        if (d === '"') break;
        if (d === '\\' && i + 1 < s.length && '$`"\\\n'.includes(s[i + 1]!)) {
          text = (text ?? '') + s[i + 1];
          i += 2;
        } else if (d === '$' && s[i + 1] === '(') {
          const close = closeParen(s, i + 2);
          if (close === undefined) return undefined;
          subs.push(s.slice(i + 2, close - 1));
          i = close;
        } else if (d === '`') {
          const close = s.indexOf('`', i + 1);
          if (close === -1) return undefined;
          subs.push(s.slice(i + 1, close));
          i = close + 1;
        } else {
          text = (text ?? '') + d;
          i++;
        }
      }
      i++;
    } else if (c === '\\') {
      if (i + 1 < s.length) text = (text ?? '') + s[i + 1];
      i += 2;
    } else if (c === '$' && s[i + 1] === '(') {
      const close = closeParen(s, i + 2);
      if (close === undefined) return undefined;
      subs.push(s.slice(i + 2, close - 1));
      i = close;
    } else if (c === '`') {
      const close = s.indexOf('`', i + 1);
      if (close === -1) return undefined;
      subs.push(s.slice(i + 1, close));
      i = close + 1;
    } else if (c === '$' && /[A-Za-z_{]/.test(s[i + 1] ?? '')) {
      // $VAR / ${VAR}: kept literally so a later `eval "$VAR"` can be spotted.
      text = (text ?? '') + c;
      i++;
    } else {
      text = (text ?? '') + c;
      i++;
    }
  }
  end();
  return toks;
}

// ------------------------------------------------------------- command structure

interface Stage {
  words: Word[];
}
interface Command {
  stages: Stage[];
}

/** Split tokens into commands (at ; && || &) and each command into pipe stages. */
function commandsOf(toks: Token[]): Command[] {
  const commands: Command[] = [];
  let stages: Stage[] = [];
  let words: Word[] = [];
  let skip = false;
  const endStage = () => {
    stages.push({ words });
    words = [];
  };
  const endCommand = () => {
    endStage();
    commands.push({ stages });
    stages = [];
  };
  for (const t of toks) {
    if ('word' in t) {
      if (skip) skip = false;
      else words.push(t.word);
    } else if (t.op === 'redir') {
      skip = true; // the redirection target is not an argument
    } else if (t.op === '|' || t.op === '|&') {
      endStage();
    } else {
      endCommand();
    }
  }
  endCommand();
  return commands;
}

// ----------------------------------------------------------- program position

type Exec =
  | { kind: 'none' }
  | { kind: 'unresolved' }
  | { kind: 'name'; name: string; cArg?: string; evalLiterals?: string[] };

/**
 * The program a stage runs: its normalized family name, or `unresolved` when
 * the program is a variable, a substitution or sits behind a wrapper option
 * this reader does not know (fail closed). Leading assignments and shell
 * keywords are skipped, and known wrapper commands are stepped over along with
 * their options. For a shell it also returns the `-c` command; for `eval`,
 * `source` or `.` the literal words it would run.
 */
function stageExec(stage: Stage): Exec {
  const words = stage.words;
  let i = 0;
  while (i < words.length) {
    const w = words[i]!;
    if (w.unsure || (w.text === '' && w.subs.length)) return { kind: 'unresolved' };
    if (w.text === '' || KEYWORDS.has(w.text) || ASSIGNMENT_RE.test(w.text)) {
      i++;
      continue;
    }
    const name = family(basename(w.text));
    const wrapper = WRAPPERS[name];
    if (wrapper) {
      i++;
      while (i < words.length) {
        const a = words[i]!;
        if (a.unsure) return { kind: 'unresolved' };
        if (ASSIGNMENT_RE.test(a.text)) {
          i++;
        } else if (a.text === '--') {
          i++;
          break;
        } else if (a.text.startsWith('-') && a.text !== '-') {
          if (wrapper.value.has(a.text))
            i++; // this option takes the next word
          else if (!/^-[A-Za-z0-9]+$/.test(a.text)) return { kind: 'unresolved' };
          i++;
        } else break;
      }
      continue;
    }
    // A program named by a variable is not resolvable; fail closed.
    if (w.text.includes('$')) return { kind: 'unresolved' };
    const rest = words.slice(i + 1);
    if (SHELLS.has(name)) {
      const ci = rest.findIndex((x) => SHELL_C_RE.test(x.text));
      const arg = ci >= 0 ? rest[ci + 1] : undefined;
      if (arg === undefined) return { kind: 'name', name };
      return { kind: 'name', name, cArg: arg.subs.length === 0 ? arg.text : '' };
    }
    if (name === 'eval' || name === 'source' || name === '.') {
      const literals = rest.filter((x) => x.subs.length === 0 && x.text !== '').map((x) => x.text);
      return { kind: 'name', name, evalLiterals: literals };
    }
    return { kind: 'name', name };
  }
  return { kind: 'none' };
}

// --------------------------------------------------------------------- scanning

interface Acc {
  download: boolean;
  interp: boolean;
}

/** Walk `src`, marking whether it contains a download and an interpreter anywhere. */
function scan(src: string, depth: number, acc: Acc): void {
  if (acc.download && acc.interp) return;
  if (depth > MAX_DEPTH || src.length > MAX_COMMAND) {
    acc.download = true;
    acc.interp = true;
    return;
  }
  const toks = lex(src);
  if (!toks) {
    acc.download = true;
    acc.interp = true;
    return;
  }
  for (const cmd of commandsOf(toks))
    for (const stage of cmd.stages) {
      for (const w of stage.words) for (const sub of w.subs) scan(sub, depth + 1, acc);
      const r = stageExec(stage);
      if (r.kind === 'unresolved') {
        acc.interp = true;
      } else if (r.kind === 'name') {
        if (DOWNLOADERS.has(r.name)) acc.download = true;
        if (INTERPRETERS.has(r.name)) acc.interp = true;
        if (r.cArg !== undefined) scan(r.cArg, depth + 1, acc);
        if (r.evalLiterals) for (const lit of r.evalLiterals) scan(lit, depth + 1, acc);
      }
      if (acc.download && acc.interp) return;
    }
}

// ------------------------------------------------------------- harness & guard

/** The `'\''` idiom restored to a single quote. */
function unescapeSingleQuoted(s: string): string {
  return s.replace(/'\\''/g, "'");
}

/**
 * Claude Code runs a step through a fixed harness. Strip it to the one command
 * it runs, so the harness's own `source`/`eval` are not mistaken for the step
 * running a download. Only the exact harness shapes are stripped.
 */
function unwrapHarness(cmd: string): string | undefined {
  const full = /^source \S+ && eval '([\s\S]*)' < \/dev\/null && pwd -P >\| \S+$/.exec(cmd);
  if (full) return unescapeSingleQuoted(full[1]!);
  const bare = /^eval '([\s\S]*)'$/.exec(cmd);
  if (bare) return unescapeSingleQuoted(bare[1]!);
  return undefined;
}

/** A cheap test for a downloader anywhere, seeing through quotes and backslashes. */
function mentionsDownloader(cmd: string): boolean {
  const bare = cmd.replace(/['"\\]/g, '');
  return bare.includes('curl') || bare.includes('wget');
}

// ------------------------------------------------------------- real-line templates

const HOST = String.raw`(?:127\.0\.0\.1|localhost)`;
const PORT = String.raw`\d{2,5}`;
/** JSON keys the real lines read; a narrow slot, not free text. */
const KEY = String.raw`(?:token|state|models|name|id|a|b)`;

/**
 * The exact Claude Code command lines that read a local service's JSON through
 * a short python one-liner, which would otherwise look like running a
 * download. Matched anchored over the normalized command; the only free slots
 * are a loopback host, a port number and a JSON key from the set above.
 */
const TEMPLATES: RegExp[] = [
  new RegExp(
    `^T=\\$\\(curl -s http://${HOST}:${PORT}/api/bootstrap \\| python3 -c "import json,sys;print\\(json\\.load\\(sys\\.stdin\\)\\['${KEY}'\\]\\)"\\) && for code in a b; do python3 -c "import urllib\\.request; urllib\\.request\\.urlopen\\('http://${HOST}:${PORT}/api/run'\\)"; done$`,
  ),
  new RegExp(
    `^for i in 1 2 3; do S=\\$\\(curl -s -m 8 http://${HOST}:${PORT}/api/status \\| python3 -c "import json,sys; print\\(json\\.load\\(sys\\.stdin\\)\\['${KEY}'\\]\\)"\\); echo \\$S; sleep 2; done$`,
  ),
  new RegExp(
    `^for i in 1 2 3; do curl -s -m 8 http://${HOST}:${PORT}/api/ps \\| python3 -c "import json,sys; d=json\\.load\\(sys\\.stdin\\); print\\(\\[m\\['${KEY}'\\] for m in d\\.get\\('${KEY}',\\[\\]\\)\\]\\)"; sleep 2; done$`,
  ),
  new RegExp(
    `^curl -s -m 3 http://${HOST}:${PORT}/api/tags \\| python3 -c "import sys,json; print\\(json\\.load\\(sys\\.stdin\\)\\)"$`,
  ),
];

function matchesTemplate(cmd: string): boolean {
  return TEMPLATES.some((re) => re.test(cmd));
}

/**
 * True when the command runs code it downloads with curl or wget: a download
 * anywhere on the line (including in a substitution, an assignment value or an
 * `eval` body) together with any interpreter, shell or `eval` in a program
 * position. Reads the command without running it; anything it cannot read with
 * confidence is treated as running. The known real Claude Code lines, and the
 * harness wrapper Claude Code runs them through, are the only exemptions.
 */
export function pipesDownloadIntoCode(command: string): boolean {
  const norm = preprocess(command);
  if (!mentionsDownloader(norm)) return false;
  const inner = unwrapHarness(norm);
  const target = inner ?? norm;
  if (matchesTemplate(target)) return false;
  const acc: Acc = { download: false, interp: false };
  scan(target, 0, acc);
  return acc.download && acc.interp;
}
