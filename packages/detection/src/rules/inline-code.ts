// Does a shell command run something it downloads with curl or wget? Used by
// the `process.pipesDownloadIntoCode` field (fields.ts), alongside the regexes
// in macos-core.ts that catch the plain `curl … | sh` and `sh -c "$(curl …)"`
// shapes.
//
// This file covers what a regex over the raw line cannot read safely:
//   - a download piped into python, perl, ruby or node. Perl and ruby always
//     run it. python and node run it unless the inline program (`-c`/`-e`)
//     only reads the download as data, which is decided by a strict allowlist
//     of names, attributes and keys (pythonReadsOnly, nodeReadsOnly) — never a
//     denylist, so an unlisted name is refused rather than missed;
//   - a download captured into a variable and then run (`V=$(curl …); sh -c
//     "$V"`, `eval "$V"`);
//   - the same written in a way a plain regex misses: ${IFS}/$IFS word splits,
//     a line continuation inside a word, quoted or backslash-escaped program
//     names, and env/sudo wrappers before the interpreter.
//
// The command is read with a small shell lexer (quotes, escapes, $( ),
// backticks, <( ), and `eval`/`sh -c` bodies read again), never run. When a
// stage cannot be read with confidence, it is treated as running the download.

/** How deep the lexer follows substitutions and nested shells. */
const MAX_DEPTH = 6;
/** Longest command read; a longer one is treated as running. */
const MAX_COMMAND = 64 * 1024;
/** Longest inline program the allowlists read. */
const MAX_CODE = 4096;

const DOWNLOADERS = new Set(['curl', 'wget']);
const INTERPRETERS = new Set(['python', 'perl', 'ruby', 'node']);
const SHELLS = new Set(['sh', 'bash', 'zsh', 'dash', 'ksh']);
/** Programs that run the program named after them; their own options and VAR=val are skipped. */
const WRAPPERS = new Set([
  'sudo',
  'env',
  'command',
  'exec',
  'nice',
  'nohup',
  'builtin',
  'time',
  'stdbuf',
  'setsid',
  'ionice',
  'doas',
]);
const ASSIGNMENT_RE = /^[A-Za-z_][A-Za-z0-9_]*=/;
const SHELL_C_RE = /^-[A-Za-z]*[ce][A-Za-z]*$/;

function basename(p: string): string {
  const i = p.lastIndexOf('/');
  return i === -1 ? p : p.slice(i + 1);
}

/** python3.12 and python2 are python; the rest keep their name. */
function family(name: string): string {
  const m = /^(python|perl|ruby|node|bash|zsh|dash|ksh|sh|curl|wget)[0-9.]*$/.exec(name);
  return m ? m[1]! : name;
}

// --------------------------------------------------------------- preprocessing

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

/** The program a stage runs: its name family, skipping VAR=val and wrapper commands. */
function stageProgram(stage: Stage): {
  name?: string;
  unsure: boolean;
  wrapped: boolean;
  rest: Word[];
} {
  const words = stage.words;
  let i = 0;
  let wrapped = false;
  while (i < words.length) {
    const w = words[i]!;
    if (w.unsure || (w.text === '' && w.subs.length)) return { unsure: true, wrapped, rest: [] };
    if (w.text === '' && !w.subs.length) {
      i++;
      continue;
    }
    if (ASSIGNMENT_RE.test(w.text)) {
      wrapped = true; // an inline VAR=val changes the environment the program runs in
      i++;
      continue;
    }
    const name = family(basename(w.text));
    if (WRAPPERS.has(name)) {
      wrapped = true;
      i++;
      // Skip this wrapper's own options and, for env, its VAR=val pairs.
      while (i < words.length) {
        const a = words[i]!;
        if (a.unsure) return { unsure: true, wrapped, rest: [] };
        if (a.text.startsWith('-') || ASSIGNMENT_RE.test(a.text)) i++;
        else break;
      }
      continue;
    }
    return { name, unsure: false, wrapped, rest: words.slice(i) };
  }
  return { unsure: false, wrapped, rest: [] };
}

// --------------------------------------------------------------------- judging

interface Ctx {
  downloadVars: Set<string>;
}

/** Does a stage's words, as an interpreter invocation, run what it reads? */
function interpreterRuns(words: Word[]): boolean {
  if (words.some((w) => w.unsure)) return true;
  const name = family(basename(words[0]!.text));
  const args = words.slice(1).map((w) => w.text);
  if (name === 'perl' || name === 'ruby') return true;
  if (name === 'python') {
    let i = 0;
    while (i < args.length && /^-[uIESBsqOdvx]+$/.test(args[i]!)) i++;
    if (args[i] === '-m' && args[i + 1] === 'json.tool')
      return !args
        .slice(i + 2)
        .every((a) =>
          /^(--(sort-keys|compact|no-ensure-ascii|json-lines|tab|indent)|\d{1,3})$/.test(a),
        );
    if (args[i] !== '-c' || args[i + 1] === undefined) return true;
    return !pythonReadsOnly(args[i + 1]!);
  }
  if (name === 'node') {
    if (!['-e', '--eval', '-p', '--print'].includes(args[0] ?? '') || args[1] === undefined)
      return true;
    return !nodeReadsOnly(args[1]!);
  }
  return true;
}

/** A word references one of the capture variables (`$V`, `${V}`, `"$V"`). */
function referencesVar(w: Word, vars: Set<string>): boolean {
  if (!vars.size) return false;
  for (const m of w.text.matchAll(/\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?/g))
    if (vars.has(m[1]!)) return true;
  return false;
}

/** A pipeline runs a download when a download stage feeds a runner (or an unreadable) stage. */
function pipelineRuns(stages: Stage[]): boolean {
  const progs = stages.map(stageProgram);
  let seenDownload = false;
  for (const p of progs) {
    if (
      seenDownload &&
      (p.unsure || (p.name && (SHELLS.has(p.name) || INTERPRETERS.has(p.name))))
    ) {
      if (p.unsure || !p.name || SHELLS.has(p.name)) return true;
      // A wrapper (sudo, env, an inline VAR=val) before the interpreter is not how a
      // benign data read is written, and it changes how the program runs; treat it as run.
      if (p.wrapped || interpreterRuns(p.rest)) return true;
    }
    if (!p.unsure && p.name && DOWNLOADERS.has(p.name)) seenDownload = true;
  }
  return false;
}

/** Collect variables assigned the output of a command substitution that downloads. */
function collectDownloadVars(commands: Command[], ctx: Ctx, depth: number): void {
  for (const cmd of commands)
    for (const stage of cmd.stages)
      for (const w of stage.words) {
        const m = /^([A-Za-z_][A-Za-z0-9_]*)=/.exec(w.text);
        if (m && w.subs.some((sub) => judge(sub, depth + 1, true))) ctx.downloadVars.add(m[1]!);
      }
}

/** A stage runs a captured download variable: `eval "$V"`, `sh -c "$V"`. */
function runsCaptured(commands: Command[], vars: Set<string>): boolean {
  if (!vars.size) return false;
  for (const cmd of commands)
    for (const stage of cmd.stages) {
      const p = stageProgram(stage);
      if (p.unsure || !p.name) continue;
      if (p.name === 'eval' || p.name === 'source' || p.name === '.') {
        if (p.rest.slice(1).some((w) => referencesVar(w, vars))) return true;
      } else if (SHELLS.has(p.name)) {
        const hasC = p.rest.some((w) => SHELL_C_RE.test(w.text));
        if (hasC && p.rest.some((w) => referencesVar(w, vars))) return true;
      }
    }
  return false;
}

/**
 * The core walk. `downloadOnly` asks only whether the first stage downloads
 * (for capture-variable collection); otherwise it asks whether a download is
 * run anywhere in `src`, following substitutions and `eval`/`sh -c` bodies.
 */
function judge(src: string, depth: number, downloadOnly = false): boolean {
  if (src.length > MAX_COMMAND || depth > MAX_DEPTH) return true;
  const toks = lex(src);
  if (!toks) return true;
  const commands = commandsOf(toks);

  if (downloadOnly) {
    const first = commands[0]?.stages[0];
    if (!first) return false;
    const p = stageProgram(first);
    return !p.unsure && !!p.name && DOWNLOADERS.has(p.name);
  }

  // Substitutions anywhere are commands in their own right.
  for (const cmd of commands)
    for (const stage of cmd.stages)
      for (const w of stage.words) for (const sub of w.subs) if (judge(sub, depth + 1)) return true;

  for (const cmd of commands) if (pipelineRuns(cmd.stages)) return true;

  // `eval <code>` and `sh -c <code>` run another shell over text.
  for (const cmd of commands)
    for (const stage of cmd.stages) {
      const p = stageProgram(stage);
      if (p.unsure || !p.name) continue;
      if (p.name === 'eval' || p.name === 'source' || p.name === '.') {
        for (const w of p.rest.slice(1)) if (judge(w.text, depth + 1)) return true;
      } else if (SHELLS.has(p.name)) {
        const ci = p.rest.findIndex((w) => SHELL_C_RE.test(w.text));
        if (ci >= 0 && p.rest[ci + 1]) if (judge(p.rest[ci + 1]!.text, depth + 1)) return true;
      }
    }

  const ctx: Ctx = { downloadVars: new Set() };
  collectDownloadVars(commands, ctx, depth);
  return runsCaptured(commands, ctx.downloadVars);
}

/**
 * True when the command runs code it downloads with curl or wget: piped into
 * an interpreter that runs it, run through `eval`/`sh -c`, or captured into a
 * variable and then run. Reads the command without executing it; anything it
 * cannot read with confidence counts as running.
 */
export function pipesDownloadIntoCode(command: string): boolean {
  // A cheap gate: with no downloader named at all, nothing is run from a download.
  if (!command.includes('curl') && !command.includes('wget')) return false;
  return judge(preprocess(command), 0);
}

// ------------------------------------------------------ python inline allowlist

/** Names a data-reading `python -c` program may use (besides its own variables). */
const PY_ALLOWED = new Set([
  'json',
  'sys',
  'print',
  'len',
  'str',
  'int',
  'float',
  'round',
  'bool',
  'sorted',
  'reversed',
  'enumerate',
  'zip',
  'range',
  'list',
  'dict',
  'tuple',
  'set',
  'min',
  'max',
  'sum',
  'abs',
  'any',
  'all',
  'map',
  'filter',
  'for',
  'in',
  'if',
  'else',
  'elif',
  'and',
  'or',
  'not',
  'is',
  'None',
  'True',
  'False',
]);
/** Attribute names (after `.`) it may use, on anything. */
const PY_ATTRS = new Set([
  'load',
  'loads',
  'dump',
  'dumps',
  'read',
  'readline',
  'readlines',
  'stdin',
  'get',
  'items',
  'keys',
  'values',
  'append',
  'split',
  'rsplit',
  'strip',
  'lstrip',
  'rstrip',
  'join',
  'lower',
  'upper',
  'format',
  'startswith',
  'endswith',
  'replace',
]);
/** Names that mean code, refused wherever they appear (even as an assignment target). */
const PY_DENY = new Set([
  'exec',
  'eval',
  'compile',
  'open',
  'input',
  'getattr',
  'setattr',
  'delattr',
  'globals',
  'locals',
  'vars',
  'dir',
  'breakpoint',
  'memoryview',
  'bytearray',
  'os',
  'subprocess',
  'pickle',
  'marshal',
  'yaml',
  'importlib',
  'builtins',
  'ctypes',
  'socket',
  'shutil',
  'pty',
  'platform',
  'commands',
  'popen',
  'system',
  'lambda',
  'class',
  'def',
  'async',
  'await',
  'with',
  'yield',
  'global',
  'nonlocal',
  'from',
  'type',
  'super',
  'object',
  'property',
  'classmethod',
  'staticmethod',
  'vars',
]);
const PY_MODULES = new Set(['json', 'sys']);
const PY_OPS = [
  '**',
  '//',
  '==',
  '!=',
  '<=',
  '>=',
  '+=',
  '-=',
  '*=',
  '(',
  ')',
  '[',
  ']',
  '{',
  '}',
  ',',
  ':',
  '.',
  ';',
  '=',
  '<',
  '>',
  '+',
  '-',
  '*',
  '/',
  '%',
];

type PyTok =
  { k: 'name'; v: string } | { k: 'num' } | { k: 'str'; f: string[] } | { k: 'op'; v: string };

/** Python tokens, or undefined for anything outside the small language allowed. */
function pyTokens(code: string): PyTok[] | undefined {
  const out: PyTok[] = [];
  let i = 0;
  while (i < code.length) {
    const c = code[i]!;
    if (c === ' ' || c === '\t' || c === '\r') {
      i++;
      continue;
    }
    if (c === '\n') {
      out.push({ k: 'op', v: ';' });
      i++;
      continue;
    }
    if (c === '#') return undefined;
    const q = /^([rRuUfF]{0,2})('''|"""|'|")/.exec(code.slice(i, i + 5));
    if (q) {
      const prefix = q[1]!.toLowerCase();
      const quote = q[2]!;
      if (prefix.includes('b')) return undefined;
      let j = i + q[0].length;
      let body = '';
      for (;;) {
        if (j >= code.length) return undefined;
        if (code.startsWith(quote, j)) break;
        if (code[j] === '\\' && !prefix.includes('r')) {
          body += code.slice(j, j + 2);
          j += 2;
        } else {
          if (quote.length === 1 && code[j] === '\n') return undefined;
          body += code[j];
          j++;
        }
      }
      const f: string[] = [];
      if (prefix.includes('f'))
        for (let a = 0; a < body.length; a++) {
          if (body[a] === '{' && body[a + 1] === '{') a++;
          else if (body[a] === '}' && body[a + 1] === '}') a++;
          else if (body[a] === '{') {
            const close = body.indexOf('}', a);
            if (close === -1) return undefined;
            f.push(body.slice(a + 1, close).replace(/![rsa]$|:[^}]*$/, ''));
            a = close;
          }
        }
      out.push({ k: 'str', f });
      i = j + quote.length;
      continue;
    }
    const name = /^[A-Za-z_][A-Za-z0-9_]*/.exec(code.slice(i, i + 256));
    if (name) {
      out.push({ k: 'name', v: name[0] });
      i += name[0].length;
      continue;
    }
    const num = /^[0-9][0-9_.eExXoObB]*/.exec(code.slice(i, i + 64));
    if (num) {
      out.push({ k: 'num' });
      i += num[0].length;
      continue;
    }
    const op = PY_OPS.find((o) => code.startsWith(o, i));
    if (!op) return undefined;
    out.push({ k: 'op', v: op });
    i += op.length;
  }
  return out;
}

/**
 * True when a `python -c` program only reads its input as data. Every name,
 * attribute and keyword must be on the small allowlists above; any name that
 * means code (PY_DENY) is refused wherever it appears, so reassigning it does
 * not help; imports are limited to json and sys; and `__` is refused outright
 * (it blocks dunder access). A program's own variables are the plain names it
 * assigns or loops over, and they may not be a PY_DENY name. f-string
 * expressions are checked the same way.
 */
export function pythonReadsOnly(code: string): boolean {
  if (code.length > MAX_CODE || code.includes('__')) return false;
  const toks = pyTokens(code);
  if (!toks) return false;
  if (toks.some((t) => t.k === 'name' && PY_DENY.has(t.v))) return false;
  const locals = collectPyLocals(toks);
  return pyCheck(toks, locals);
}

/** The plain names a program assigns to or loops over (its own variables). */
function collectPyLocals(toks: PyTok[]): Set<string> {
  const locals = new Set<string>();
  let depth = 0;
  for (let i = 0; i < toks.length; i++) {
    const t = toks[i]!;
    if (t.k === 'op' && '([{'.includes(t.v)) depth++;
    else if (t.k === 'op' && ')]}'.includes(t.v)) depth--;
    const next = toks[i + 1];
    if (t.k === 'name' && depth === 0 && next?.k === 'op' && /^[-+*]?=$/.test(next.v)) {
      const prev = toks[i - 1];
      if (!prev || (prev.k === 'op' && (prev.v === ';' || prev.v === ':'))) locals.add(t.v);
    }
    if (t.k === 'name' && t.v === 'for')
      for (let j = i + 1; j < toks.length; j++) {
        const u = toks[j]!;
        if (u.k === 'name' && u.v === 'in') break;
        if (u.k === 'name') locals.add(u.v);
        else if (!(u.k === 'op' && '(),[]'.includes(u.v))) break;
      }
  }
  return locals;
}

function pyCheck(toks: PyTok[], locals: Set<string>): boolean {
  let depth = 0;
  let stmtStart = true;
  for (let i = 0; i < toks.length; i++) {
    const t = toks[i]!;
    const prev = toks[i - 1];
    if (t.k === 'op' && t.v === ';') {
      stmtStart = true;
      continue;
    }
    const atStart = stmtStart;
    stmtStart = false;
    if (t.k === 'op') {
      if ('([{'.includes(t.v)) depth++;
      else if (')]}'.includes(t.v)) depth--;
      if (depth < 0) return false;
      if (t.v === ':' && depth === 0) stmtStart = true;
      continue;
    }
    if (t.k === 'num') continue;
    if (t.k === 'str') {
      for (const expr of t.f) {
        const inner = pyTokens(expr);
        if (!inner || inner.some((u) => u.k === 'name' && PY_DENY.has(u.v))) return false;
        if (!pyCheck(inner, locals)) return false;
      }
      continue;
    }
    if (t.v === 'import') {
      if (!atStart) return false;
      let j = i + 1;
      let expectName = true;
      for (; j < toks.length; j++) {
        const u = toks[j]!;
        if (u.k === 'op' && u.v === ';') break;
        if (expectName && u.k === 'name' && PY_MODULES.has(u.v)) expectName = false;
        else if (!expectName && u.k === 'op' && u.v === ',') expectName = true;
        else return false;
      }
      if (expectName) return false;
      i = j - 1;
      continue;
    }
    if (prev?.k === 'op' && prev.v === '.') {
      if (!PY_ATTRS.has(t.v)) return false;
      continue;
    }
    const next = toks[i + 1];
    // A keyword argument's name (`print(x, end='')`) is not a lookup.
    if (
      depth > 0 &&
      next?.k === 'op' &&
      next.v === '=' &&
      prev?.k === 'op' &&
      '(,'.includes(prev.v)
    )
      continue;
    if (!PY_ALLOWED.has(t.v) && !locals.has(t.v)) return false;
  }
  return depth === 0;
}

// -------------------------------------------------------- node inline allowlist

/** Identifiers a data-reading `node -e` program may use (besides its own variables). */
const JS_ALLOWED = new Set([
  'JSON',
  'require',
  'process',
  'console',
  'Object',
  'Array',
  'String',
  'Number',
  'Boolean',
  'Math',
  'parseInt',
  'parseFloat',
  'const',
  'let',
  'var',
  'for',
  'of',
  'in',
  'if',
  'else',
  'return',
  'typeof',
  'true',
  'false',
  'null',
  'undefined',
]);
/** Attribute and string-key names it may use, on anything. Data field names are not here. */
const JS_ATTRS = new Set([
  'parse',
  'stringify',
  'stdin',
  'stdout',
  'readFileSync',
  'on',
  'once',
  'log',
  'error',
  'warn',
  'info',
  'length',
  'keys',
  'values',
  'entries',
  'map',
  'filter',
  'forEach',
  'reduce',
  'join',
  'slice',
  'includes',
  'indexOf',
  'sort',
  'trim',
  'split',
  'toString',
  'toFixed',
  'push',
  'read',
  'setEncoding',
  'pipe',
  'write',
  'end',
]);
/** Identifiers that mean code, refused wherever they appear. */
const JS_DENY = new Set([
  'eval',
  'Function',
  'globalThis',
  'global',
  'import',
  'arguments',
  'Reflect',
  'Proxy',
  'module',
  'exports',
  'Buffer',
  'setTimeout',
  'setInterval',
  'setImmediate',
  'queueMicrotask',
  'WebAssembly',
  'constructor',
  'new',
]);
const JS_OPS = [
  '===',
  '!==',
  '=>',
  '==',
  '!=',
  '<=',
  '>=',
  '&&',
  '||',
  '??',
  '?.',
  '+=',
  '(',
  ')',
  '[',
  ']',
  '{',
  '}',
  ',',
  ';',
  ':',
  '.',
  '=',
  '<',
  '>',
  '+',
  '-',
  '*',
  '/',
  '%',
  '!',
  '?',
];

type JsTok =
  { k: 'name'; v: string } | { k: 'num' } | { k: 'str'; v: string } | { k: 'op'; v: string };

function jsTokens(code: string): JsTok[] | undefined {
  const out: JsTok[] = [];
  let i = 0;
  while (i < code.length) {
    const c = code[i]!;
    if (/\s/.test(c)) {
      i++;
      continue;
    }
    if (c === '/' && (code[i + 1] === '/' || code[i + 1] === '*')) return undefined;
    if (c === "'" || c === '"' || c === '`') {
      let j = i + 1;
      let v = '';
      for (;;) {
        if (j >= code.length) return undefined;
        const d = code[j]!;
        if (d === c) break;
        if (d === '\\') return undefined; // an escape could spell anything
        if (c === '`' && d === '$' && code[j + 1] === '{') return undefined;
        v += d;
        j++;
      }
      out.push({ k: 'str', v });
      i = j + 1;
      continue;
    }
    const name = /^[A-Za-z_$][A-Za-z0-9_$]*/.exec(code.slice(i, i + 256));
    if (name) {
      out.push({ k: 'name', v: name[0] });
      i += name[0].length;
      continue;
    }
    const num = /^[0-9][0-9.xXeEoObB]*/.exec(code.slice(i, i + 64));
    if (num) {
      out.push({ k: 'num' });
      i += num[0].length;
      continue;
    }
    const op = JS_OPS.find((o) => code.startsWith(o, i));
    if (!op) return undefined;
    out.push({ k: 'op', v: op });
    i += op.length;
  }
  return out;
}

/**
 * True when a `node -e` program only reads its input as data: JSON.parse,
 * require('fs').readFileSync(0 | '/dev/stdin'), process.stdin, console, and a
 * small set of array and string methods. Every identifier must be allowed or a
 * declared local (never a JS_DENY name, even if declared), every attribute and
 * string key must be on the allowlist (so data is reached by subscript, not by
 * dotting through objects), and `$` as an identifier character blocks `$`
 * globals. `__`, escapes, comments and template expressions are refused.
 */
export function nodeReadsOnly(code: string): boolean {
  if (code.length > MAX_CODE || code.includes('__')) return false;
  const toks = jsTokens(code);
  if (!toks) return false;
  if (toks.some((t) => t.k === 'name' && (JS_DENY.has(t.v) || t.v.includes('$')))) return false;
  const locals = collectJsLocals(toks);
  for (let i = 0; i < toks.length; i++) {
    const t = toks[i]!;
    const prev = toks[i - 1];
    const next = toks[i + 1];
    if (t.k === 'op' && t.v === '[') {
      // A computed key must be a literal; a string key must be on the allowlist,
      // which blocks reaching a method or module through brackets.
      const key = next;
      if (!key || (key.k !== 'str' && key.k !== 'num')) return false;
      if (key.k === 'str' && !JS_ATTRS.has(key.v)) return false;
      continue;
    }
    if (t.k !== 'name') continue;
    if (prev?.k === 'op' && (prev.v === '.' || prev.v === '?.')) {
      if (!JS_ATTRS.has(t.v)) return false;
      continue;
    }
    if (t.v === 'require') {
      const arg = toks[i + 2];
      const close = toks[i + 3];
      if (
        next?.k !== 'op' ||
        next.v !== '(' ||
        arg?.k !== 'str' ||
        !['fs', 'node:fs'].includes(arg.v) ||
        close?.k !== 'op' ||
        close.v !== ')'
      )
        return false;
      continue;
    }
    if (!JS_ALLOWED.has(t.v) && !locals.has(t.v)) return false;
  }
  // readFileSync's first argument must be the standard input.
  for (let i = 0; i < toks.length; i++) {
    const t = toks[i]!;
    if (t.k === 'name' && t.v === 'readFileSync') {
      const open = toks[i + 1];
      const arg = toks[i + 2];
      if (open?.k !== 'op' || open.v !== '(') return false;
      const ok =
        arg?.k === 'num' ||
        (arg?.k === 'str' && /^(\/dev\/stdin|\/proc\/self\/fd\/0)$/.test(arg.v));
      if (!ok) return false;
    }
  }
  return true;
}

/** Plain names a node program declares (its own variables), as const/let/var or arrow parameters. */
function collectJsLocals(toks: JsTok[]): Set<string> {
  const locals = new Set<string>();
  for (let i = 0; i < toks.length; i++) {
    const t = toks[i]!;
    const next = toks[i + 1];
    if (t.k === 'name' && (t.v === 'const' || t.v === 'let' || t.v === 'var') && next?.k === 'name')
      locals.add(next.v);
    if (t.k === 'name' && next?.k === 'op' && next.v === '=>') locals.add(t.v);
    if (t.k === 'op' && t.v === ')' && next?.k === 'op' && next.v === '=>')
      for (let j = i - 1; j >= 0; j--) {
        const u = toks[j]!;
        if (u.k === 'op' && u.v === '(') break;
        if (u.k === 'name') locals.add(u.v);
      }
  }
  return locals;
}
