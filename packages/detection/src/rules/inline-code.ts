// Does a shell command pipe a download (curl, wget) into a script interpreter
// that runs it? Used by the `process.pipesDownloadIntoCode` field (fields.ts).
//
// Piping a download into python3, perl, ruby or node runs it, with one
// exception seen in Claude Code's own steps on a real Mac (2026-10-08): an
// inline program that only reads the download as data (`curl … | python3 -c
// "import json,sys; print(json.load(sys.stdin)['x'])"`). That exception is an
// allowlist, checked token by token: python3 -c or node -e whose program uses
// only a few data-reading names (see PY_* and JS_*). Anything else, perl and
// ruby always, counts as running the download.
//
// The command is read with a small shell lexer (quotes, escapes, `$( )`,
// backticks, `<( )`, `eval '…'` and `sh -c '…'` read again), never run. When
// the lexer cannot account for every download piped into an interpreter that a
// plain regex sees, the answer is "runs".

import * as fs from 'node:fs';

/** curl or wget piped into an interpreter, as plain text. Every such pair must be explained. */
const PAIR_RE =
  /(curl|wget)\s[^|]*\|\s*(\S+=\S*\s+){0,4}((sudo|env|command|exec|nice|nohup|time)\s+(-\S+\s+){0,4})?(\S*\/)?(python[0-9.]*|perl|ruby|node)(?![\w.-])/g;
/** Programs that run the program named after them. */
const WRAPPERS = new Set(['sudo', 'env', 'command', 'exec', 'nice', 'nohup', 'time']);
const INTERPRETER_RE = /^(python[0-9.]*|perl|ruby|node)$/;
const SHELL_RE = /^(sh|bash|zsh|dash|ksh)$/;
const SHELL_C_RE = /^-[A-Za-z]*c[A-Za-z]*$/;
/** Longest command read; a longer one counts as running. */
const MAX_COMMAND = 64 * 1024;
const MAX_DEPTH = 6;

function basename(p: string): string {
  const i = p.lastIndexOf('/');
  return i === -1 ? p : p.slice(i + 1);
}

// ------------------------------------------------------------------ shell lexer

type Tok = { w: string } | { op: string };

interface Lexed {
  toks: Tok[];
  /** The text of every `$( )`, backtick and `<( )` substitution, read again on its own. */
  subs: string[];
}

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

/** Words and operators of a shell command, or undefined when it cannot be read (an open quote). */
function lex(s: string): Lexed | undefined {
  const toks: Tok[] = [];
  const subs: string[] = [];
  let word: string | undefined;
  const end = () => {
    if (word !== undefined) toks.push({ w: word });
    word = undefined;
  };
  let i = 0;
  while (i < s.length) {
    const c = s[i]!;
    if (c === ' ' || c === '\t') {
      end();
      i++;
    } else if (c === '#' && word === undefined) {
      while (i < s.length && s[i] !== '\n') i++;
    } else if (c === '\n' || c === ';' || c === '&' || c === '|' || c === '(' || c === ')') {
      end();
      const two = s.slice(i, i + 2);
      const op = ['&&', '||', ';;', '|&'].includes(two) ? two : c === '\n' ? ';' : c;
      toks.push({ op });
      i += op.length === 2 ? 2 : 1;
    } else if (c === '<' && s[i + 1] === '(') {
      const close = closeParen(s, i + 2);
      if (close === undefined) return undefined;
      subs.push(s.slice(i + 2, close - 1));
      word = (word ?? '') + s.slice(i, close);
      i = close;
    } else if (c === '<' || c === '>') {
      end();
      let j = i + 1;
      while (j < s.length && '<>|&'.includes(s[j]!)) j++;
      toks.push({ op: 'redir' });
      i = j;
    } else if (c === "'") {
      const close = s.indexOf("'", i + 1);
      if (close === -1) return undefined;
      word = (word ?? '') + s.slice(i + 1, close);
      i = close + 1;
    } else if (c === '"') {
      let v = '';
      i++;
      for (;;) {
        if (i >= s.length) return undefined;
        const d = s[i]!;
        if (d === '"') break;
        if (d === '\\' && i + 1 < s.length && '$`"\\\n'.includes(s[i + 1]!)) {
          v += s[i + 1];
          i += 2;
        } else if (d === '$' && s[i + 1] === '(') {
          const close = closeParen(s, i + 2);
          if (close === undefined) return undefined;
          subs.push(s.slice(i + 2, close - 1));
          v += s.slice(i, close);
          i = close;
        } else if (d === '`') {
          const close = s.indexOf('`', i + 1);
          if (close === -1) return undefined;
          subs.push(s.slice(i + 1, close));
          v += s.slice(i, close + 1);
          i = close + 1;
        } else {
          v += d;
          i++;
        }
      }
      word = (word ?? '') + v;
      i++;
    } else if (c === '\\') {
      word = (word ?? '') + (s[i + 1] ?? '');
      i += 2;
    } else if (c === '$' && s[i + 1] === '(') {
      const close = closeParen(s, i + 2);
      if (close === undefined) return undefined;
      subs.push(s.slice(i + 2, close - 1));
      word = (word ?? '') + s.slice(i, close);
      i = close;
    } else if (c === '$' && s[i + 1] === "'") {
      // ANSI-C quoting: escapes this reader does not decode. Kept raw, so an
      // inline program written this way never passes the allowlist.
      const close = s.indexOf("'", i + 2);
      if (close === -1) return undefined;
      word = (word ?? '') + s.slice(i, close + 1);
      i = close + 1;
    } else if (c === '`') {
      const close = s.indexOf('`', i + 1);
      if (close === -1) return undefined;
      subs.push(s.slice(i + 1, close));
      word = (word ?? '') + s.slice(i, close + 1);
      i = close + 1;
    } else {
      word = (word ?? '') + c;
      i++;
    }
  }
  end();
  return { toks, subs };
}

// --------------------------------------------------------------- the pipeline

interface Found {
  runs: boolean;
  /** Download → interpreter pairs found and judged. */
  pairs: number;
}

const ASSIGNMENT_RE = /^[A-Za-z_][A-Za-z0-9_]*=/;

/** Does an interpreter command, given what a download wrote to its input, run it? */
function interpreterRuns(words: string[]): boolean {
  // An environment assignment (PYTHONPATH, NODE_OPTIONS) or sudo changes what runs.
  if (!words.length || ASSIGNMENT_RE.test(words[0]!)) return true;
  const prog = basename(words[0]!);
  const args = words.slice(1);
  if (/^python[0-9.]*$/.test(prog)) {
    let i = 0;
    while (i < args.length && /^-[uIESBsqO]+$/.test(args[i]!)) i++;
    // python3 -m json.tool, the pretty-printer, with its formatting options only.
    if (args[i] === '-m' && args[i + 1] === 'json.tool')
      return !args
        .slice(i + 2)
        .every((a) =>
          /^(--(sort-keys|compact|no-ensure-ascii|json-lines|tab|no-indent)|--indent|\d{1,2})$/.test(
            a,
          ),
        );
    if (args[i] !== '-c' || args[i + 1] === undefined) return true;
    return !pythonReadsOnly(args[i + 1]!);
  }
  if (prog === 'node') {
    if (!['-e', '--eval', '-p', '--print'].includes(args[0] ?? '') || args[1] === undefined)
      return true;
    return !nodeReadsOnly(args[1]);
  }
  return true; // perl, ruby
}

/** Read one command (and what it substitutes, evals or hands to `sh -c`). */
function scan(src: string, depth: number, out: Found): void {
  if (out.runs) return;
  if (depth > MAX_DEPTH) {
    out.runs = true;
    return;
  }
  const lexed = lex(src);
  if (!lexed) {
    // Unreadable: only a problem if it holds a pair (the caller's count decides).
    return;
  }
  for (const sub of lexed.subs) scan(sub, depth + 1, out);
  // Commands, each with the operator that ends it.
  const cmds: { words: string[]; next?: string }[] = [{ words: [] }];
  let skipNext = false;
  for (const t of lexed.toks) {
    const cur = cmds[cmds.length - 1]!;
    if ('w' in t) {
      if (skipNext) skipNext = false;
      else cur.words.push(t.w);
    } else if (t.op === 'redir') {
      skipNext = true;
    } else {
      cur.next = t.op;
      cmds.push({ words: [] });
    }
  }
  for (let i = 0; i < cmds.length; i++) {
    const { words, next } = cmds[i]!;
    // What it hands to another shell reading: eval's words, sh -c's command.
    let k = 0;
    while (k < words.length && ASSIGNMENT_RE.test(words[k]!)) k++;
    const prog = words[k] === undefined ? '' : basename(words[k]!);
    if (prog === 'eval') scan(words.slice(k + 1).join(' '), depth + 1, out);
    else if (SHELL_RE.test(prog) && words[k + 1] && SHELL_C_RE.test(words[k + 1]!)) {
      const cmd = words[k + 2];
      if (cmd !== undefined) scan(cmd, depth + 1, out);
    }
    if (next !== '|' && next !== '|&') continue;
    if (!words.some((w) => /^(curl|wget)$/.test(basename(w)))) continue;
    const to = cmds[i + 1]?.words ?? [];
    let j = 0;
    while (j < to.length && ASSIGNMENT_RE.test(to[j]!)) j++;
    const p = to[j] === undefined ? '' : basename(to[j]!);
    if (WRAPPERS.has(p)) {
      out.pairs++;
      out.runs ||= to.slice(j + 1).some((w) => INTERPRETER_RE.test(basename(w)));
      continue;
    }
    if (!INTERPRETER_RE.test(p)) continue;
    out.pairs++;
    if (interpreterRuns(to)) out.runs = true;
  }
}

/**
 * True when `command` pipes curl or wget output into python, perl, ruby or
 * node and that interpreter runs it: anything but an inline program on the
 * allowlist (see pythonReadsOnly and nodeReadsOnly).
 */
export function pipesDownloadIntoCode(command: string): boolean {
  const seen = command.match(PAIR_RE)?.length ?? 0;
  if (seen === 0) return false;
  if (command.length > MAX_COMMAND) return true;
  const out: Found = { runs: false, pairs: 0 };
  scan(command, 0, out);
  // Every pair the plain text shows must have been found and judged.
  return out.runs || out.pairs < seen;
}

// ------------------------------------------------------------ python allowlist

/** Names a data-reading python3 -c program may use, besides its own variables. */
const PY_NAMES = new Set([
  'json',
  'sys',
  'print',
  'len',
  'str',
  'int',
  'float',
  'round',
  'sorted',
  'list',
  'dict',
  'min',
  'max',
  'sum',
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
/** Attributes it may use, on anything. */
const PY_ATTRS = new Set([
  'load',
  'loads',
  'dumps',
  'stdin',
  'read',
  'get',
  'items',
  'keys',
  'values',
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
  | { k: 'name'; v: string }
  | { k: 'num' }
  | { k: 'str'; f: string[] }
  | { k: 'op'; v: string }
  | { k: 'nl' };

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
      out.push({ k: 'nl' });
      i++;
      continue;
    }
    if (c === '#') {
      while (i < code.length && code[i] !== '\n') i++;
      continue;
    }
    const str = /^([rRuUfF]{0,2})('''|"""|'|")/.exec(code.slice(i, i + 5));
    if (str) {
      const prefix = str[1]!.toLowerCase();
      const q = str[2]!;
      if (/[b]/.test(prefix)) return undefined;
      let j = i + str[0].length;
      let body = '';
      for (;;) {
        if (j >= code.length) return undefined;
        if (code.startsWith(q, j)) break;
        if (code[j] === '\\' && !prefix.includes('r')) {
          body += code.slice(j, j + 2);
          j += 2;
        } else {
          if (q.length === 1 && code[j] === '\n') return undefined;
          body += code[j];
          j++;
        }
      }
      const f: string[] = [];
      if (prefix.includes('f')) {
        // The expressions in an f-string are code too.
        for (let a = 0; a < body.length; a++) {
          if (body[a] === '{' && body[a + 1] === '{') a++;
          else if (body[a] === '{') {
            const close = body.indexOf('}', a);
            if (close === -1) return undefined;
            f.push(body.slice(a + 1, close).replace(/![rsa]$|:[^\]})]*$/, ''));
            a = close;
          }
        }
      }
      out.push({ k: 'str', f });
      i = j + q.length;
      continue;
    }
    const name = /^[A-Za-z_][A-Za-z0-9_]*/.exec(code.slice(i, i + 256));
    if (name) {
      out.push({ k: 'name', v: name[0] });
      i += name[0].length;
      continue;
    }
    const num = /^[0-9][0-9_.eE]*/.exec(code.slice(i, i + 64));
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
 * True when a python3 -c program only reads its input as data: json and sys,
 * json.load(sys.stdin), sys.stdin.read(), print, a few built-ins, .get,
 * .items, .keys, .values, subscripts, for and comprehensions, if/else,
 * literals (f-string expressions checked the same way) and plain-name
 * assignments. No dunder, no other import, no from, no other name or
 * attribute.
 */
export function pythonReadsOnly(code: string): boolean {
  if (code.includes('__') || code.length > 4096) return false;
  const toks = pyTokens(code);
  if (!toks) return false;
  // Its own variables: plain names assigned at the top level, and loop targets.
  const locals = new Set<string>();
  let depth = 0;
  for (let i = 0; i < toks.length; i++) {
    const t = toks[i]!;
    if (t.k === 'op' && '([{'.includes(t.v)) depth++;
    else if (t.k === 'op' && ')]}'.includes(t.v)) depth--;
    const next = toks[i + 1];
    if (t.k === 'name' && depth === 0 && next?.k === 'op' && /^[-+]?=$/.test(next.v)) {
      const prev = toks[i - 1];
      if (!prev || prev.k === 'nl' || (prev.k === 'op' && (prev.v === ';' || prev.v === ':')))
        locals.add(t.v);
    }
    if (t.k === 'name' && t.v === 'for') {
      for (let j = i + 1; j < toks.length; j++) {
        const u = toks[j]!;
        if (u.k === 'name' && u.v === 'in') break;
        if (u.k === 'name') locals.add(u.v);
        else if (!(u.k === 'op' && '(),'.includes(u.v))) return false;
      }
    }
  }
  return pyCheck(toks, locals, true);
}

function pyCheck(toks: PyTok[], locals: Set<string>, statements: boolean): boolean {
  let depth = 0;
  let stmtStart = true;
  for (let i = 0; i < toks.length; i++) {
    const t = toks[i]!;
    const prev = toks[i - 1];
    if (t.k === 'nl' || (t.k === 'op' && t.v === ';')) {
      if (!statements) return false;
      stmtStart = true;
      continue;
    }
    const atStart = stmtStart;
    stmtStart = false;
    if (t.k === 'op') {
      if ('([{'.includes(t.v)) depth++;
      else if (')]}'.includes(t.v)) depth--;
      if (t.v === ':' && depth === 0) stmtStart = true; // if x: y, for a in b: c
      if (depth < 0) return false;
      continue;
    }
    if (t.k === 'num') continue;
    if (t.k === 'str') {
      for (const expr of t.f) {
        const inner = pyTokens(expr);
        if (!inner || !pyCheck(inner, locals, false)) return false;
      }
      continue;
    }
    // A name.
    if (t.v === 'import') {
      if (!statements || !atStart) return false;
      // import json, sys: only those, up to the end of the statement.
      let j = i + 1;
      let expectName = true;
      for (; j < toks.length; j++) {
        const u = toks[j]!;
        if (u.k === 'nl' || (u.k === 'op' && u.v === ';')) break;
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
    // A keyword argument's name (print(x, end='')) is not a lookup.
    if (
      depth > 0 &&
      next?.k === 'op' &&
      next.v === '=' &&
      prev?.k === 'op' &&
      '(,'.includes(prev.v)
    )
      continue;
    if (!PY_NAMES.has(t.v) && !locals.has(t.v)) return false;
  }
  return depth === 0;
}

// -------------------------------------------------------------- node allowlist

/** Names a data-reading node -e program may use, besides its own variables. */
const JS_NAMES = new Set([
  'JSON',
  'require',
  'process',
  'console',
  'Object',
  'String',
  'Number',
  'true',
  'false',
  'null',
  'undefined',
  'const',
  'let',
  'var',
  'for',
  'of',
  'in',
  'if',
  'else',
  'typeof',
]);
/** Attributes it may use on anything, the globals above included. */
const JS_ATTRS = new Set([
  'parse',
  'stringify',
  'readFileSync',
  'stdin',
  'on',
  'log',
  'error',
  'length',
  'keys',
  'values',
  'entries',
  'map',
  'filter',
  'forEach',
  'join',
  'slice',
  'includes',
  'sort',
  'trim',
  'split',
  'toFixed',
  'toString',
  'find',
  'some',
  'every',
  'push',
  'setEncoding',
  'name',
  'stdout',
  'write',
  'pipe',
]);

/**
 * Other attribute names are data (`d.models`, `m.name`) unless something the
 * program can reach has them: fs and its promises, process, Object, Reflect,
 * functions (call, apply, bind), the global object, or a few that lead to code.
 */
const JS_DENY: ReadonlySet<string> = (() => {
  const deny = new Set([
    'constructor',
    'prototype',
    'caller',
    'callee',
    'mainModule',
    'binding',
    'require',
    'eval',
    'Function',
    'then',
  ]);
  const add = (o: object | undefined) => {
    for (let p = o; p && p !== Object.prototype; p = Object.getPrototypeOf(p) as object)
      for (const k of Object.getOwnPropertyNames(p)) deny.add(k);
  };
  for (const o of [fs, fs.promises, process, Object, Reflect, Function.prototype, globalThis])
    add(o);
  for (const k of Object.getOwnPropertyNames(Object.prototype)) deny.add(k);
  for (const k of JS_ATTRS) deny.delete(k);
  return deny;
})();
const JS_OPS = [
  '===',
  '+=',
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
        if (d === '\\') return undefined; // escapes could spell anything
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
    const num = /^[0-9][0-9.]*/.exec(code.slice(i, i + 64));
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
 * True when a node -e program only reads its input as data: JSON.parse,
 * require('fs').readFileSync(0…) or process.stdin, console.log, property
 * access to data (not to anything in JS_DENY), literals, its own
 * const/let/var and arrow-function parameters. No other require, no eval,
 * Function, new, import(), child_process or vm (no name for them is on the
 * list), no comment, escape or template expression, and computed member
 * access only by a literal.
 */
export function nodeReadsOnly(code: string): boolean {
  if (code.includes('__') || code.length > 4096) return false;
  const toks = jsTokens(code);
  if (!toks) return false;
  const locals = new Set<string>();
  for (let i = 0; i < toks.length; i++) {
    const t = toks[i]!;
    const next = toks[i + 1];
    if (t.k === 'name' && ['const', 'let', 'var'].includes(t.v) && next?.k === 'name')
      locals.add(next.v);
    if (t.k === 'name' && next?.k === 'op' && next.v === '=>') locals.add(t.v);
    if (t.k === 'op' && t.v === ')' && next?.k === 'op' && next.v === '=>') {
      // (a, b) => …
      for (let j = i - 1; j >= 0; j--) {
        const u = toks[j]!;
        if (u.k === 'op' && u.v === '(') break;
        if (u.k === 'name') locals.add(u.v);
        else if (!(u.k === 'op' && u.v === ',')) return false;
      }
    }
  }
  for (let i = 0; i < toks.length; i++) {
    const t = toks[i]!;
    const prev = toks[i - 1];
    const next = toks[i + 1];
    if (t.k === 'op' && t.v === '[') {
      // Member access by a computed key only with a literal: d['models'], a[0].
      const isMember =
        prev &&
        (prev.k === 'name' ||
          prev.k === 'str' ||
          (prev.k === 'op' && (prev.v === ')' || prev.v === ']')));
      if (isMember) {
        const key = toks[i + 1];
        if (!key || (key.k !== 'str' && key.k !== 'num')) return false;
        if (key.k === 'str' && /^(constructor|prototype|caller|callee)$/.test(key.v)) return false;
        if (toks[i + 2]?.k !== 'op' || (toks[i + 2] as { v: string }).v !== ']') return false;
      }
      continue;
    }
    if (t.k !== 'name') continue;
    if (prev?.k === 'op' && (prev.v === '.' || prev.v === '?.')) {
      if (JS_DENY.has(t.v)) return false;
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
    if (!JS_NAMES.has(t.v) && !locals.has(t.v)) return false;
  }
  return true;
}
