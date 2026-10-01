#!/usr/bin/env node
// vigil-hook preflight --socket <path> [--on-unavailable ask|defer]
//     Claude Code's PreToolUse hook: prints a deny or ask answer, or nothing.
// vigil-hook hello --socket <path>
//     Claude Code's SessionStart hook: tells Vigil the hook is set up. Prints nothing.
//
// The app ships this bundled as Resources/helper/vigil-hook.mjs, next to its
// signed node, and shows the user the snippet that runs it. It always exits
// 0. If anything goes wrong, preflight asks (or, with --on-unavailable defer,
// leaves the step to Claude Code's own permissions).

import { connect, type Socket } from 'node:net';
import { LIMITS, parseArgs, render, runHello, runPreflight, type HookIO } from './hook.js';

const USAGE =
  'usage: vigil-hook preflight --socket <path> [--on-unavailable ask|defer]\n' +
  '       vigil-hook hello --socket <path>\n';

const args = parseArgs(process.argv.slice(2));
const out: string[] = [];
let finished = false;

/** Print what the hook decided, then exit 0 once stdout has taken it. */
function finish(): void {
  if (finished) return;
  finished = true;
  const text = out.join('');
  if (text) process.stdout.write(text, () => process.exit(0));
  else process.exit(0);
}

/** Anything unexpected: answer as if Vigil were unavailable. */
function bail(): void {
  if (finished) return;
  out.length = 0;
  if (args.command === 'preflight') out.push(render('unavailable', args.onUnavailable));
  finish();
}

process.on('uncaughtException', bail);
process.on('unhandledRejection', bail);
process.stdout.on('error', () => process.exit(0));
// The last resort if something still waits past the hook's own deadline.
setTimeout(bail, LIMITS.totalMs + 500);

const io: HookIO = {
  stdin: process.stdin,
  write: (s) => out.push(s),
  connect: (path) =>
    new Promise<Socket>((resolve, reject) => {
      const sock = connect(path);
      sock.once('connect', () => resolve(sock));
      sock.once('error', reject);
    }),
};

async function main(): Promise<void> {
  switch (args.command) {
    case 'preflight':
      await runPreflight(io, {
        socket: args.socket,
        onUnavailable: args.onUnavailable,
        ppid: process.ppid,
      });
      return;
    case 'hello':
      await runHello(io, { socket: args.socket });
      return;
    case 'usage':
      process.stderr.write(USAGE);
      return;
  }
}

main().then(finish, bail);
