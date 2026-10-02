import type { ProcessRef, SensorEvent } from '@vigil/core';

/** Same id as VIGIL_SELF in @vigil/detection, restated so this file stays import-light. */
const VIGIL_SELF = 'vigil-self';

/**
 * Which events no rule matched are worth the labeller's look, and what makes
 * two of them the same. Kept free of Electron so the benchmarks can import it.
 *
 * Apple's own programs are mostly skipped: they're the bulk of what a Mac
 * runs. The exception is the handful attackers borrow (shells, osascript,
 * curl, security and the like) and any Apple program started from a temp,
 * shared or hidden folder. Those are keyed by their command line, so a new
 * command is a new thing to look at, and capped per hour by the caller.
 */

/** Apple tools attackers run instead of shipping their own. Matched on the file name. */
const BORROWED_TOOLS = new Set([
  'sh',
  'bash',
  'zsh',
  'dash',
  'ksh',
  'tcsh',
  'csh',
  'osascript',
  'python',
  'python3',
  'perl',
  'ruby',
  'php',
  'swift',
  'tclsh',
  'jsc',
  'curl',
  'nc',
  'security',
  'sqlite3',
  'dscl',
  'xattr',
  'spctl',
  'tccutil',
  'launchctl',
  'base64',
  'openssl',
  'screencapture',
  'pbpaste',
  'hdiutil',
]);

/** Tools that only matter when they touch something sensitive (a watched file), not when they start. */
const COPY_TOOLS = new Set(['cp', 'ditto', 'cat', 'zip', 'tar', 'rsync']);

/** Folders programs rarely start from legitimately. */
const ODD_FOLDER = /^(\/private)?\/tmp\/|^\/Users\/Shared\/|^\/Volumes\/|\/\.[^/]+\//;

function toolName(p: ProcessRef | undefined): string | undefined {
  const name = p?.path.slice(p.path.lastIndexOf('/') + 1);
  // python3.12, perl5.34 and the like.
  return name?.replace(/^(python|perl|ruby|php)[\d.]+$/, (_, n: string) =>
    n === 'python' ? 'python3' : n,
  );
}

/** An Apple program Vigil still wants labelled. */
function borrowedTool(p: ProcessRef | undefined, touchesFiles: boolean): boolean {
  const name = toolName(p);
  if (!name) return false;
  return BORROWED_TOOLS.has(name) || (touchesFiles && COPY_TOOLS.has(name));
}

function startedOddly(p: ProcessRef | undefined): boolean {
  return !!p?.parentPath && ODD_FOLDER.test(p.parentPath);
}

/** Skipped: Apple programs, unless borrowed or started from an odd folder. */
function skipApple(p: ProcessRef | undefined, touchesFiles = false): boolean {
  return p?.signing === 'apple' && !borrowedTool(p, touchesFiles) && !startedOddly(p);
}

/** Numbers and long hex runs vary between otherwise identical commands; cut them out. */
function shape(args: string[] | undefined): string {
  return (args ?? [])
    .join(' ')
    .replace(/\b[0-9a-f]{12,}\b/gi, 'h')
    .replace(/\d+/g, '#')
    .slice(0, 200);
}

/** A browser or app reading its own files isn't news: Google Chrome.app in …/Google/Chrome/…. */
function ownFiles(p: ProcessRef | undefined, path: string): boolean {
  const app = /\/([^/]+)\.app\//.exec(p?.path ?? '')?.[1];
  const word = app?.split(/\s+/)[0];
  return !!word && word.length > 2 && path.toLowerCase().includes(`/${word.toLowerCase()}`);
}

function folder(path: string): string {
  return path.slice(0, path.lastIndexOf('/'));
}

/**
 * The dedupe key for an event worth labelling, or undefined when it isn't:
 * exits, removals, Apple's own programs doing ordinary things, and apps
 * reading their own files. `tool` is true when only the borrowed-tool
 * exception let it through, so the caller can cap those separately.
 */
export function labelKey(e: SensorEvent): { key: string; tool: boolean } | undefined {
  // A watched agent's activity is reviewed per session, not event by event: an
  // agent runs hundreds of commands an hour, which would swamp the labeller's
  // CPU budget. Vigil's own helpers (vigil-self) are still labelled.
  const agent = 'process' in e ? e.process?.agent : undefined;
  if (agent && agent.id !== VIGIL_SELF) return undefined;
  const apple = 'process' in e && e.process?.signing === 'apple';
  const k = (key: string) => ({ key, tool: apple });
  switch (e.kind) {
    case 'process.exec':
      if (skipApple(e.process)) return undefined;
      return k(
        apple ? `exec:${e.process.path}:${shape(e.process.args)}` : `exec:${e.process.path}`,
      );
    case 'network.connection':
      if (skipApple(e.process)) return undefined;
      return k(
        `net:${e.process?.path ?? '?'}>${e.remoteHost ?? e.remoteAddress}:${e.remotePort ?? ''}`,
      );
    case 'network.listen':
      if (skipApple(e.process)) return undefined;
      return k(`listen:${e.process?.path ?? '?'}:${e.localPort}`);
    case 'file':
      // Only watched files are reported, so a read here is already sensitive.
      if (e.op === 'delete' || skipApple(e.process, true) || ownFiles(e.process, e.path))
        return undefined;
      return k(`file:${e.process?.path ?? '?'}:${folder(e.path)}`);
    case 'santa.decision':
      // Blocks already raise an alert; audited or allowed reads of a protected file may not.
      if (e.target !== 'file_access' || e.decision === 'block' || !e.path) return undefined;
      if (skipApple(e.process, true) || ownFiles(e.process, e.path)) return undefined;
      return k(`file:${e.process.path}:${folder(e.path)}`);
    case 'persistence':
      return e.change === 'removed' ? undefined : { key: `persist:${e.path}`, tool: false };
    case 'browser.extension':
      return e.change === 'removed' ? undefined : { key: `ext:${e.extensionId}`, tool: false };
    case 'system.alert':
      return { key: `sys:${e.subtype}:${e.path ?? e.details['service'] ?? ''}`, tool: false };
    default:
      return undefined;
  }
}
