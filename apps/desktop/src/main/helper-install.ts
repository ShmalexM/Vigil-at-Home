import { execFile } from 'node:child_process';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import type { HelperInstallResult } from '../shared/ipc.js';

const hasHelper = (dir: string) =>
  existsSync(join(dir, 'install.sh')) && existsSync(join(dir, 'node'));

/**
 * The helper files shipped in the app (Contents/Resources/helper). A
 * development build doesn't carry them, so it uses `devDir` instead, which
 * `pnpm build:helper` fills (`pnpm dev` runs it first). Null when neither has them.
 */
export function helperBundleDir(
  resourcesPath: string | undefined = process.resourcesPath,
  devDir?: string,
): string | null {
  if (resourcesPath && hasHelper(join(resourcesPath, 'helper')))
    return join(resourcesPath, 'helper');
  return devDir && hasHelper(devDir) ? devDir : null;
}

/** Shell-quote one argument for a command the user pastes into Terminal. */
export function shellQuote(s: string): string {
  return `'${s.replace(/'/g, `'\\''`)}'`;
}

/** The Terminal command that installs the helper, for the setup wizard. */
export function helperInstallCommand(dir = helperBundleDir()): string | undefined {
  return dir ? `sudo ${shellQuote(join(dir, 'install.sh'))}` : undefined;
}

const PROMPTS = {
  install:
    'Vigil at Home wants to install its helper, which blocks and quarantines threats on this Mac.',
  uninstall: 'Vigil at Home wants to remove its helper.',
} as const;

/**
 * The osascript arguments that run one of the bundled scripts as root. macOS
 * shows its own password dialog. The script path goes in as an argument and
 * through AppleScript's `quoted form of`, so no path can break out of it.
 */
export function adminScriptArgs(script: string, kind: keyof typeof PROMPTS): string[] {
  return [
    '-e',
    'on run argv',
    '-e',
    `do shell script (quoted form of item 1 of argv) with prompt ${JSON.stringify(PROMPTS[kind])} with administrator privileges`,
    '-e',
    'end run',
    script,
  ];
}

export type RunFile = (
  file: string,
  args: string[],
) => Promise<{ code: number; stdout: string; stderr: string }>;

const runFile: RunFile = (file, args) =>
  new Promise((resolve) =>
    execFile(file, args, { timeout: 3 * 60_000 }, (err, stdout, stderr) =>
      resolve({
        code: err ? (typeof err.code === 'number' ? err.code : 1) : 0,
        stdout: String(stdout),
        stderr: String(stderr),
      }),
    ),
  );

/** Install or remove the helper through the macOS admin password dialog. */
export async function runHelperScript(
  kind: 'install' | 'uninstall',
  dir = helperBundleDir(),
  run: RunFile = runFile,
): Promise<HelperInstallResult> {
  if (process.platform !== 'darwin' && run === runFile) {
    return { ok: false, error: 'The helper only runs on macOS' };
  }
  if (!dir) return { ok: false, error: 'This build of Vigil does not include the helper' };
  const out = await run('/usr/bin/osascript', adminScriptArgs(join(dir, `${kind}.sh`), kind));
  if (out.code === 0) return { ok: true };
  // osascript reports a closed password dialog as error -128.
  if (/-128/.test(out.stderr)) return { ok: false, error: 'cancelled' };
  const msg = out.stderr
    .replace(/^\d+:\d+: execution error: /, '')
    .replace(/ \(-?\d+\)\s*$/, '')
    .trim();
  return { ok: false, error: msg || `The ${kind} script failed` };
}
