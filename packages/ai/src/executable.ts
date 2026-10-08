import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { access, constants, readFile, realpath, stat } from 'node:fs/promises';
import { homedir } from 'node:os';
import { delimiter, isAbsolute, join } from 'node:path';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);

/**
 * Where vendor CLIs are usually installed on a Mac. A menu-bar app launched
 * from Finder gets a minimal PATH, so these are checked too.
 */
export function defaultSearchDirs(home: string = homedir()): string[] {
  return [
    join(home, '.local', 'bin'),
    join(home, '.claude', 'local'),
    '/opt/homebrew/bin',
    '/usr/local/bin',
  ];
}

export interface ResolvedExecutable {
  /** The path Vigil will launch. Always absolute, symlinks followed. */
  readonly realPath: string;
  readonly sha256: string;
  /** Apple Developer Team ID when the binary is code-signed (macOS only). */
  readonly teamId?: string;
}

async function isExecutable(path: string): Promise<boolean> {
  try {
    await access(path, constants.X_OK);
    return true;
  } catch {
    return false;
  }
}

export async function findExecutable(
  name: string,
  options: { explicitPath?: string; pathEnv?: string; extraDirs?: readonly string[] } = {},
): Promise<string | undefined> {
  if (options.explicitPath) {
    if (!isAbsolute(options.explicitPath)) return undefined;
    return (await isExecutable(options.explicitPath)) ? options.explicitPath : undefined;
  }
  const dirs = [
    ...(options.pathEnv ?? process.env.PATH ?? '').split(delimiter).filter(isAbsolute),
    ...(options.extraDirs ?? defaultSearchDirs()),
  ];
  for (const dir of dirs) {
    const candidate = join(dir, name);
    if (await isExecutable(candidate)) return candidate;
  }
  return undefined;
}

/** codesign can stall (e.g. on a network volume); a run's deadline shouldn't wait on it. */
const CODESIGN_TIMEOUT_MS = 20_000;

async function readTeamId(path: string): Promise<string | undefined> {
  if (process.platform !== 'darwin') return undefined;
  const opts = { timeout: CODESIGN_TIMEOUT_MS };
  try {
    await execFileAsync('/usr/bin/codesign', ['--verify', '--strict', path], opts);
    const { stderr } = await execFileAsync('/usr/bin/codesign', ['-dv', '--verbose=2', path], opts);
    const match = /^TeamIdentifier=(\S+)$/m.exec(stderr);
    return match && match[1] !== 'not' ? match[1] : undefined;
  } catch (err) {
    // Timed out: say so rather than cache "no team" for this binary.
    if ((err as { killed?: boolean }).killed)
      throw new Error(`codesign timed out on ${path}`, { cause: err });
    return undefined;
  }
}

/** Hashing a large CLI on every run is slow, so reuse the result until the file changes. */
const resolvedCache = new Map<string, { stamp: string; resolved: ResolvedExecutable }>();

export async function resolveExecutable(path: string): Promise<ResolvedExecutable> {
  const realPath = await realpath(path);
  const info = await stat(realPath);
  const stamp = `${info.size}:${info.mtimeMs}:${info.ino}`;
  const cached = resolvedCache.get(realPath);
  if (cached?.stamp === stamp) return cached.resolved;
  const sha256 = createHash('sha256')
    .update(await readFile(realPath))
    .digest('hex');
  const teamId = await readTeamId(realPath);
  const resolved = teamId ? { realPath, sha256, teamId } : { realPath, sha256 };
  resolvedCache.set(realPath, { stamp, resolved });
  return resolved;
}

/** What Vigil recorded for a provider binary the first time the user set it up. */
export interface ExecutablePin {
  readonly realPath: string;
  readonly sha256: string;
  readonly teamId?: string;
}

/**
 * A signed binary may update itself (new hash) as long as the signer stays the
 * same. An unsigned one must match its recorded hash exactly.
 */
export function checkPin(
  current: ResolvedExecutable,
  pin: ExecutablePin | undefined,
): 'ok' | 'new' | 'changed' {
  if (!pin) return 'new';
  if (pin.teamId) return current.teamId === pin.teamId ? 'ok' : 'changed';
  return current.sha256 === pin.sha256 ? 'ok' : 'changed';
}

export interface PinStore {
  get(provider: string): Promise<ExecutablePin | undefined>;
  set(provider: string, pin: ExecutablePin): Promise<void>;
}

export function memoryPinStore(): PinStore {
  const pins = new Map<string, ExecutablePin>();
  return {
    get: async (provider) => pins.get(provider),
    set: async (provider, pin) => void pins.set(provider, pin),
  };
}
