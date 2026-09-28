import { execFile } from 'node:child_process';
import { accessSync, constants, existsSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import type { CheckId } from '../../shared/setup.js';
import { LOCAL_MODEL, LOCAL_MODEL_SMALL } from './plan.js';

export interface CheckResult {
  ok: boolean;
  detail?: string;
}

/** Everything a check touches, so tests can fake a Mac. Read-only: nothing here installs or changes anything. */
export interface Probe {
  exists(path: string): boolean;
  executable(path: string): boolean;
  /** Run a program by absolute path with a short timeout. Never through a shell. */
  run(file: string, args: string[]): Promise<{ code: number; stdout: string }>;
  getJson(url: string): Promise<unknown>;
  home: string;
}

export const SANTA_SYNC_PORT = 47821;
export const HELPER_SOCKET = '/var/run/vigil-helper.sock';
const SANTACTL = '/usr/local/bin/santactl';
const BIN_DIRS = (home: string) => [
  '/opt/homebrew/bin',
  '/usr/local/bin',
  join(home, '.local', 'bin'),
  join(home, '.claude', 'local'),
];

function which(p: Probe, name: string): string | undefined {
  return BIN_DIRS(p.home)
    .map((d) => join(d, name))
    .find((f) => p.executable(f));
}

/** `santactl status --json`, or undefined when Santa's daemon isn't answering. */
async function santaStatus(p: Probe): Promise<Record<string, Record<string, unknown>> | undefined> {
  if (!p.executable(SANTACTL)) return undefined;
  const r = await p.run(SANTACTL, ['status', '--json']);
  if (r.code !== 0) return undefined;
  try {
    return JSON.parse(r.stdout) as Record<string, Record<string, unknown>>;
  } catch {
    return undefined;
  }
}

export const CHECKS: Record<CheckId, (p: Probe) => Promise<CheckResult>> = {
  homebrew: async (p) => {
    const brew = ['/opt/homebrew/bin/brew', '/usr/local/bin/brew'].find((f) => p.executable(f));
    return brew ? { ok: true, detail: `Found at ${brew}` } : { ok: false };
  },

  'santa.installed': async (p) =>
    p.exists('/Applications/Santa.app') ? { ok: true } : { ok: false },

  'santa.running': async (p) => {
    const s = await santaStatus(p);
    if (!s) return { ok: false, detail: 'Santa isn’t answering yet' };
    const mode = typeof s['daemon']?.['mode'] === 'string' ? s['daemon']['mode'] : undefined;
    return { ok: true, ...(mode ? { detail: `Running in ${mode.toLowerCase()} mode` } : {}) };
  },

  'santa.profile': async (p) => {
    const s = await santaStatus(p);
    const server = s?.['sync']?.['server'];
    if (typeof server !== 'string' || !server) return { ok: false };
    const local = new RegExp(
      `^https?://(127\\.0\\.0\\.1|localhost|\\[::1\\]):${SANTA_SYNC_PORT}\\b`,
    );
    return local.test(server)
      ? { ok: true, detail: 'Santa gets its rules from Vigil' }
      : { ok: false, detail: `Santa syncs with ${server}, not Vigil` };
  },

  osquery: async (p) => {
    const bin = ['/usr/local/bin/osqueryi', '/opt/osquery/lib/osquery.app/Contents/MacOS/osqueryd'];
    return bin.some((f) => p.exists(f)) ? { ok: true } : { ok: false };
  },

  helper: async (p) => (p.exists(HELPER_SOCKET) ? { ok: true } : { ok: false }),

  ollama: async (p) => {
    const tags = await ollamaModels(p);
    return tags ? { ok: true } : { ok: false, detail: 'Nothing answers on 127.0.0.1:11434' };
  },

  'ollama.model': async (p) => {
    const names = (await ollamaModels(p)) ?? [];
    const ours = [LOCAL_MODEL, LOCAL_MODEL_SMALL].find((m) => names.includes(m));
    if (ours) return { ok: true, detail: ours };
    if (names.length) return { ok: true, detail: `Using ${names[0]} (already installed)` };
    return { ok: false };
  },

  claude: async (p) => {
    const bin = which(p, 'claude');
    if (!bin) return { ok: false };
    const r = await p.run(bin, ['auth', 'status']);
    const signedIn = r.code === 0 && !/not (logged|signed) in|"loggedIn":\s*false/i.test(r.stdout);
    return signedIn
      ? { ok: true, detail: 'Installed and signed in' }
      : { ok: false, detail: 'Installed, not signed in' };
  },

  codex: async (p) =>
    which(p, 'codex')
      ? { ok: true, detail: 'Installed. Sign in with ChatGPT from Settings › AI.' }
      : { ok: false },
};

async function ollamaModels(p: Probe): Promise<string[] | undefined> {
  try {
    const body = (await p.getJson('http://127.0.0.1:11434/api/tags')) as {
      models?: { name?: unknown }[];
    };
    return (body.models ?? []).map((m) => m.name).filter((n): n is string => typeof n === 'string');
  } catch {
    return undefined;
  }
}

const RUN_TIMEOUT_MS = 4000;

export function systemProbe(home = homedir()): Probe {
  // Finder-launched apps get a minimal PATH. Vendor CLIs installed with npm
  // are node scripts, so node has to be findable too.
  const env = { HOME: home, PATH: [...BIN_DIRS(home), '/usr/bin', '/bin'].join(':') };
  return {
    home,
    exists: (path) => existsSync(path),
    executable: (path) => {
      try {
        accessSync(path, constants.X_OK);
        return true;
      } catch {
        return false;
      }
    },
    run: (file, args) =>
      new Promise((resolve) => {
        execFile(
          file,
          args,
          { timeout: RUN_TIMEOUT_MS, maxBuffer: 256 * 1024, env },
          (err, stdout) => {
            const code = err ? (typeof err.code === 'number' ? err.code : 1) : 0;
            resolve({ code, stdout: String(stdout) });
          },
        );
      }),
    getJson: async (url) => {
      const res = await fetch(url, { signal: AbortSignal.timeout(1500) });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return res.json();
    },
  };
}
