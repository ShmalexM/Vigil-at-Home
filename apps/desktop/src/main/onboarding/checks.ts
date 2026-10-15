import { execFileWithin } from '@vigil/ai';
import { accessSync, constants, existsSync } from 'node:fs';
import { homedir, totalmem } from 'node:os';
import { classifierModelChoice } from '@vigil/ai';
import { join } from 'node:path';
import type { CheckId } from '../../shared/setup.js';
import { FAPOLICYD_ALLOW_RULES, LOCAL_MODEL, LOCAL_MODEL_SMALL } from './plan.js';

export interface CheckResult {
  ok: boolean;
  detail?: string;
  /**
   * Not done because something already installed has to be installed again
   * (Santa's profile from before its client certificate). The step then says
   * so in its title and is offered once outside Setup.
   */
  again?: string;
  /**
   * Not done yet, and nothing for the user to do: Vigil is waiting for
   * something to happen by itself (Santa's first sync). Shown as waiting,
   * with `detail`, never as a banner.
   */
  waiting?: boolean;
}

/** Shown on the Santa profile step until Santa first syncs its rules with its certificate. */
export const SANTA_FIRST_SYNC = 'Waiting for Santa’s first sync';

/** Shown on the Santa profile step while the helper can't be asked how Santa's syncs go. */
export const SANTA_UNVERIFIED = 'Waiting for the Vigil helper to confirm Santa’s syncs';

/** Shown when Santa syncs with Vigil on a profile that predates its client certificate. */
export const SANTA_REINSTALL = 'Reinstall the Santa profile to finish securing Santa';

/** Everything a check touches, so tests can fake a Mac. Read-only: nothing here installs or changes anything. */
export interface Probe {
  exists(path: string): boolean;
  executable(path: string): boolean;
  /** Run a program by absolute path with a timeout (default 4 s). Never through a shell. */
  run(
    file: string,
    args: string[],
    opts?: { timeoutMs?: number },
  ): Promise<{ code: number; stdout: string; timedOut?: boolean }>;
  getJson(url: string): Promise<unknown>;
  /** Ask the running helper for its status over its socket; true when it answers. */
  helperAnswers?(): Promise<boolean>;
  /** What the helper says about Santa's client certificate (helper.status), or null. */
  helperSanta?(): Promise<{
    clientCertRequired?: boolean;
    clientCertIssued?: boolean;
    /** When Santa last finished a rule sync with its certificate; null if it never has. */
    lastAuthRuleSyncAt?: number | null;
  } | null>;
  home: string;
  /** Which computer is being checked; defaults to a Mac. */
  platform?: NodeJS.Platform;
  /** Total memory, which decides the labelling models Vigil will pick; defaults to this machine's. */
  memoryBytes?: number;
  /** The labelling model set in AI settings (`classifier.model`), if any. */
  classifierModel?(): string | undefined;
}

export const SANTA_SYNC_PORT = 47821;
/** The helper's socket: /var/run on macOS, /run on Linux (see the helper's config). */
export const HELPER_SOCKET =
  process.platform === 'linux' ? '/run/vigil-helper.sock' : '/var/run/vigil-helper.sock';
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
    if (!local.test(server)) return { ok: false, detail: `Santa syncs with ${server}, not Vigil` };
    // The helper has a client certificate for Santa but still serves it
    // without one: the installed profile is from before the certificate.
    const cert = await p.helperSanta?.().catch(() => null);
    // Without the helper's status nothing confirms Santa reaches Vigil: the
    // step stays unverified rather than done.
    if (!cert) return { ok: false, waiting: true, detail: SANTA_UNVERIFIED };
    if (cert.clientCertIssued && cert.clientCertRequired === false) {
      return {
        ok: false,
        again: SANTA_REINSTALL,
        detail:
          'Santa gets its rules from Vigil, but its profile is from before Santa had its own certificate, so another program on this Mac could still sync in its place. Installing the new profile replaces the old one.',
      };
    }
    // Done only once Santa has synced its rules with its certificate: the
    // profile pointing at Vigil proves nothing about Santa reaching it.
    // Older helpers don't report it (undefined), and are taken at their word.
    if (cert.clientCertRequired && cert.lastAuthRuleSyncAt === null) {
      return { ok: false, waiting: true, detail: SANTA_FIRST_SYNC };
    }
    return {
      ok: true,
      detail: cert.clientCertRequired
        ? 'Santa gets its rules from Vigil, with its own certificate'
        : 'Santa gets its rules from Vigil',
    };
  },

  osquery: async (p) => {
    const bin =
      p.platform === 'linux'
        ? ['/opt/osquery/bin/osqueryd', '/usr/bin/osqueryd']
        : ['/usr/local/bin/osqueryi', '/opt/osquery/lib/osquery.app/Contents/MacOS/osqueryd'];
    return bin.some((f) => p.exists(f)) ? { ok: true } : { ok: false };
  },

  fapolicyd: async (p) => {
    if (!['/usr/sbin/fapolicyd', '/usr/bin/fapolicyd'].some((f) => p.exists(f))) {
      return { ok: false };
    }
    if (!p.exists(FAPOLICYD_ALLOW_RULES)) {
      return {
        ok: false,
        detail: 'Installed, but it isn’t set to allow what Vigil hasn’t blocked',
      };
    }
    const r = await p.run('/usr/bin/systemctl', ['is-active', '--quiet', 'fapolicyd']);
    return r.code === 0 ? { ok: true } : { ok: false, detail: 'Installed, not running' };
  },

  helper: async (p) => {
    if (!p.exists(HELPER_SOCKET)) return { ok: false };
    // A socket file can outlive the helper, so only an answer counts.
    if (!(await p.helperAnswers?.())) {
      return { ok: false, detail: 'Installed, but the helper isn’t answering' };
    }
    return { ok: true, detail: 'Running and answering' };
  },

  ollama: async (p) => {
    const tags = await ollamaModels(p);
    return tags ? { ok: true } : { ok: false, detail: 'Nothing answers on 127.0.0.1:11434' };
  },

  /**
   * Labelling only ever uses one of @vigil/ai's small models, so this says
   * which one, the same way the labeller picks it. A big model the user
   * already has explains alerts, but doesn't stand in for the small one.
   */
  'ollama.model': async (p) => {
    const names = (await ollamaModels(p)) ?? [];
    // The labeller's own choice, so this step is done exactly when labelling has a model.
    const picked = classifierModelChoice(
      names.map((name) => ({ name })),
      p.classifierModel?.(),
      p.memoryBytes ?? totalmem(),
    );
    if (picked) {
      const ours = picked === LOCAL_MODEL || picked === LOCAL_MODEL_SMALL;
      return { ok: true, detail: `${picked}${ours ? '' : ', already installed,'} labels events` };
    }
    if (names.length) {
      return {
        ok: false,
        detail: `${names.length === 1 ? names[0] : `${names.length} models`} already installed can explain alerts, but labelling events needs a small model`,
      };
    }
    return { ok: false };
  },

  claude: async (p) => {
    const bin = which(p, 'claude');
    if (!bin) return { ok: false };
    // Claude Code can take several seconds to start, especially the first time
    // after an update, so it gets a longer timeout than the other checks.
    const r = await p.run(bin, ['auth', 'status', '--json'], { timeoutMs: CLAUDE_TIMEOUT_MS });
    if (r.timedOut) {
      return {
        ok: false,
        detail: `Installed, but claude auth status didn’t answer within ${CLAUDE_TIMEOUT_MS / 1000} s`,
      };
    }
    let signedIn: boolean;
    try {
      signedIn = (JSON.parse(r.stdout) as { loggedIn?: unknown }).loggedIn === true;
    } catch {
      // Older versions without --json: go by the exit code and wording.
      signedIn = r.code === 0 && !/not (logged|signed) in/i.test(r.stdout);
    }
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
export const CLAUDE_TIMEOUT_MS = 15_000;

/** What a checked CLI may inherit: enough to find its login and reach the network, nothing else. */
const INHERITED_ENV = [
  'USER',
  'LOGNAME',
  'LANG',
  'LC_ALL',
  'LC_CTYPE',
  'TMPDIR',
  'HTTPS_PROXY',
  'HTTP_PROXY',
  'NO_PROXY',
  'https_proxy',
  'http_proxy',
  'no_proxy',
  'NODE_EXTRA_CA_CERTS',
  'SSL_CERT_FILE',
] as const;

export function systemProbe(
  home = homedir(),
  helperAnswers?: () => Promise<boolean>,
  helperSanta?: Probe['helperSanta'],
): Probe {
  // Finder-launched apps get a minimal PATH. Vendor CLIs installed with npm
  // are node scripts, so node has to be findable too.
  const env: Record<string, string> = {};
  for (const name of INHERITED_ENV) {
    const v = process.env[name];
    if (v !== undefined) env[name] = v;
  }
  env['HOME'] = home;
  env['PATH'] = [...BIN_DIRS(home), '/usr/bin', '/bin'].join(':');
  return {
    home,
    platform: process.platform,
    ...(helperAnswers ? { helperAnswers } : {}),
    ...(helperSanta ? { helperSanta } : {}),
    exists: (path) => existsSync(path),
    executable: (path) => {
      try {
        accessSync(path, constants.X_OK);
        return true;
      } catch {
        return false;
      }
    },
    run: async (file, args, opts) => {
      const r = await execFileWithin(file, args, opts?.timeoutMs ?? RUN_TIMEOUT_MS, {
        maxBuffer: 256 * 1024,
        env,
      });
      return { code: r.code ?? 1, stdout: r.stdout, ...(r.timedOut ? { timedOut: true } : {}) };
    },
    getJson: async (url) => {
      const res = await fetch(url, { signal: AbortSignal.timeout(1500) });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return res.json();
    },
  };
}
