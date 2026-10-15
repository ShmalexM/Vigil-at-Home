import { EventEmitter } from 'node:events';
import { z } from 'zod';
import type { UpdateView } from '../shared/updates.js';
import type { SelfUpdateAssets, SelfUpdater, Staged } from './self-update.js';

/** Where releases are published. Only published releases are visible; drafts never are. */
export const RELEASES_URL =
  'https://api.github.com/repos/ShmalexM/Vigil-at-Home/releases?per_page=30';
/** Wait a little after start, then check a few times a day. */
export const FIRST_CHECK_MS = 60_000;
export const CHECK_EVERY_MS = 6 * 60 * 60_000;
/** A downloaded update installs once the computer has been left alone this long. */
export const IDLE_INSTALL_S = 10 * 60;
const INSTALL_TICK_MS = 60_000;

const Release = z.object({
  tag_name: z.string().max(100),
  html_url: z.string().max(500),
  draft: z.boolean(),
  prerelease: z.boolean(),
  published_at: z.string().nullable().optional(),
  assets: z
    .array(z.object({ name: z.string().max(300), browser_download_url: z.string().max(1000) }))
    .default([]),
});
const Releases = z.array(z.unknown());

const Saved = z.object({
  auto: z.boolean().default(true),
  /** Download and install by itself, where this copy can (see SelfUpdater). */
  install: z.boolean().default(true),
  dismissed: z.string().max(100).optional(),
  /** The version that ran last, so the first start of a new one can say it updated. */
  lastRun: z.string().max(100).optional(),
});
type Saved = z.infer<typeof Saved>;

export interface UpdateOptions {
  current: string;
  /** process.arch: arm64 (Apple silicon) or x64 (Intel), matching the DMG names. */
  arch: string;
  /**
   * process.platform. Only macOS gets a direct installer link: the Linux .deb
   * and AppImage can't be told apart from here, and an x64 DMG must never be
   * offered to an x64 Linux machine. Elsewhere the release page opens instead.
   */
  platform?: NodeJS.Platform;
  load: () => unknown;
  save: (s: Saved) => void;
  fetch?: typeof fetch;
  openExternal: (url: string) => Promise<void>;
  /** Told once per version when a newer release turns up and won't install by itself. */
  onFound?: (version: string) => void;
  now?: () => number;
  /** macOS, packaged: installs updates in place. Elsewhere the user downloads them. */
  installer?: Pick<SelfUpdater, 'canInstall' | 'stage' | 'swap'>;
  /** Starts the new version once the swap is done (app.relaunch, then exit). */
  relaunch?: () => void;
  /** Seconds since the user last touched the keyboard or mouse. */
  idleSeconds?: () => number;
  /** False while something on screen is waiting for the user (a popup, a password dialog). */
  canRestart?: () => boolean;
}

/**
 * Checks GitHub for a newer published release. It sends nothing about the
 * user or the Mac: one anonymous GET of the public releases list.
 */
export class UpdateChecker extends EventEmitter<{ changed: [] }> {
  private checking = false;
  private lastCheckedAt: number | undefined;
  private error: string | undefined;
  private available: UpdateView['available'];
  private told = new Set<string>();
  private timers: ReturnType<typeof setTimeout>[] = [];
  private canSelf: boolean | undefined;
  private staging: string | undefined;
  private staged: Staged | undefined;
  private installError: { version: string; error: string } | undefined;
  /** Quitting: a check still in flight must not start staging. */
  private stopped = false;
  private updatedFrom: string | undefined;

  constructor(private readonly o: UpdateOptions) {
    super();
  }

  private saved(): Saved {
    const r = Saved.safeParse(this.o.load() ?? {});
    return r.success ? r.data : { auto: true, install: true };
  }

  view(): UpdateView {
    const s = this.saved();
    return {
      current: this.o.current,
      auto: s.auto,
      checking: this.checking,
      ...(this.lastCheckedAt !== undefined ? { lastCheckedAt: this.lastCheckedAt } : {}),
      ...(this.error ? { error: this.error } : {}),
      ...(this.available ? { available: this.available } : {}),
      dismissed: !!this.available && s.dismissed === this.available.version,
      install: s.install,
      ...(this.updatedFrom ? { updatedFrom: this.updatedFrom } : {}),
      selfInstall: !!this.canSelf,
      ...(this.staging ? { preparing: this.staging } : {}),
      ...(this.staged ? { ready: this.staged.version } : {}),
      ...(this.installError ? { installError: this.installError.error } : {}),
    };
  }

  /** Whether this copy installs updates by itself (decided once, at start). */
  private async selfInstalls(): Promise<boolean> {
    if (!this.o.installer) return false;
    this.canSelf ??= await this.o.installer.canInstall().catch(() => false);
    return this.canSelf;
  }

  /**
   * Downloads and checks the available version beside the app, once per
   * version, unless the user turned automatic installs off. A failure is kept
   * in words and the version isn't tried again until the next start.
   */
  private async prepare(): Promise<void> {
    const a = this.available;
    const assets = a?.selfUpdate;
    if (!a || !assets || !this.saved().install || !(await this.selfInstalls())) return;
    if (this.stopped || this.staging || this.staged?.version === a.version) return;
    if (this.installError?.version === a.version) return;
    // Staging clears the folder beside the app, so an older staged copy goes too.
    this.staged = undefined;
    this.staging = a.version;
    this.emit('changed');
    try {
      this.staged = await this.o.installer!.stage({ version: a.version, ...assets });
    } catch (err) {
      this.installError = {
        version: a.version,
        error: `Couldn’t get ${a.version} ready to install (${err instanceof Error ? err.message : String(err)})`,
      };
    } finally {
      this.staging = undefined;
      this.emit('changed');
    }
  }

  /** Installs now if an update is ready and the user is away. */
  private maybeInstall(): void {
    if (this.saved().install) this.install();
  }

  /**
   * Swaps in the downloaded version and starts it; the helper keeps blocking
   * meanwhile. Synchronous from the checks to the relaunch, so nothing (a
   * quit, a new staging, the user coming back) can happen in between. Waits
   * while a version is being staged, and while a popup or password dialog
   * is open. Unless `now` (the user pressed Restart to update), also waits
   * until the computer has been left alone for {@link IDLE_INSTALL_S}.
   *
   * canRestart sees every password dialog the app has open (approvalOpen
   * counts the dialog programs until they exit), and each closes itself,
   * as a no, before the app stops waiting on it.
   *
   * Accepted: idle time and canRestart are read just before the swap, not
   * during it. The swap and relaunch take a moment, and relaunching straight
   * away is safer than leaving a swapped app running.
   */
  install(now = false): void {
    const s = this.staged;
    if (!s || this.staging || !this.o.installer) return;
    if (!now && (this.o.idleSeconds?.() ?? 0) < IDLE_INSTALL_S) return;
    if (this.o.canRestart && !this.o.canRestart()) return;
    try {
      this.o.installer.swap(s);
    } catch (err) {
      this.staged = undefined;
      this.installError = {
        version: s.version,
        error: `Couldn’t install ${s.version} (${err instanceof Error ? err.message : String(err)})`,
      };
      this.emit('changed');
      return;
    }
    this.staged = undefined;
    this.o.relaunch?.();
  }

  /** On quit: put a downloaded update in place so the next start runs it. */
  installOnQuit(): boolean {
    const s = this.staged;
    if (!s || this.staging || !this.o.installer || !this.saved().install) return false;
    // Not under a password dialog or the helper's installer, which checks
    // the app it installs from. The staged copy is cleared at the next
    // start, so that run downloads it again and installs it later.
    if (this.o.canRestart && !this.o.canRestart()) return false;
    try {
      this.o.installer.swap(s);
      this.staged = undefined;
      return true;
    } catch (err) {
      // Accepted: on quit there is no window left to say so, only this log.
      // A failed swap normally puts the old app back; if even that failed,
      // the error names where the old copy is.
      console.error('[updates] could not install on quit:', err);
      return false;
    }
  }

  /** Starts the automatic checks. */
  start(): void {
    const s = this.saved();
    if (s.lastRun && compareVersions(s.lastRun, this.o.current) < 0) this.updatedFrom = s.lastRun;
    if (s.lastRun !== this.o.current) this.o.save({ ...s, lastRun: this.o.current });
    const tick = () => {
      if (this.saved().auto) void this.check();
    };
    this.timers.push(setTimeout(tick, FIRST_CHECK_MS));
    this.timers.push(setInterval(tick, CHECK_EVERY_MS));
    if (this.o.installer) this.timers.push(setInterval(() => this.maybeInstall(), INSTALL_TICK_MS));
  }

  stop(): void {
    this.stopped = true;
    for (const t of this.timers) clearTimeout(t);
    this.timers = [];
  }

  async check(): Promise<UpdateView> {
    if (this.checking) return this.view();
    this.checking = true;
    this.emit('changed');
    try {
      const res = await (this.o.fetch ?? fetch)(RELEASES_URL, {
        headers: { Accept: 'application/vnd.github+json', 'User-Agent': 'Vigil-at-Home' },
        signal: AbortSignal.timeout(20_000),
      });
      if (!res.ok) throw new Error(`GitHub answered ${res.status}`);
      this.available = newest(
        Releases.parse(await res.json()),
        this.o.current,
        this.o.arch,
        this.o.platform,
      );
      this.error = undefined;
      const v = this.available?.version;
      // A version that failed to install by itself goes back to the user.
      const selfInstalls =
        !!this.available?.selfUpdate &&
        this.saved().install &&
        this.installError?.version !== v &&
        (await this.selfInstalls());
      if (selfInstalls) void this.prepare();
      else if (v && !this.told.has(v) && this.saved().dismissed !== v) {
        this.told.add(v);
        this.o.onFound?.(v);
      }
    } catch (err) {
      this.error = `Couldn’t check for updates (${err instanceof Error ? err.message : String(err)})`;
    } finally {
      this.checking = false;
      this.lastCheckedAt = (this.o.now ?? Date.now)();
      this.emit('changed');
    }
    return this.view();
  }

  /**
   * install: check, download and install by itself; notify: check and say so;
   * manual: only when the user presses Check now.
   */
  setMode(mode: 'install' | 'notify' | 'manual'): void {
    this.o.save({ ...this.saved(), auto: mode !== 'manual', install: mode === 'install' });
    if (mode === 'install') void this.prepare();
    this.emit('changed');
  }

  /** Hides the notice until a newer version than this one comes out. */
  dismiss(): void {
    if (!this.available) return;
    this.o.save({ ...this.saved(), dismissed: this.available.version });
    this.emit('changed');
  }

  /** Opens the DMG download (or the release page) in the browser. Nothing installs by itself. */
  async download(): Promise<void> {
    const a = this.available;
    if (!a) return;
    await this.o.openExternal(a.downloadUrl ?? a.notesUrl);
  }

  /** Opens the release's page on GitHub, to read what changed. */
  async openNotes(): Promise<void> {
    if (this.available) await this.o.openExternal(this.available.notesUrl);
  }
}

/**
 * The newest release newer than `current`, or undefined. Pre-releases count on
 * a pre-release, and on any build while no full release has been published yet
 * (every Vigil release so far is an alpha, and local builds say 0.0.1).
 */
export function newest(
  raw: unknown[],
  current: string,
  arch: string,
  platform: NodeJS.Platform = 'darwin',
): UpdateView['available'] | undefined {
  const releases = raw.flatMap((item) => {
    const p = Release.safeParse(item);
    return p.success && !p.data.draft ? [p.data] : [];
  });
  const takePre =
    parseVersion(current)?.pre.length !== 0 ||
    !releases.some((r) => !r.prerelease && parseVersion(r.tag_name.replace(/^v/, '')));
  let best: { version: string; r: z.infer<typeof Release> } | undefined;
  for (const r of releases) {
    if (r.prerelease && !takePre) continue;
    const version = r.tag_name.replace(/^v/, '');
    if (!parseVersion(version) || !isGitHub(r.html_url)) continue;
    if (compareVersions(version, current) <= 0) continue;
    // A release with nothing to install on this Linux machine isn't an update for it.
    if (platform === 'linux' && !r.assets.some((a) => isLinuxPackage(a.name, arch))) continue;
    if (!best || compareVersions(version, best.version) > 0) best = { version, r };
  }
  if (!best) return undefined;
  const dmg =
    platform === 'darwin'
      ? best.r.assets.find(
          (a) => a.name.endsWith(`-${arch}.dmg`) && isGitHub(a.browser_download_url),
        )
      : undefined;
  const zip =
    platform === 'darwin'
      ? best.r.assets.find(
          (a) => a.name.endsWith(`-${arch}.zip`) && isGitHub(a.browser_download_url),
        )
      : undefined;
  const sums = best.r.assets.find(
    (a) => a.name === 'SHA256SUMS.txt' && isGitHub(a.browser_download_url),
  );
  const selfUpdate: Omit<SelfUpdateAssets, 'version'> | undefined =
    zip && sums
      ? { zipName: zip.name, zipUrl: zip.browser_download_url, sumsUrl: sums.browser_download_url }
      : undefined;
  return {
    version: best.version,
    notesUrl: best.r.html_url,
    ...(dmg ? { downloadUrl: dmg.browser_download_url } : {}),
    ...(selfUpdate ? { selfUpdate } : {}),
    ...(best.r.published_at ? { publishedAt: best.r.published_at } : {}),
  };
}

/**
 * A .deb or AppImage for this chip, as electron-builder names them: the
 * .deb says amd64 and the AppImage x86_64 for x64; both say arm64 for ARM.
 */
export function isLinuxPackage(name: string, arch: string): boolean {
  const tags =
    arch === 'x64' ? ['amd64.deb', 'x86_64.AppImage'] : [`${arch}.deb`, `${arch}.AppImage`];
  return tags.some((t) => name.endsWith(`-${t}`));
}

/** Only ever open links to this project's own pages on github.com. */
function isGitHub(url: string): boolean {
  try {
    const u = new URL(url);
    return (
      u.protocol === 'https:' &&
      u.hostname === 'github.com' &&
      u.pathname.toLowerCase().startsWith('/shmalexm/vigil-at-home/')
    );
  } catch {
    return false;
  }
}

function parseVersion(v: string): { nums: number[]; pre: string[] } | undefined {
  const m = /^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/.exec(v);
  if (!m) return undefined;
  return { nums: [Number(m[1]), Number(m[2]), Number(m[3])], pre: m[4] ? m[4].split('.') : [] };
}

/** Semantic-version order: 0.1.0-alpha.2 < 0.1.0-alpha.10 < 0.1.0-beta.1 < 0.1.0. */
export function compareVersions(a: string, b: string): number {
  const x = parseVersion(a);
  const y = parseVersion(b);
  if (!x || !y) return 0;
  for (let i = 0; i < 3; i++) if (x.nums[i] !== y.nums[i]) return x.nums[i]! - y.nums[i]!;
  if (!x.pre.length || !y.pre.length) return y.pre.length - x.pre.length;
  for (let i = 0; i < Math.min(x.pre.length, y.pre.length); i++) {
    const p = x.pre[i]!;
    const q = y.pre[i]!;
    if (p === q) continue;
    const pn = /^\d+$/.test(p);
    const qn = /^\d+$/.test(q);
    if (pn && qn) return Number(p) - Number(q);
    if (pn !== qn) return pn ? -1 : 1;
    return p < q ? -1 : 1;
  }
  return x.pre.length - y.pre.length;
}
