import { createHash } from 'node:crypto';
import { cpSync, createWriteStream, lstatSync, readFileSync, renameSync, rmSync } from 'node:fs';
import { access, constants, mkdir, readdir, readFile, rm } from 'node:fs/promises';
import { basename, dirname, join, sep } from 'node:path';
import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { execOutputWithin } from '@vigil/ai';

/** What a release offers this Mac for installing itself: its zip and the release's checksums. */
export interface SelfUpdateAssets {
  version: string;
  zipName: string;
  zipUrl: string;
  sumsUrl: string;
}

/** A downloaded, checked copy of the new version, waiting next to the running one. */
export interface Staged {
  version: string;
  /** The new .app, in a hidden folder beside the running one so the swap is one rename. */
  app: string;
  /** SHA-256 of its Info.plist when it was checked, so the swap can tell it is unchanged. */
  plist: string;
}

export interface SelfUpdateOptions {
  /** The running .app bundle, from {@link bundleOf}. */
  bundle: string;
  /** The running app's CFBundleIdentifier; the new copy must carry the same. */
  bundleId: string;
  /** Where the zip downloads to, inside Vigil's own data folder. */
  downloads: string;
  fetch?: typeof fetch;
  /** Runs one of the system tools below and gives its output. */
  run?: (file: string, args: string[]) => Promise<string>;
  /** For tests: fs.renameSync, and the copy a failed restore falls back to. */
  rename?: (from: string, to: string) => void;
  copy?: (from: string, to: string) => void;
}

/** A release zip is about 150 MB; anything far past that isn't one. */
export const MAX_ZIP_BYTES = 800 * 1024 * 1024;
const STAGE_DIR = '.vigil-update';
/** Where GitHub serves this repo's release files from, after its redirects. */
const DOWNLOAD_HOSTS = new Set([
  'github.com',
  'objects.githubusercontent.com',
  'release-assets.githubusercontent.com',
]);
/** The name electron-builder gives a Mac release zip (electron-builder.yml). */
const ZIP_NAME = /^Vigil-at-Home-[0-9][0-9A-Za-z.+-]*-(arm64|x64)\.zip$/;

/** Refuses a response that a redirect took anywhere but GitHub's own release hosts. */
function checkLanding(res: Response, what: string): void {
  let host = '';
  try {
    const u = new URL(res.url);
    if (u.protocol === 'https:') host = u.hostname;
  } catch {
    // An empty or odd URL is refused below.
  }
  if (!DOWNLOAD_HOSTS.has(host)) throw new Error(`${what} came from somewhere other than GitHub`);
}

const sha256 = (b: Buffer) => createHash('sha256').update(b).digest('hex');

/**
 * The .app bundle a macOS executable path belongs to, or undefined outside one
 * (a dev build runs from node_modules/electron).
 */
export function bundleOf(execPath: string): string | undefined {
  const m = /^(\/.+?\.app)\/Contents\/MacOS\/[^/]+$/.exec(execPath);
  return m && !m[1]!.includes('/node_modules/') ? m[1] : undefined;
}

/** The SHA-256 a SHA256SUMS.txt (as `sha256sum` writes it) lists for one file. */
export function sumFor(sums: string, name: string): string | undefined {
  for (const line of sums.split('\n')) {
    const m = /^([0-9a-f]{64}) [ *](.+)$/.exec(line.trim());
    if (m && m[2] === name) return m[1];
  }
  return undefined;
}

/**
 * Installs a newer release in place of the running app, with the same trust
 * as dragging the DMG in by hand: the zip comes from this project's GitHub
 * release, must match the release's SHA256SUMS, and must unpack to one app
 * with Vigil's bundle id, the expected version and a valid signature. The
 * root helper is not touched here: once the new app starts, it sees the
 * helper is outdated and asks for the admin password as it always has.
 *
 * Accepted: the zip and SHA256SUMS come from the same release, so they catch
 * a damaged or swapped download, not a release published by someone holding
 * the repo. Builds are ad hoc signed, so codesign pins no developer either.
 * Developer ID signing is the fix for that; until then this matches the
 * trust of installing the DMG by hand.
 */
export class SelfUpdater {
  private readonly run: (file: string, args: string[]) => Promise<string>;
  private readonly rename: (from: string, to: string) => void;
  /**
   * A restore failed and the only copy of the app is previous.app in the
   * staging folder: nothing may stage (which clears that folder) again.
   */
  private stranded = false;

  constructor(private readonly o: SelfUpdateOptions) {
    this.run = o.run ?? runTool;
    this.rename = o.rename ?? renameSync;
  }

  private get stageRoot(): string {
    return join(dirname(this.o.bundle), STAGE_DIR);
  }

  /**
   * Whether this copy can replace itself: it runs from a folder the user can
   * write (not a DMG, a translocated copy or a root-owned install).
   */
  async canInstall(): Promise<boolean> {
    const b = this.o.bundle;
    if (b.startsWith('/Volumes/') || b.includes('/AppTranslocation/')) return false;
    try {
      await access(dirname(b), constants.W_OK);
      await access(b, constants.W_OK);
      await access(join(b, 'Contents'), constants.W_OK);
      return true;
    } catch {
      return false;
    }
  }

  /** Downloads, checks and unpacks a release beside the running app. Throws, in words, on any mismatch. */
  async stage(a: SelfUpdateAssets): Promise<Staged> {
    if (this.stranded) throw new Error('the previous version still needs to be moved back');
    const f = this.o.fetch ?? fetch;
    if (basename(a.zipName) !== a.zipName || !ZIP_NAME.test(a.zipName))
      throw new Error('the release’s zip has an unexpected name');
    const sumsRes = await f(a.sumsUrl, { signal: AbortSignal.timeout(30_000) });
    if (!sumsRes.ok) throw new Error(`the release’s checksums answered ${sumsRes.status}`);
    checkLanding(sumsRes, 'the release’s checksums');
    const want = sumFor(await sumsRes.text(), a.zipName);
    if (!want) throw new Error(`the release’s checksums don’t list ${a.zipName}`);

    await mkdir(this.o.downloads, { recursive: true });
    const zip = join(this.o.downloads, a.zipName);
    const res = await f(a.zipUrl, { signal: AbortSignal.timeout(30 * 60_000) });
    if (!res.ok || !res.body) throw new Error(`the download answered ${res.status}`);
    checkLanding(res, 'the download');
    const hash = createHash('sha256');
    let bytes = 0;
    const counted = Readable.fromWeb(res.body as never).map((chunk: Buffer) => {
      bytes += chunk.length;
      if (bytes > MAX_ZIP_BYTES) throw new Error('the download is far larger than a release');
      hash.update(chunk);
      return chunk;
    });
    try {
      await pipeline(counted, createWriteStream(zip));
      const got = hash.digest('hex');
      if (got !== want) throw new Error('the download doesn’t match the release’s checksum');

      const out = join(this.stageRoot, a.version);
      await rm(this.stageRoot, { recursive: true, force: true });
      await mkdir(out, { recursive: true });
      // --noqtn: never carry a download flag onto the new app. The zip has none
      // (Node's fetch sets none), and an app with the flag and no Developer ID
      // signature trips the "Unsigned download opened" rule, which would
      // stop and quarantine Vigil itself.
      await this.run('/usr/bin/ditto', ['-x', '-k', '--noqtn', zip, out]);
      const apps = (await readdir(out)).filter((n) => n.endsWith('.app'));
      if (apps.length !== 1) throw new Error('the download doesn’t hold exactly one app');
      const app = join(out, apps[0]!);
      const plist = join(app, 'Contents', 'Info.plist');
      const id = (
        await this.run('/usr/bin/plutil', ['-extract', 'CFBundleIdentifier', 'raw', plist])
      ).trim();
      if (id !== this.o.bundleId) throw new Error('the download is a different app');
      const version = (
        await this.run('/usr/bin/plutil', ['-extract', 'CFBundleShortVersionString', 'raw', plist])
      ).trim();
      if (version !== a.version)
        throw new Error(`the download says it is ${version}, not ${a.version}`);
      await this.run('/usr/bin/codesign', ['--verify', '--deep', '--strict', app]);
      return { version: a.version, app, plist: sha256(await readFile(plist)) };
    } catch (err) {
      await rm(this.stageRoot, { recursive: true, force: true }).catch(() => {});
      throw err;
    } finally {
      await rm(zip, { force: true }).catch(() => {});
    }
  }

  /**
   * Puts the staged app where the running one is: two renames, back to back
   * and synchronous, so nothing (a quit included) can run between them. The
   * running process keeps its open files, so the caller relaunches straight
   * after. First it checks the staged copy is still the one checked: a real
   * folder (not a link) inside the staging folder, with the same Info.plist.
   * If the second rename fails, the old app goes back (renamed, or copied if
   * that fails too); if even that fails, the error says where it is.
   *
   * Accepted: if the process dies between the two renames, the app is only
   * in the staging folder; the window is two system calls long.
   */
  swap(s: Staged): void {
    if (this.stranded) throw new Error('the previous version still needs to be moved back');
    this.verifyStaged(s);
    const previous = join(this.stageRoot, 'previous.app');
    rmSync(previous, { recursive: true, force: true });
    this.rename(this.o.bundle, previous);
    try {
      this.rename(s.app, this.o.bundle);
    } catch (err) {
      this.restore(previous);
      throw err;
    }
  }

  private verifyStaged(s: Staged): void {
    const root = lstatSync(this.stageRoot);
    if (!root.isDirectory() || root.isSymbolicLink())
      throw new Error('the staging folder isn’t a plain folder');
    if (!s.app.startsWith(this.stageRoot + sep)) throw new Error('the staged app is elsewhere');
    const app = lstatSync(s.app);
    if (!app.isDirectory() || app.isSymbolicLink())
      throw new Error('the staged app isn’t a plain folder');
    if (sha256(readFileSync(join(s.app, 'Contents', 'Info.plist'))) !== s.plist)
      throw new Error('the staged app changed after it was checked');
  }

  private restore(previous: string): void {
    try {
      this.rename(previous, this.o.bundle);
      return;
    } catch {
      // Try a copy instead.
    }
    try {
      rmSync(this.o.bundle, { recursive: true, force: true });
      if (this.o.copy) this.o.copy(previous, this.o.bundle);
      else cpSync(previous, this.o.bundle, { recursive: true, verbatimSymlinks: true });
    } catch {
      this.stranded = true;
      throw new Error(
        `Vigil couldn’t put itself back. The previous version is at ${previous}; move it to ${this.o.bundle}`,
      );
    }
  }

  /**
   * Clears what an earlier update left beside the app (the old copy, a
   * half-staged one). Synchronous, at start, before anything stages.
   */
  cleanup(): void {
    try {
      rmSync(this.stageRoot, { recursive: true, force: true });
    } catch {
      // Tried again next start.
    }
  }
}

function runTool(file: string, args: string[]): Promise<string> {
  return execOutputWithin(file, args, 5 * 60_000, { maxBuffer: 1024 * 1024 });
}
