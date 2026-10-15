import { createHash } from 'node:crypto';
import { createWriteStream, renameSync, rmSync } from 'node:fs';
import { access, constants, mkdir, readdir, rename, rm } from 'node:fs/promises';
import { dirname, join } from 'node:path';
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
}

/** A release zip is about 150 MB; anything far past that isn't one. */
export const MAX_ZIP_BYTES = 800 * 1024 * 1024;
const STAGE_DIR = '.vigil-update';

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
 */
export class SelfUpdater {
  private readonly run: (file: string, args: string[]) => Promise<string>;

  constructor(private readonly o: SelfUpdateOptions) {
    this.run = o.run ?? runTool;
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
    const f = this.o.fetch ?? fetch;
    const sumsRes = await f(a.sumsUrl, { signal: AbortSignal.timeout(30_000) });
    if (!sumsRes.ok) throw new Error(`the release’s checksums answered ${sumsRes.status}`);
    const want = sumFor(await sumsRes.text(), a.zipName);
    if (!want) throw new Error(`the release’s checksums don’t list ${a.zipName}`);

    await mkdir(this.o.downloads, { recursive: true });
    const zip = join(this.o.downloads, a.zipName);
    const res = await f(a.zipUrl, { signal: AbortSignal.timeout(30 * 60_000) });
    if (!res.ok || !res.body) throw new Error(`the download answered ${res.status}`);
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
      return { version: a.version, app };
    } catch (err) {
      await rm(this.stageRoot, { recursive: true, force: true }).catch(() => {});
      throw err;
    } finally {
      await rm(zip, { force: true }).catch(() => {});
    }
  }

  /**
   * Puts the staged app where the running one is. The running process keeps
   * its open files, so the caller relaunches straight after. If the second
   * rename fails, the old app goes back.
   */
  async swap(s: Staged): Promise<void> {
    const previous = join(this.stageRoot, 'previous.app');
    await rm(previous, { recursive: true, force: true });
    await rename(this.o.bundle, previous);
    try {
      await rename(s.app, this.o.bundle);
    } catch (err) {
      await rename(previous, this.o.bundle);
      throw err;
    }
  }

  /** {@link swap} for the moment Vigil quits, when nothing async gets to finish. */
  swapSync(s: Staged): void {
    const previous = join(this.stageRoot, 'previous.app');
    rmSync(previous, { recursive: true, force: true });
    renameSync(this.o.bundle, previous);
    try {
      renameSync(s.app, this.o.bundle);
    } catch (err) {
      renameSync(previous, this.o.bundle);
      throw err;
    }
  }

  /** Clears what an earlier update left beside the app (the old copy, a half-staged one). */
  async cleanup(): Promise<void> {
    await rm(this.stageRoot, { recursive: true, force: true }).catch(() => {});
  }
}

function runTool(file: string, args: string[]): Promise<string> {
  return execOutputWithin(file, args, 5 * 60_000, { maxBuffer: 1024 * 1024 });
}
