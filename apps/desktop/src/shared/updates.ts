/**
 * Update notices, shared by main and the renderer. On a Mac where Vigil runs
 * from a folder the user can write, it downloads, checks and installs a newer
 * release by itself while the user is away; elsewhere it offers the installer.
 */
export interface UpdateView {
  /** The version running now. */
  current: string;
  /** Checks run on their own (at start and every few hours) unless the user turns them off. */
  auto: boolean;
  checking: boolean;
  lastCheckedAt?: number;
  /** Why the last check failed, in words. */
  error?: string;
  /** The newest published release, when it's newer than this one. */
  available?: {
    version: string;
    /** The release page on GitHub. */
    notesUrl: string;
    /** The DMG for this Mac's chip, when the release has one. */
    downloadUrl?: string;
    publishedAt?: string;
    /** The zip and checksums this Mac installs itself from, when the release has them. */
    selfUpdate?: { zipName: string; zipUrl: string; sumsUrl: string };
  };
  /** The user chose Later for this version; the banner stays hidden until a newer one. */
  dismissed: boolean;
  /** The user lets updates install by themselves (the default). */
  install: boolean;
  /** This copy can install updates by itself (macOS, run from a folder the user can write). */
  selfInstall: boolean;
  /** The version being downloaded and checked. */
  preparing?: string;
  /** A checked version waiting beside the app; it installs once the computer is left alone. */
  ready?: string;
  /** This run is the first of a new version: the one it replaced. */
  updatedFrom?: string;
  /** Why the last automatic install didn't happen, in words. */
  installError?: string;
}

/**
 * Whether an available update needs the user: not when this copy will
 * download and install it by itself, unless that already failed.
 */
export function updateNeedsUser(u: UpdateView): boolean {
  if (!u.available) return false;
  return !(u.selfInstall && u.install && u.available.selfUpdate && !u.installError);
}
