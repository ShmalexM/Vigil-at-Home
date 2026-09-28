/**
 * Update notices, shared by main and the renderer. Vigil ships unsigned for now,
 * so it can't replace itself: it tells the user a newer release is out and
 * offers the DMG for their Mac.
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
  };
  /** The user chose Later for this version; the banner stays hidden until a newer one. */
  dismissed: boolean;
}
