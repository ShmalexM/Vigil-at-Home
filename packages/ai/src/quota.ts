import type { ProviderId, UsageWindow } from './types.js';

/** How long to assume a rejected window stays closed when the vendor gives no reset time. */
const DEFAULT_BLOCK_MS = 15 * 60_000;
/** Background work stops before the window is this full, whatever Vigil's share. */
const BACKGROUND_CEILING_PERCENT = 90;

const key = (provider: ProviderId, windowId: string) => `${provider}\u0000${windowId}`;

/**
 * Tracks subscription usage windows from the vendors' own signals and how much
 * of each window Vigil itself used, so background work never eats more than its
 * share and the user's own chats keep working.
 */
export class QuotaTracker {
  private readonly latest = new Map<string, UsageWindow>();
  private readonly blockedUntil = new Map<ProviderId, number>();
  /** Keyed by window and reset time, so a new window starts at zero. */
  private readonly vigilUsed = new Map<string, number>();

  constructor(
    private readonly sharePercent: number,
    private readonly now: () => number = Date.now,
  ) {}

  observe(window: UsageWindow): void {
    if (window.rejected) {
      this.blockedUntil.set(window.provider, window.resetsAt ?? this.now() + DEFAULT_BLOCK_MS);
      return;
    }
    this.latest.set(key(window.provider, window.windowId), window);
  }

  /** Current usage per window for one provider, to compare before and after a run. */
  snapshot(provider: ProviderId): Map<string, UsageWindow> {
    const out = new Map<string, UsageWindow>();
    for (const w of this.latest.values()) if (w.provider === provider) out.set(w.windowId, w);
    return out;
  }

  /** Count the growth of each window during a Vigil run as Vigil's own use. */
  attribute(provider: ProviderId, before: Map<string, UsageWindow>): void {
    for (const after of this.snapshot(provider).values()) {
      const prior = before.get(after.windowId);
      const sameWindow = prior && prior.resetsAt === after.resetsAt;
      const delta = sameWindow ? Math.max(0, after.usedPercent - prior.usedPercent) : 0;
      const k = `${key(provider, after.windowId)}\u0000${after.resetsAt ?? ''}`;
      this.vigilUsed.set(k, (this.vigilUsed.get(k) ?? 0) + delta);
    }
  }

  vigilShare(provider: ProviderId, windowId: string): number {
    const w = this.latest.get(key(provider, windowId));
    return this.vigilUsed.get(`${key(provider, windowId)}\u0000${w?.resetsAt ?? ''}`) ?? 0;
  }

  private blocked(provider: ProviderId): boolean {
    const until = this.blockedUntil.get(provider);
    if (until === undefined) return false;
    if (until > this.now()) return true;
    this.blockedUntil.delete(provider);
    return false;
  }

  allowNow(provider: ProviderId): boolean {
    return !this.blocked(provider);
  }

  allowBackground(provider: ProviderId): boolean {
    if (this.blocked(provider)) return false;
    for (const w of this.snapshot(provider).values()) {
      if (w.resetsAt !== undefined && w.resetsAt <= this.now()) continue;
      if (w.usedPercent >= BACKGROUND_CEILING_PERCENT) return false;
      if (this.vigilShare(provider, w.windowId) >= this.sharePercent) return false;
    }
    return true;
  }
}
