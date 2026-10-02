import { z } from 'zod';

/** Opaque identifier. Generated with {@link newId}; sortable by creation time. */
export const Id = z.string().min(1).max(128);
export type Id = z.infer<typeof Id>;

/** Milliseconds since the Unix epoch (UTC). Stored as INTEGER in SQLite. */
export const Timestamp = z.number().int().nonnegative();
export type Timestamp = z.infer<typeof Timestamp>;

export const Severity = z.enum(['info', 'low', 'medium', 'high', 'critical']);
export type Severity = z.infer<typeof Severity>;

const severityRank: Record<Severity, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

/** Negative when `a` is less severe than `b`. */
export function compareSeverity(a: Severity, b: Severity): number {
  return severityRank[a] - severityRank[b];
}

/** How a binary is signed, as reported by Santa or osquery's `signature` table. */
export const SigningStatus = z.enum([
  'apple', // platform binary
  'app_store',
  'developer_id',
  'adhoc',
  'unsigned',
  'invalid',
  'unknown',
]);
export type SigningStatus = z.infer<typeof SigningStatus>;

/** A process as seen by a sensor. `pid` + `startTime` identifies it; pids are reused. */
export const ProcessRef = z.object({
  pid: z.number().int().nonnegative(),
  startTime: Timestamp.optional(),
  ppid: z.number().int().nonnegative().optional(),
  path: z.string(),
  args: z.array(z.string()).optional(),
  cwd: z.string().optional(),
  uid: z.number().int().optional(),
  user: z.string().optional(),
  sha256: z.string().optional(),
  cdhash: z.string().optional(),
  signingId: z.string().optional(),
  teamId: z.string().optional(),
  signing: SigningStatus.optional(),
  parentPath: z.string().optional(),
  /** Gatekeeper quarantine attribute on the executable, when it was downloaded. */
  quarantine: z
    .object({
      originUrl: z.string().optional(),
      /** The app that downloaded it, e.g. Safari. */
      agent: z.string().optional(),
    })
    .optional(),
  /** Program names of the parent, grandparent and so on, nearest first. Filled by Vigil, not sensors. */
  ancestors: z.array(z.string().max(255)).max(4).optional(),
  /**
   * The nearest ancestor that was downloaded from the internet (had the
   * quarantine flag), so a script started by a downloaded app still counts
   * as coming from that download. Filled by Vigil, not sensors.
   */
  downloadedAncestor: z.object({ path: z.string(), originUrl: z.string().optional() }).optional(),
});
export type ProcessRef = z.infer<typeof ProcessRef>;

let lastMs = 0;
let seq = 0;

/**
 * Time-ordered unique id: 12 hex chars of milliseconds, 4 of sequence, 16 random.
 * Lexicographic order matches creation order within one process.
 */
export function newId(now: number = Date.now()): Id {
  if (now === lastMs) {
    seq = (seq + 1) & 0xffff;
  } else {
    lastMs = now;
    seq = 0;
  }
  const random = crypto.getRandomValues(new Uint8Array(8));
  const hex = Array.from(random, (b) => b.toString(16).padStart(2, '0')).join('');
  return now.toString(16).padStart(12, '0') + seq.toString(16).padStart(4, '0') + hex;
}
