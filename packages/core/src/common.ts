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

/** A watched AI agent's id, e.g. `claude-code`. Built-in ids and the user's own share this shape. */
export const AgentId = z.string().regex(/^[a-z0-9][a-z0-9-]{0,39}$/);
export type AgentId = z.infer<typeof AgentId>;

/**
 * Which watched agent a process runs under. Set by Vigil's process tracker
 * before rules run, never by a sensor. `depth` is 0 for the agent itself, 1
 * for what it starts directly, and so on.
 */
export const AgentTag = z.object({
  id: AgentId,
  /** One run of the agent: 16 hex chars derived from the root process. */
  session: z.string().regex(/^[0-9a-f]{16}$/),
  depth: z.number().int().min(0).max(64),
});
export type AgentTag = z.infer<typeof AgentTag>;

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
  /** Set when the process runs under a watched AI agent. */
  agent: AgentTag.optional(),
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
