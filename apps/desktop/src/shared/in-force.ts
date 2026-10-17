/** What one thing Vigil enforces is, as the In force page groups it. */
export type InForceKind =
  | 'program' // a Santa rule (fapolicyd's on Linux) Vigil set
  | 'block-list' // an entry on the user's own block list
  | 'network' // a firewall block
  | 'quarantine' // a file moved to quarantine
  | 'paused' // a paused process
  | 'startup' // a startup item turned off
  | 'prelaunch'; // Santa stops a program before launch for a blocking rule

/** Why the startup check calls an item out. */
export type InForceFlag =
  | 'apple-program' // blocks a program that is part of the system
  | 'test-leftover' // aims at a path only Vigil's own tests use
  | 'long-running'; // in force longer than LONG_IN_FORCE_DAYS, and the user didn't ask for it

/** Days after which something Vigil did on its own counts as forgotten. */
export const LONG_IN_FORCE_DAYS = 7;

export interface InForceItem {
  /** Stable while it stays in force; what release() takes. */
  key: string;
  kind: InForceKind;
  /** What it does, in plain words: "Blocks /bin/sh". */
  title: string;
  /** The exact target when the title can't hold it: a hash, an address and port. */
  detail?: string;
  /** When it began, when known. */
  since?: number;
  /** When it stops on its own: a block-list entry the app dropped keeps blocking until then. */
  until?: number;
  /** What caused it, when the app knows. */
  cause?: {
    alertId?: string;
    alertTitle?: string;
    ruleId?: string;
    ruleName?: string;
    /** The user asked for it (a click, or confirming a threat). */
    byYou?: boolean;
  };
  /** `release` asks for the admin password; `rule` is undone by changing the rule. */
  release: 'release' | 'rule';
  flags: InForceFlag[];
}

export interface InForceCheck {
  /** One sentence for Home. */
  message: string;
  /** The flagged items, worst first. */
  keys: string[];
}

export interface InForceView {
  /** `unavailable`: the helper isn't connected, so the list is the app's own record and may be stale. */
  helper: 'connected' | 'unavailable';
  items: InForceItem[];
  check: InForceCheck | null;
}

export interface InForceReleaseResult {
  ok: boolean;
  error?: string;
}
