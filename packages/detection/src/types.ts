/**
 * Local copies of the event and detection shapes.
 *
 * The App shell thread owns the shared types package. Until it lands, these
 * mirror the shapes proposed to it; once it exists, this file re-exports
 * from there and the rest of the package does not change.
 */

export const EVENT_KINDS = [
  "process_exec",
  "file_open",
  "file_write",
  "file_rename",
  "network_connect",
  "listening_port",
  "persistence_added",
  "browser_extension_added",
  "santa_block",
] as const;
export type EventKind = (typeof EVENT_KINDS)[number];

export type SigningStatus =
  | "apple" // Apple platform binary
  | "app_store"
  | "developer_id"
  | "adhoc"
  | "unsigned"
  | "invalid";

export interface ProcessInfo {
  pid: number;
  ppid?: number;
  path: string;
  args?: string[];
  sha256?: string;
  cdhash?: string;
  user?: string;
  parentPath?: string;
  signing?: {
    status: SigningStatus;
    teamId?: string;
    signingId?: string;
    notarized?: boolean;
  };
  /** Present when the executable carries the com.apple.quarantine xattr. */
  quarantine?: {
    originUrl?: string;
    agent?: string;
  };
}

export interface FileInfo {
  path: string;
  /** Destination of a rename. */
  targetPath?: string;
}

export interface NetworkInfo {
  remoteAddress?: string;
  remotePort?: number;
  localAddress?: string;
  localPort?: number;
  protocol?: "tcp" | "udp";
  domain?: string;
}

export interface PersistenceInfo {
  type: "launch_agent" | "launch_daemon" | "login_item" | "cron" | "other";
  itemPath: string;
  label?: string;
  programPath?: string;
  programArgs?: string[];
}

export interface ExtensionInfo {
  browser: string;
  id: string;
  name?: string;
  permissions?: string[];
}

export interface SantaBlockInfo {
  reason?: string;
  ruleType?: string;
}

export interface SensorEvent {
  id: string;
  /** Milliseconds since the Unix epoch. */
  ts: number;
  kind: EventKind;
  source: "osquery" | "santa" | "vigil";
  process?: ProcessInfo;
  file?: FileInfo;
  network?: NetworkInfo;
  persistence?: PersistenceInfo;
  extension?: ExtensionInfo;
  santa?: SantaBlockInfo;
}

export const SEVERITIES = ["info", "low", "medium", "high", "critical"] as const;
export type Severity = (typeof SEVERITIES)[number];

/**
 * What a detection asks the app to do, weakest to strongest.
 * record: store only. alert: popup or notification, nothing touched.
 * suspend: pause the process tree and pop up. block: kill the process,
 * firewall its remote address when there is one, and pop up.
 */
export const ACTIONS = ["record", "alert", "suspend", "block"] as const;
export type Action = (typeof ACTIONS)[number];

/**
 * How far a rule is trusted. Only the user moves a rule up; the engine may
 * move it down when the user keeps dismissing it.
 * shadow: records what it would have done. alert: may pop up, never touches
 * a process. enforce: may suspend or block.
 */
export const STAGES = ["shadow", "alert", "enforce"] as const;
export type Stage = (typeof STAGES)[number];

export type SantaRuleType = "BINARY" | "CERTIFICATE" | "TEAMID" | "SIGNINGID" | "CDHASH";

export interface SantaSuggestion {
  policy: "BLOCKLIST";
  ruleType: SantaRuleType;
  identifier: string;
  customMsg: string;
}

/**
 * What a suspend or block acts on.
 * process: pause or kill the process tree.
 * network: firewall the remote address or domain; the process is left alone
 *   (a browser that loaded a bad page should not be killed).
 * persistence: disable the launch item.
 */
export const TARGETS = ["process", "network", "persistence"] as const;
export type ResponseTarget = (typeof TARGETS)[number];

/** The concrete things a response would touch, copied from the event. */
export interface ResponseSubject {
  pid?: number;
  processPath?: string;
  sha256?: string;
  remoteAddress?: string;
  domain?: string;
  itemPath?: string;
  label?: string;
}

export interface Detection {
  id: string;
  ts: number;
  ruleId: string;
  ruleVersion: number;
  title: string;
  severity: Severity;
  /** What the rule asks for. */
  requestedAction: Action;
  /** What the app should do after stage, learning, dedupe and the safety floor. */
  action: Action;
  stage: Stage;
  target: ResponseTarget;
  subject: ResponseSubject;
  /** Plain-language reasons, rendered locally, shown in the popup before any AI runs. */
  reasons: string[];
  /** Why `action` is weaker than `requestedAction`, if it is. */
  downgrades: string[];
  eventIds: string[];
  dedupeKey: string;
  /** True when the same rule already fired for this key inside its dedupe window. */
  deduped: boolean;
  /** The Santa rule to install if the user confirms this as malicious. */
  santaSuggestion?: SantaSuggestion;
  tags: string[];
}

export const ACTION_RANK: Record<Action, number> = { record: 0, alert: 1, suspend: 2, block: 3 };

export function minAction(a: Action, b: Action): Action {
  return ACTION_RANK[a] <= ACTION_RANK[b] ? a : b;
}
