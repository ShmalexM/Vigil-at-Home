// The subset of Santa's sync protocol (santa.sync.v1) that Vigil uses.
// Source of truth: github.com/northpolesec/protos, sync/v1.proto.
//
// Santa sends requests as protobuf JSON (MessageToJsonString with default
// options), so field names arrive as lowerCamelCase, or as the explicit
// json_name where the proto sets one (e.g. "serial_num", "machine_id").
// Santa parses responses with JsonStringToMessage, which accepts both the
// original snake_case proto names and the JSON names, and ignores unknown
// fields. Vigil therefore reads requests accepting either spelling and writes
// responses with snake_case proto names.

export type ClientMode = 'MONITOR' | 'LOCKDOWN' | 'STANDALONE';

export type SyncType = 'NORMAL' | 'CLEAN' | 'CLEAN_ALL' | 'CLEAN_RULES';

export type RuleType = 'BINARY' | 'CERTIFICATE' | 'TEAMID' | 'SIGNINGID' | 'CDHASH';

export type RulePolicy =
  | 'ALLOWLIST'
  | 'BLOCKLIST'
  | 'SILENT_BLOCKLIST'
  | 'SILENT_GUI_BLOCKLIST'
  | 'SILENT_TTY_BLOCKLIST'
  /** Santa decides by running the rule's cel_expr (Santa 2025.8 and later). */
  | 'CEL'
  | 'REMOVE';

export const RULE_TYPES: readonly RuleType[] = [
  'BINARY',
  'CERTIFICATE',
  'TEAMID',
  'SIGNINGID',
  'CDHASH',
];

export interface SantaRule {
  identifier: string;
  policy: RulePolicy;
  rule_type: RuleType;
  custom_msg?: string;
  custom_url?: string;
  /** For policy CEL: the expression Santa evaluates at each launch. */
  cel_expr?: string;
  event_detail_button_label?: string;
}

export interface PreflightResponse {
  client_mode: ClientMode;
  sync_type?: SyncType;
  batch_size?: number;
  enable_bundles?: boolean;
  enable_transitive_rules?: boolean;
  enable_all_event_upload?: boolean;
  disable_unknown_event_upload?: boolean;
  full_sync_interval?: number;
  event_detail_url?: string;
  event_detail_text?: string;
}

export interface RuleDownloadResponse {
  rules: SantaRule[];
  cursor?: string;
}

/** A blocked (or would-be-blocked) execution Santa uploaded. */
export interface SantaUploadedEvent {
  file_sha256?: string | undefined;
  file_path?: string | undefined;
  file_name?: string | undefined;
  executing_user?: string | undefined;
  execution_time?: number | undefined;
  decision?: string | undefined;
  file_bundle_id?: string | undefined;
  file_bundle_path?: string | undefined;
  pid?: number | undefined;
  ppid?: number | undefined;
  parent_name?: string | undefined;
  team_id?: string | undefined;
  signing_id?: string | undefined;
  cdhash?: string | undefined;
  signing_chain?:
    | {
        sha256?: string | undefined;
        cn?: string | undefined;
        org?: string | undefined;
        ou?: string | undefined;
      }[]
    | undefined;
}

export interface SantaUploadedFileAccessEvent {
  rule_version?: string | undefined;
  rule_name?: string | undefined;
  target?: string | undefined;
  access_time?: number | undefined;
  decision?: string | undefined;
  process_chain?:
    | {
        file_path?: string | undefined;
        cdhash?: string | undefined;
        file_sha256?: string | undefined;
        signing_id?: string | undefined;
        team_id?: string | undefined;
        pid?: number | undefined;
      }[]
    | undefined;
}

/** Read a field that may arrive as snake_case, camelCase or an explicit json_name. */
export function pick<T = unknown>(obj: unknown, ...names: string[]): T | undefined {
  if (!obj || typeof obj !== 'object') return undefined;
  const rec = obj as Record<string, unknown>;
  for (const n of names) {
    if (rec[n] !== undefined) return rec[n] as T;
    const camel = n.replace(/_([a-z0-9])/g, (_m, c: string) => c.toUpperCase());
    if (rec[camel] !== undefined) return rec[camel] as T;
  }
  return undefined;
}

/** Normalize one uploaded execution event to snake_case fields. */
export function normalizeUploadedEvent(e: unknown): SantaUploadedEvent {
  const chain = pick<unknown[]>(e, 'signing_chain');
  return {
    file_sha256: pick(e, 'file_sha256'),
    file_path: pick(e, 'file_path'),
    file_name: pick(e, 'file_name'),
    executing_user: pick(e, 'executing_user'),
    execution_time: toNum(pick(e, 'execution_time')),
    decision: pick(e, 'decision'),
    file_bundle_id: pick(e, 'file_bundle_id'),
    file_bundle_path: pick(e, 'file_bundle_path'),
    pid: toNum(pick(e, 'pid')),
    ppid: toNum(pick(e, 'ppid')),
    parent_name: pick(e, 'parent_name'),
    team_id: pick(e, 'team_id'),
    signing_id: pick(e, 'signing_id'),
    cdhash: pick(e, 'cdhash'),
    signing_chain: Array.isArray(chain)
      ? chain.map((c) => ({
          sha256: pick(c, 'sha256'),
          cn: pick(c, 'cn'),
          org: pick(c, 'org'),
          ou: pick(c, 'ou'),
        }))
      : undefined,
  };
}

export function normalizeUploadedFileAccessEvent(e: unknown): SantaUploadedFileAccessEvent {
  const chain = pick<unknown[]>(e, 'process_chain');
  return {
    rule_version: pick(e, 'rule_version'),
    rule_name: pick(e, 'rule_name'),
    target: pick(e, 'target'),
    access_time: toNum(pick(e, 'access_time')),
    decision: pick(e, 'decision'),
    process_chain: Array.isArray(chain)
      ? chain.map((p) => ({
          file_path: pick(p, 'file_path'),
          cdhash: pick(p, 'cdhash'),
          file_sha256: pick(p, 'file_sha256'),
          signing_id: pick(p, 'signing_id'),
          team_id: pick(p, 'team_id'),
          pid: toNum(pick(p, 'pid')),
        }))
      : undefined,
  };
}

function toNum(v: unknown): number | undefined {
  if (typeof v === 'number') return v;
  if (typeof v === 'string' && v !== '' && Number.isFinite(Number(v))) return Number(v);
  return undefined;
}

// Identifier formats Santa expects for each rule type.
const IDENTIFIER_RE: Record<RuleType, RegExp> = {
  BINARY: /^[a-f0-9]{64}$/,
  CERTIFICATE: /^[a-f0-9]{64}$/,
  CDHASH: /^[a-f0-9]{40}$/,
  TEAMID: /^[A-Z0-9]{10}$/,
  // TeamID:SigningID, or platform:SigningID for Apple platform binaries.
  SIGNINGID: /^(?:[A-Z0-9]{10}|platform):[A-Za-z0-9._-]{1,255}$/,
};

export function isValidRuleIdentifier(ruleType: RuleType, identifier: string): boolean {
  return IDENTIFIER_RE[ruleType].test(identifier);
}
