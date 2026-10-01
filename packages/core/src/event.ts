import { z } from 'zod';
import { AgentId, Id, ProcessRef, Timestamp } from './common.js';

/** Where an event came from. */
export const EventSource = z.enum(['osquery', 'santa', 'vigil', 'test']);
export type EventSource = z.infer<typeof EventSource>;

const base = {
  id: Id,
  /** When the activity happened on the machine (not when Vigil received it). */
  ts: Timestamp,
  source: EventSource,
  /** The sensor's original record, kept for investigation. Never interpreted by rules. */
  raw: z.unknown().optional(),
};

export const ProcessExecEvent = z.object({
  ...base,
  kind: z.literal('process.exec'),
  process: ProcessRef,
});

export const ProcessExitEvent = z.object({
  ...base,
  kind: z.literal('process.exit'),
  process: ProcessRef,
  exitCode: z.number().int().optional(),
});

export const FileOp = z.enum(['create', 'write', 'rename', 'delete', 'open']);
export type FileOp = z.infer<typeof FileOp>;

export const FileEvent = z.object({
  ...base,
  kind: z.literal('file'),
  op: FileOp,
  path: z.string(),
  /** Destination for renames. */
  newPath: z.string().optional(),
  sha256: z.string().optional(),
  process: ProcessRef.optional(),
});

export const NetworkConnectionEvent = z.object({
  ...base,
  kind: z.literal('network.connection'),
  direction: z.enum(['outbound', 'inbound']),
  protocol: z.enum(['tcp', 'udp', 'other']),
  localAddress: z.string().optional(),
  localPort: z.number().int().optional(),
  remoteAddress: z.string(),
  remotePort: z.number().int().optional(),
  /** Resolved name when the sensor knows it. */
  remoteHost: z.string().optional(),
  process: ProcessRef.optional(),
});

/** A launch agent, launch daemon, login item or similar was added or changed. */
export const PersistenceEvent = z.object({
  ...base,
  kind: z.literal('persistence'),
  change: z.enum(['added', 'modified', 'removed']),
  mechanism: z.enum([
    'launch_agent',
    'launch_daemon',
    'login_item',
    'cron',
    'shell_profile',
    'other',
  ]),
  path: z.string(),
  /** launchd label, when the item has one. */
  label: z.string().optional(),
  /** Program the item runs, when known. */
  program: z.string().optional(),
  programArgs: z.array(z.string()).optional(),
  process: ProcessRef.optional(),
});

/** Santa allowed or blocked a launch, or a protected-file access. */
export const SantaDecisionEvent = z.object({
  ...base,
  kind: z.literal('santa.decision'),
  target: z.enum(['execution', 'file_access']),
  decision: z.enum(['allow', 'block', 'audit_only']),
  /** Santa's own reason, e.g. BLOCK_BINARY, ALLOW_CERTIFICATE, BLOCK_UNKNOWN. */
  reason: z.string(),
  /** For file_access: the protected path that was touched. */
  path: z.string().optional(),
  process: ProcessRef,
});

/** A process started listening on a port (a backdoor opening a door). */
export const NetworkListenEvent = z.object({
  ...base,
  kind: z.literal('network.listen'),
  protocol: z.enum(['tcp', 'udp', 'other']),
  localAddress: z.string().optional(),
  localPort: z.number().int(),
  process: ProcessRef.optional(),
});

/** A browser extension was installed, updated or removed. */
export const BrowserExtensionEvent = z.object({
  ...base,
  kind: z.literal('browser.extension'),
  change: z.enum(['added', 'modified', 'removed']),
  browser: z.string(),
  extensionId: z.string(),
  name: z.string().optional(),
  permissions: z.array(z.string()).optional(),
});

/** macOS's own security notices: XProtect hits, TCC permission changes, Gatekeeper overrides. */
export const SystemAlertEvent = z.object({
  ...base,
  kind: z.literal('system.alert'),
  subtype: z.enum(['xprotect_detected', 'tcc_modified', 'gatekeeper_override']),
  path: z.string().optional(),
  sha256: z.string().optional(),
  process: ProcessRef.optional(),
  /** Subtype-specific fields, e.g. malware name, TCC service and right. */
  details: z.record(z.string(), z.string()).default({}),
});

/**
 * An AI agent asked to run a tool (Claude Code's PreToolUse hook). Vigil checks
 * it against rules before the tool runs. Nothing has happened yet, so no real
 * process exists: write content arrives only as its size and hash.
 */
export const AgentToolRequestEvent = z.object({
  ...base,
  kind: z.literal('agent.tool_request'),
  /** The agent's tool name, e.g. Bash, Write, WebFetch or mcp__server__tool. */
  tool: z.string().max(128),
  command: z.string().max(4096).optional(),
  /** Size of the full command; it may be longer than the part in `command`. */
  commandBytes: z.number().int().nonnegative().optional(),
  /** Absolute; the hook has already resolved `..` against `cwd`. */
  filePath: z.string().max(1024).optional(),
  url: z.string().max(2048).optional(),
  /** For mcp__<server>__<tool> tools. */
  mcpServer: z.string().max(128).optional(),
  cwd: z.string().max(1024).optional(),
  contentBytes: z.number().int().nonnegative().optional(),
  contentSha256: z
    .string()
    .regex(/^[0-9a-f]{64}$/)
    .optional(),
  agent: z.object({
    host: z.enum(['claude-code']),
    id: AgentId.optional(),
    /** Vigil's session for the agent, when the tracker knows the hook's parent. */
    session: z.string().max(32).optional(),
    /** The host's own session id. */
    hookSession: z.string().max(128).optional(),
  }),
  /** Bash only: the would-be shell. Never a real process. */
  process: ProcessRef.extend({ pid: z.literal(0) }).optional(),
});
export type AgentToolRequestEvent = z.infer<typeof AgentToolRequestEvent>;

export const SensorEvent = z.discriminatedUnion('kind', [
  ProcessExecEvent,
  ProcessExitEvent,
  FileEvent,
  NetworkConnectionEvent,
  PersistenceEvent,
  SantaDecisionEvent,
  NetworkListenEvent,
  BrowserExtensionEvent,
  SystemAlertEvent,
  AgentToolRequestEvent,
]);
export type SensorEvent = z.infer<typeof SensorEvent>;
export type EventKind = SensorEvent['kind'];
export const EventKind = z.enum([
  'process.exec',
  'process.exit',
  'file',
  'network.connection',
  'persistence',
  'santa.decision',
  'network.listen',
  'browser.extension',
  'system.alert',
  'agent.tool_request',
]);

export type EventOfKind<K extends EventKind> = Extract<SensorEvent, { kind: K }>;
