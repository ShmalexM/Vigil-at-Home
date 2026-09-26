import { z } from 'zod';
import { Id, ProcessRef, Timestamp } from './common.js';

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
]);

export type EventOfKind<K extends EventKind> = Extract<SensorEvent, { kind: K }>;
