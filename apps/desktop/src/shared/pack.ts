// The pack: Vigil's own AI agents. The Lead dog is the one the user talks to;
// it can add dogs to the pack, change them, send them off on a job or retire
// them, within the permission mode the user picked. Each pack dog has a job
// (its standing instructions), a schedule and the tools the user lets it use.
//
// What no dog can do, in any mode: block or allow anything on the Mac,
// release a block, answer a watched agent's pre-flight check, or approve or
// edit a rule. Vigil's own tools are read-only; connectors are the user's own
// MCP servers, and every call to one goes through the tool gate (pack.ts in
// main).

import { z } from 'zod';

export const Breed = z.enum([
  'shepherd',
  'doberman',
  'husky',
  'golden',
  'beagle',
  'corgi',
  'dachshund',
  'chihuahua',
]);
export type Breed = z.infer<typeof Breed>;

/** What a dog looks like it's doing. Driven by real work, never decoration alone. */
export type DogMood =
  'idle' | 'thinking' | 'sniffing' | 'fetching' | 'waiting' | 'done' | 'error' | 'sleeping';

/**
 * How much the pack may do without asking, like a coding agent's permission
 * modes. "ask": every pack change and every tool that can change something
 * waits for the user. "auto": the user's AI judges each such tool call and
 * low-risk ones go ahead (never on a Claude plan for background work).
 * "full": dogs go ahead, except where a rule or the user's own tool setting
 * says ask.
 */
export const PermissionMode = z.enum(['ask', 'auto', 'full']);
export type PermissionMode = z.infer<typeof PermissionMode>;

/**
 * The user's choice for one tool. "auto" follows the permission mode; "ask"
 * always asks; "allow" never asks (rules still apply); "off" hides it from
 * every dog.
 */
export const ToolChoice = z.enum(['auto', 'ask', 'allow', 'off']);
export type ToolChoice = z.infer<typeof ToolChoice>;

export const Schedule = z.enum(['manual', 'hourly', 'daily', 'nightly']);
export type Schedule = z.infer<typeof Schedule>;

/** A tool's key: `vigil.<name>` for Vigil's own, `<connectorId>.<name>` for a connector's. */
export const ToolKey = z.string().regex(/^[a-z0-9-]{1,40}\.[A-Za-z0-9_.-]{1,64}$/);

export const DogName = z.string().trim().min(1).max(32);
export const DogJob = z.string().trim().min(1).max(2000);

export const DogInput = z.object({
  name: DogName,
  breed: Breed,
  job: DogJob,
  schedule: Schedule,
  tools: z.array(ToolKey).max(64),
});
export type DogInput = z.infer<typeof DogInput>;

export const DogPatch = DogInput.partial().extend({ enabled: z.boolean().optional() });
export type DogPatch = z.infer<typeof DogPatch>;

export interface DogReport {
  at: number;
  ok: boolean;
  summary: string;
  findings: {
    title: string;
    detail?: string | undefined;
    severity: 'info' | 'low' | 'medium' | 'high';
  }[];
  /** The AI that ran it. */
  provider?: string;
}

/** Vigil's built-in AI helpers, shown as pack dogs. Their jobs and tools are fixed. */
export type HelperId = 'explainer' | 'labeller' | 'rule-reviewer';

export interface Dog {
  id: string;
  /** lead: the one you talk to. helper: one of Vigil's built-in AI jobs. pack: made by you or the Lead dog. */
  role: 'lead' | 'helper' | 'pack';
  helper?: HelperId;
  name: string;
  breed: Breed;
  /** The Lead dog's job is fixed: talk with the user and manage the pack. */
  job: string;
  schedule: Schedule;
  tools: string[];
  enabled: boolean;
  createdBy: 'you' | 'lead';
  createdAt: number;
  lastReport?: DogReport;
}

/** What the Lead dog asked to do. Applied by Vigil, as the mode allows. */
export const LeadActionKind = z.enum(['create', 'update', 'run', 'retire']);
export type LeadActionKind = z.infer<typeof LeadActionKind>;

export interface LeadAction {
  id: string;
  kind: LeadActionKind;
  /** The dog it's about (update, run, retire, or the one created). */
  dogId?: string;
  /** For create and update. */
  dog?: Partial<DogInput>;
  status: 'pending' | 'done' | 'declined' | 'failed';
  /** Why it waits, or why it failed. */
  note?: string;
}

export interface ChatMessage {
  id: string;
  at: number;
  from: 'you' | 'lead';
  text: string;
  actions?: LeadAction[];
  /** Tools the Lead dog used while answering. */
  used?: string[];
  failed?: boolean;
}

/** A tool call waiting on the user. */
export interface ToolApproval {
  id: string;
  at: number;
  dogId: string;
  tool: string;
  toolTitle: string;
  /** The arguments, redacted and cut short, as the user sees them. */
  args: string;
  why: 'mode' | 'always-ask' | 'rule' | 'judged-risky' | 'no-judge';
  /** The rule's or the judge's reason, when there is one. */
  reason?: string;
}

export const ToolDecision = z.enum(['allow-once', 'deny']);
export type ToolDecision = z.infer<typeof ToolDecision>;

export interface ToolView {
  key: string;
  /** "vigil" or the connector's id. */
  source: string;
  sourceName: string;
  name: string;
  title: string;
  description: string;
  /** Only Vigil's own tools. A connector's tools never count as read-only. */
  readOnly: boolean;
  /** The connector's server says the tool only reads: shown, never trusted. */
  serverHint: boolean;
  choice: ToolChoice;
}

export const ConnectorInput = z.discriminatedUnion('kind', [
  z.object({
    kind: z.literal('stdio'),
    name: z.string().trim().min(1).max(40),
    command: z.string().trim().min(1).max(1024),
    args: z.array(z.string().max(1024)).max(32),
    /** Environment values (tokens) kept in the Keychain, never shown again. */
    env: z.record(z.string().regex(/^[A-Z_][A-Z0-9_]{0,63}$/), z.string().max(4096)).optional(),
  }),
  z.object({
    kind: z.literal('http'),
    name: z.string().trim().min(1).max(40),
    url: z.string().url().max(2048),
    /** A bearer token, kept in the Keychain. */
    token: z.string().max(4096).optional(),
  }),
]);
export type ConnectorInput = z.infer<typeof ConnectorInput>;

export interface ConnectorView {
  id: string;
  name: string;
  kind: 'stdio' | 'http';
  /** Command line or URL, for display. */
  target: string;
  /** Names of saved secrets (env names, or "token"); values never leave main. */
  secrets: string[];
  state: 'connected' | 'connecting' | 'error' | 'off';
  error?: string;
  tools: number;
  enabled: boolean;
}

export interface PackView {
  mode: PermissionMode;
  dogs: (Dog & { mood: DogMood; activity?: string })[];
  chat: ChatMessage[];
  approvals: ToolApproval[];
  /** Whether a Claude plan may answer the Lead dog (Settings › AI opt-in). */
  leadMayUsePlan: boolean;
  /** Which AI judges risk in "auto" mode, or why none can. */
  judge: { ready: boolean; detail: string };
  /** No AI is set up, so nobody can talk yet. */
  noAi: boolean;
  tools: ToolView[];
  connectors: ConnectorView[];
}
