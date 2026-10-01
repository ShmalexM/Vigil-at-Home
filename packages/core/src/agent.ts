import { z } from 'zod';
import { AgentId, Timestamp } from './common.js';

/**
 * Watched AI agents (Claude Code, Codex, Cursor and the like) and the
 * pre-flight bridge their hooks use to ask Vigil about a tool call.
 *
 * Vigil's answer to a hook is deny, ask or nothing. It never answers "allow":
 * in Claude Code, allow skips the user's own permission prompt.
 */

export const AgentKind = z.enum(['cli', 'app', 'ide', 'runtime']);
export type AgentKind = z.infer<typeof AgentKind>;

/**
 * One way to recognise an agent's program. Within a matcher every list given
 * must match; `argGlobs` only narrows a match, so at least one identity field
 * (team ID, signing ID, path or name) is required.
 */
export const AgentMatcher = z
  .strictObject({
    teamIds: z
      .array(z.string().regex(/^[A-Z0-9]{10}$/))
      .max(8)
      .optional(),
    signingIds: z.array(z.string().max(128)).max(8).optional(),
    /** Path globs; `~/` means any user's home folder. */
    paths: z.array(z.string().min(3).max(256)).max(8).optional(),
    /** Exact program names (basenames). */
    names: z.array(z.string().min(1).max(64)).max(8).optional(),
    /** Globs AND-ed against the joined arguments, e.g. `*@openai/codex*` for a node script. */
    argGlobs: z.array(z.string().min(3).max(256)).max(4).optional(),
  })
  .refine(
    (m) => !!(m.teamIds?.length || m.signingIds?.length || m.paths?.length || m.names?.length),
    'name a team ID, signing ID, path or program name',
  );
export type AgentMatcher = z.infer<typeof AgentMatcher>;

export const AgentIdentity = z.strictObject({
  id: AgentId,
  name: z.string().min(1).max(60),
  kind: AgentKind,
  /** builtin: Vigil's catalogue; user: added by the user; suggested: Vigil's heuristic. */
  origin: z.enum(['builtin', 'user', 'suggested']),
  /** Only active identities tag processes. A suggestion tags nothing until the user accepts it. */
  status: z.enum(['active', 'suggested', 'ignored']),
  /** Whether processes under this agent are tagged for agent-watch rules. */
  watch: z.boolean(),
  match: z.array(AgentMatcher).min(1).max(4),
  note: z.string().max(200).optional(),
  createdAt: Timestamp,
  updatedAt: Timestamp,
});
export type AgentIdentity = z.infer<typeof AgentIdentity>;

/** What the user may set when adding or editing an agent. Vigil sets the rest. */
export const AgentIdentityInput = AgentIdentity.pick({
  id: true,
  name: true,
  kind: true,
  match: true,
  watch: true,
  note: true,
});
export type AgentIdentityInput = z.infer<typeof AgentIdentityInput>;

// ---------------------------------------------------------------- pre-flight bridge

/** deny stops the tool, ask hands it to the user's own prompt, none leaves it to the agent. Never allow. */
export const PreflightDecision = z.enum(['deny', 'ask', 'none']);
export type PreflightDecision = z.infer<typeof PreflightDecision>;

/**
 * A hook asking about one tool call. Strict: anything else the host sends
 * (a transcript path, the content being written) is refused, not ignored.
 */
export const PreflightRequest = z.strictObject({
  v: z.literal(1),
  method: z.literal('preflight.check'),
  host: z.enum(['claude-code']),
  hookSession: z.string().max(128).optional(),
  /** The hook process's parent, i.e. the agent. Used for attribution only. */
  ppid: z.number().int().positive().optional(),
  cwd: z.string().max(1024).optional(),
  tool: z.string().regex(/^[A-Za-z][A-Za-z0-9_.-]{0,127}$/),
  command: z.string().max(4096).optional(),
  commandBytes: z.number().int().nonnegative().optional(),
  filePath: z.string().max(1024).optional(),
  url: z.string().max(2048).optional(),
  contentBytes: z.number().int().nonnegative().optional(),
  contentSha256: z
    .string()
    .regex(/^[0-9a-f]{64}$/)
    .optional(),
});
export type PreflightRequest = z.infer<typeof PreflightRequest>;

/** Sent by the hook when an agent session starts, so Vigil can show the hook is connected. */
export const HookHello = z.strictObject({
  v: z.literal(1),
  method: z.literal('hello'),
  host: z.enum(['claude-code']),
  hookVersion: z.string().max(32),
  hookSession: z.string().max(128).optional(),
});
export type HookHello = z.infer<typeof HookHello>;

/** Read-only Vigil tools offered to the user's own agents over MCP (opt-in). */
export const ToolsListRequest = z.strictObject({
  v: z.literal(1),
  method: z.literal('tools.list'),
});
export type ToolsListRequest = z.infer<typeof ToolsListRequest>;

export const ToolsCallRequest = z.strictObject({
  v: z.literal(1),
  method: z.literal('tools.call'),
  tool: z.string().regex(/^[a-z][a-z0-9_]{0,63}$/),
  args: z.record(z.string(), z.unknown()).default({}),
});
export type ToolsCallRequest = z.infer<typeof ToolsCallRequest>;

export const AgentBridgeRequest = z.discriminatedUnion('method', [
  PreflightRequest,
  HookHello,
  ToolsListRequest,
  ToolsCallRequest,
]);
export type AgentBridgeRequest = z.infer<typeof AgentBridgeRequest>;

export const PreflightReply = z.strictObject({
  v: z.literal(1),
  decision: PreflightDecision,
  reason: z.string().max(300).optional(),
  ruleIds: z.array(z.string().max(100)).max(8).optional(),
});
export type PreflightReply = z.infer<typeof PreflightReply>;

export const HelloReply = z.strictObject({ v: z.literal(1), ok: z.literal(true) });
export type HelloReply = z.infer<typeof HelloReply>;

/** The answer to tools.list or tools.call. It never carries a decision. */
export const ToolsReply = z.discriminatedUnion('ok', [
  z.strictObject({ v: z.literal(1), ok: z.literal(true), result: z.unknown() }),
  z.strictObject({ v: z.literal(1), ok: z.literal(false), error: z.string().max(300) }),
]);
export type ToolsReply = z.infer<typeof ToolsReply>;
