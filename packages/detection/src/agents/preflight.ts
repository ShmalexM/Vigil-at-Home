import {
  compareSeverity,
  type AgentTag,
  type AgentToolRequestEvent,
  type PreflightReply,
  type PreflightRequest,
} from '@vigil/core';
import { posix } from 'node:path';
import type { Detection } from '../types.js';

/**
 * Pre-flight: an agent's hook asks before a tool runs, and Vigil answers
 * from its rules. Rules decide; nothing here is AI. The answer is deny, ask
 * or none, never allow: in Claude Code, allow would skip the user's own
 * permission prompt.
 */

const MAX_REASON = 300;
const MAX_RULE_IDS = 8;
const MAX_RULE_ID = 100;

const FIRMLINK = /^\/system\/volumes\/data(?=\/|$)/i;
const PRIVATE_LINK = /^\/private\/(var|tmp|etc)(?=\/|$)/i;

/**
 * A path in the form rules write it. macOS reaches /Users and /Applications
 * through the /System/Volumes/Data firmlink as well, and /var, /tmp and /etc
 * are links into /private, so `/private/var/db/santa` is `/var/db/santa`.
 * APFS looks names up without regard to case, so the prefixes are matched
 * that way. Text only: no file is touched, so the hook resolves symlinks.
 */
export function canonicalPath(path: string): string {
  if (!path.startsWith('/')) return path;
  let out = posix.normalize(path);
  for (;;) {
    const next =
      out
        .replace(FIRMLINK, '')
        .replace(PRIVATE_LINK, (_, dir: string) => `/${dir.toLowerCase()}`) || '/';
    if (next === out) return out;
    out = next;
  }
}

/**
 * The event rules see for a tool request. `tag` is the agent the hook's
 * parent process runs under, when the tracker knows it (attribution only).
 * A Bash request carries the shell it would start, with pid 0: there is no
 * real process yet, so nothing can act on it.
 */
export function toolRequestEvent(
  req: PreflightRequest,
  ctx: { id: string; ts: number; tag?: AgentTag },
): AgentToolRequestEvent {
  const agent: AgentToolRequestEvent['agent'] = { host: req.host };
  if (ctx.tag) {
    agent.id = ctx.tag.id;
    agent.session = ctx.tag.session;
  }
  if (req.hookSession !== undefined) agent.hookSession = req.hookSession;
  const e: AgentToolRequestEvent = {
    id: ctx.id,
    ts: ctx.ts,
    source: 'vigil',
    kind: 'agent.tool_request',
    tool: req.tool,
    agent,
  };
  if (req.command !== undefined) e.command = req.command;
  if (req.commandBytes !== undefined) e.commandBytes = req.commandBytes;
  // The hook keeps the first 4,096 characters but counts the whole command in UTF-8
  // bytes, so compare like with like: more bytes than were sent means it was cut.
  if (
    req.command !== undefined &&
    req.commandBytes !== undefined &&
    req.commandBytes > Buffer.byteLength(req.command)
  )
    e.commandClipped = true;
  // Rules match the canonical path only, so a link like /private/var or the
  // firmlink can't step around them; what the hook sent is kept for the record.
  if (req.filePath !== undefined) {
    e.filePath = canonicalPath(req.filePath);
    if (e.filePath !== req.filePath) e.filePathGiven = req.filePath;
  }
  if (req.url !== undefined) e.url = req.url;
  if (req.cwd !== undefined) e.cwd = canonicalPath(req.cwd);
  if (req.contentBytes !== undefined) e.contentBytes = req.contentBytes;
  if (req.contentSha256 !== undefined) e.contentSha256 = req.contentSha256;
  if (req.tool.startsWith('mcp__')) {
    // mcp__<server>__<tool>
    const server = req.tool.split('__')[1];
    if (server) e.mcpServer = server;
  }
  if (req.tool === 'Bash' && req.command !== undefined) {
    e.process = { pid: 0, path: '/bin/zsh', args: ['zsh', '-c', req.command] };
  }
  return e;
}

function clip(s: string, max: number): string {
  return s.length > max ? `${s.slice(0, max - 1)}…` : s;
}

/**
 * The hook's answer from `engine.check` detections: any rule in block mode
 * denies, else any in alert mode asks, else Vigil has no opinion. Shadow
 * matches are only recorded. The reason names the most severe deciding rule.
 */
export function decide(ds: Detection[], nameOf: (ruleId: string) => string): PreflightReply {
  const blocks = ds.filter((d) => d.mode === 'block');
  const deciding = blocks.length > 0 ? blocks : ds.filter((d) => d.mode === 'alert');
  const first = [...deciding].sort((a, b) =>
    compareSeverity(b.alert?.severity ?? 'info', a.alert?.severity ?? 'info'),
  )[0];
  if (!first) return { v: 1, decision: 'none' };
  const ids = [first, ...deciding].map((d) => d.match.ruleId);
  return {
    v: 1,
    decision: blocks.length > 0 ? 'deny' : 'ask',
    reason: clip(
      `Vigil rule "${nameOf(first.match.ruleId)}": ${first.reasons.join(' ')}`,
      MAX_REASON,
    ),
    ruleIds: [...new Set(ids)].filter((id) => id.length <= MAX_RULE_ID).slice(0, MAX_RULE_IDS),
  };
}
