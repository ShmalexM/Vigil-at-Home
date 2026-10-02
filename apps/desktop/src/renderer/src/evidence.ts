import type { AgentToolRequestEvent, SensorEvent } from '@vigil/core';
import type { ExcludeScope } from '../../shared/ipc';

// How an event reads as evidence, shared by the Activity and Alerts pages. No
// React here, so it can be tested on its own.

/**
 * PREFLIGHT_SOCKET_TOOL in @vigil/detection (not imported, to keep it out of
 * the renderer): the stand-in request on the alert Vigil raises when another
 * program takes its agent socket.
 */
const SOCKET_TOOL = '#socket';

/** A request Claude Code's hook sent. Vigil's own stand-ins use tool names no hook can send. */
export function isHookRequest(e: SensorEvent): boolean {
  return e.kind === 'agent.tool_request' && !e.tool.startsWith('#');
}

/** The program an event is about, when one really ran. A tool request's is only the shell it would start. */
export function realProcess(e: SensorEvent) {
  return 'process' in e && e.kind !== 'agent.tool_request' ? e.process : undefined;
}

/** One line of a tool request's details: code, plain words, or the agent that asked. */
export type FieldRow =
  | { label: string; code: string }
  | { label: string; text: string }
  | { label: string; agent: { id: string; session?: string } };

/** What a tool request asked for, and which agent asked, in the order both pages show it. */
export function toolRequestRows(e: AgentToolRequestEvent): FieldRow[] {
  if (!isHookRequest(e)) {
    return e.filePath
      ? [{ label: e.tool === SOCKET_TOOL ? 'Socket' : 'Path', code: e.filePath }]
      : [];
  }
  const rows: FieldRow[] = [{ label: 'Tool', code: e.tool }];
  if (e.mcpServer) rows.push({ label: 'MCP server', code: e.mcpServer });
  if (e.command) rows.push({ label: 'Command', code: e.command });
  if (e.commandClipped) {
    rows.push({
      label: 'Command size',
      text: `${e.commandBytes ?? 'over 4,096'} bytes; Vigil checked the first 4,096 characters`,
    });
  }
  if (e.filePath) rows.push({ label: 'File', code: e.filePath });
  if (e.filePathGiven) rows.push({ label: 'Path as given', code: e.filePathGiven });
  if (e.url) rows.push({ label: 'Address', code: e.url });
  if (e.cwd) rows.push({ label: 'In folder', code: e.cwd });
  if (e.contentBytes !== undefined) {
    rows.push({
      label: 'Content',
      text: `${e.contentBytes} bytes${e.contentSha256 ? `, SHA-256 ${e.contentSha256.slice(0, 16)}…` : ''}. The text itself never reaches Vigil.`,
    });
  }
  rows.push(
    e.agent.id
      ? {
          label: 'Agent',
          agent: { id: e.agent.id, ...(e.agent.session ? { session: e.agent.session } : {}) },
        }
      : { label: 'Agent', text: 'Claude Code (Vigil didn’t see which session started it)' },
  );
  return rows;
}

/**
 * How an alert's answer to a hook request reads. Vigil raises alerts on tool
 * requests only for the ones it denied (and for repeated denies), never for an
 * ask, so every one was stopped.
 */
export const STOPPED_ANSWER = 'Stopped before it ran';

/** The Evidence section's subtitle: where its events came from. */
export function evidenceSub(events: readonly SensorEvent[]): string {
  const n = events.length;
  if (n > 0 && events.every(isHookRequest)) {
    return `${n} request${n === 1 ? '' : 's'} from Claude Code’s hook`;
  }
  return `${n} event${n === 1 ? '' : 's'} from the sensors`;
}

/**
 * The "stop alerting on this" scopes an event has enough detail for,
 * narrowest first. None for a tool request: its shell never ran, so "this
 * program" would mean every Bash step. Exclude on its command, file or
 * address from the rule editor instead.
 */
export function excludeScopes(e: SensorEvent): { scope: ExcludeScope; label: string }[] {
  if (e.kind === 'agent.tool_request') return [];
  const out: { scope: ExcludeScope; label: string }[] = [];
  const p = realProcess(e);
  if (p) out.push({ scope: 'this_binary', label: 'This program' });
  if (p?.teamId && p.signingId)
    out.push({ scope: 'this_signer', label: 'Anything from this signer' });
  if (e.kind === 'network.connection') out.push({ scope: 'this_host', label: 'This site' });
  if (!p && 'path' in e && e.path) out.push({ scope: 'this_path', label: 'This file' });
  return out;
}
