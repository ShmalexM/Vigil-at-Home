import type { Condition } from '../types.js';

/**
 * Fields that describe an AI agent or its tool request rather than a program.
 * They say who asked, not what ran, so an AI tuning a rule may not exclude by
 * them, and an exception keyed only on them would silence a whole agent.
 */
export const AGENT_FIELD_PREFIXES: readonly string[] = [
  'process.agent',
  'process.ancestors',
  'agent',
  'tool',
  'command',
  'commandBytes',
  'filePath',
  'url',
  'mcpServer',
  'cwd',
  'toolOutsideCwd',
  'contentBytes',
  'contentSha256',
];

/** True for an agent field or anything under one (`agent.id`, `process.agent.session`). */
export function isAgentField(f: string): boolean {
  return AGENT_FIELD_PREFIXES.some((p) => f === p || f.startsWith(`${p}.`));
}

/** True when any part of the condition reads an agent field: a test, a list lookup or a firstSeen key. */
export function conditionUsesAgentFields(c: Condition): boolean {
  if ('all' in c) return c.all.some(conditionUsesAgentFields);
  if ('any' in c) return c.any.some(conditionUsesAgentFields);
  if ('not' in c) return conditionUsesAgentFields(c.not);
  if ('inList' in c) return isAgentField(c.inList.field);
  if ('firstSeen' in c) return c.firstSeen.key.some(isAgentField);
  return isAgentField(c.field);
}
