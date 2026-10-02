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
  'commandClipped',
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

/**
 * Fields an AI exclusion may not use. Parent fields name the program that
 * started a process, which under an agent is the agent itself, and
 * `process.parentName` falls back to `process.ancestors[0]`.
 */
export const AI_EXCLUSION_DENY: readonly string[] = [
  ...AGENT_FIELD_PREFIXES,
  'process.parentName',
  'process.parentPath',
];

function deniedForAi(f: string): boolean {
  return AI_EXCLUSION_DENY.some((p) => f === p || f.startsWith(`${p}.`));
}

/** True when any part of the condition reads a field `test` accepts: a test, a list lookup or a firstSeen key. */
export function conditionUsesFields(c: Condition, test: (field: string) => boolean): boolean {
  if ('all' in c) return c.all.some((x) => conditionUsesFields(x, test));
  if ('any' in c) return c.any.some((x) => conditionUsesFields(x, test));
  if ('not' in c) return conditionUsesFields(c.not, test);
  if ('inList' in c) return test(c.inList.field);
  if ('firstSeen' in c) return c.firstSeen.key.some(test);
  return test(c.field);
}

/** True when any part of the condition reads an agent field: a test, a list lookup or a firstSeen key. */
export function conditionUsesAgentFields(c: Condition): boolean {
  return conditionUsesFields(c, isAgentField);
}

/** True when an exclusion would hide what an agent does: it reads an agent or parent field. */
export function exclusionHidesAgent(c: Condition): boolean {
  return conditionUsesFields(c, deniedForAi);
}
