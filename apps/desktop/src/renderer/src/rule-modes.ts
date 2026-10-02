import type { RuleMode } from '@vigil/core';
import type { EventOutcome, ReplayPreview } from '../../shared/ipc';

// What a rule's modes are called, in one place for the Rules, Agents and
// Activity pages. A detection rule alerts or blocks; a tool rule answers
// Claude Code's pre-flight hook, so its modes are Record, Ask and Deny; and
// the rules Vigil raises itself (probing, the socket check) only alert. No
// React here, so it can be tested on its own.

export interface ModeOption {
  value: RuleMode;
  label: string;
}

/** Detection rules: what Vigil does when one matches. */
export const RULE_MODES: ModeOption[] = [
  { value: 'disabled', label: 'Off' },
  { value: 'shadow', label: 'Shadow' },
  { value: 'alert', label: 'Alert' },
  { value: 'block', label: 'Block' },
];

/** Tool rules: how Claude Code's step is answered. */
export const TOOL_MODES: ModeOption[] = [
  { value: 'disabled', label: 'Off' },
  { value: 'shadow', label: 'Record' },
  { value: 'alert', label: 'Ask' },
  { value: 'block', label: 'Deny' },
];

/** Rules Vigil raises itself. They don't answer a step, so there's no Deny. */
export const RAISED_MODES: ModeOption[] = [
  { value: 'disabled', label: 'Off' },
  { value: 'shadow', label: 'Record' },
  { value: 'alert', label: 'Alert' },
];

/**
 * Rules Vigil raises itself rather than answering a step with. They mirror
 * PREFLIGHT_PROBING_RULE_ID and PREFLIGHT_SOCKET_RULE_ID in @vigil/detection
 * (not imported, to keep it out of the renderer).
 */
export const RAISED_BY_VIGIL: ReadonlySet<string> = new Set([
  'preflight-probing',
  'preflight-socket-tampered',
]);

const labels = (modes: ModeOption[]) =>
  Object.fromEntries(modes.map((m) => [m.value, m.label])) as Record<RuleMode, string>;

export const RULE_MODE_LABEL = labels(RULE_MODES);
export const TOOL_MODE_LABEL = labels(TOOL_MODES);
/** Block is shown as Alert: Vigil raises the same alert in either mode, and stops nothing. */
export const RAISED_MODE_LABEL: Record<RuleMode, string> = {
  ...labels(RAISED_MODES),
  block: 'Alert',
};

interface RuleKinds {
  id: string;
  eventKinds: readonly string[];
}

export const isToolRule = (rule: Pick<RuleKinds, 'eventKinds'>): boolean =>
  rule.eventKinds.includes('agent.tool_request');

/** The modes to offer for a rule. */
export function modesFor(rule: RuleKinds): ModeOption[] {
  if (RAISED_BY_VIGIL.has(rule.id)) return RAISED_MODES;
  return isToolRule(rule) ? TOOL_MODES : RULE_MODES;
}

/** A mode as this rule's page calls it: "Deny" for a tool rule, "Block" for a detection rule. */
export function modeLabel(rule: RuleKinds, mode: RuleMode): string {
  if (RAISED_BY_VIGIL.has(rule.id)) return RAISED_MODE_LABEL[mode];
  return (isToolRule(rule) ? TOOL_MODE_LABEL : RULE_MODE_LABEL)[mode];
}

/**
 * Whether picking `picked` must first be confirmed with a hold: only turning
 * on Block (Deny). Any other pick dismisses a confirmation still showing.
 */
export const confirmsFirst = (current: RuleMode, picked: RuleMode): boolean =>
  picked === 'block' && current !== 'block';

/** The rules that matched an event, with their modes in the words of its page. */
export function matchText(outcome: EventOutcome, toolRequest: boolean, sep: string): string {
  return outcome.matches
    .map((m) => `${m.ruleName} (${toolRequest ? TOOL_MODE_LABEL[m.mode] : m.mode})`)
    .join(sep);
}

/**
 * An agent's rules in the groups its page shows: those on what it starts,
 * those that answer the steps it asks about, and Vigil's own checks, which
 * raise an alert instead of answering. `kindsOf` gives a rule's event kinds,
 * or undefined while the rule list loads.
 */
export function groupAgentRules<R extends { id: string }>(
  rules: readonly R[],
  kindsOf: (id: string) => readonly string[] | undefined,
): { watch: R[]; tool: R[]; raised: R[] } {
  const out = { watch: [] as R[], tool: [] as R[], raised: [] as R[] };
  for (const r of rules) {
    if (RAISED_BY_VIGIL.has(r.id)) out.raised.push(r);
    else if (kindsOf(r.id)?.includes('agent.tool_request')) out.tool.push(r);
    else out.watch.push(r);
  }
  return out;
}

/**
 * Whether a rule as editor JSON is a tool rule: every event kind it reads is
 * a tool request. False when the text doesn't parse.
 */
export function draftIsToolRule(json: string): boolean {
  try {
    const kinds = (JSON.parse(json) as { eventKinds?: unknown } | null)?.eventKinds;
    return (
      Array.isArray(kinds) && kinds.length > 0 && kinds.every((k) => k === 'agent.tool_request')
    );
  } catch {
    return false;
  }
}

const times = (n: number, one: string) => `${n} ${one}${n === 1 ? '' : 's'}`;

/**
 * A replay's summary line. A tool rule's matches are steps Claude Code would
 * have asked about or stopped, with no alert and no program of their own (a
 * Bash step's shell never ran), so it counts steps only.
 */
export function replayLine(r: ReplayPreview, toolRule: boolean): string {
  const span = `in the last 14 days (${r.hitsPerDay.toFixed(1)} a day)`;
  if (toolRule) {
    return `Would have matched ${times(r.hits, 'step')} ${span}. Checked ${r.eventsScanned} events.`;
  }
  return `Would have matched ${times(r.hits, 'time')} ${span}, with ${times(r.popups, 'alert')}, across ${times(r.distinctPrograms, 'program')}. Checked ${r.eventsScanned} events.`;
}

/** One replay sample as a row: what it was about, and the note on its right. */
export function replaySampleRow(
  s: ReplayPreview['samples'][number],
  toolRule: boolean,
): { what: string; note: string } {
  // A tool rule's subject is the command, file or address; its "program" is the tool.
  if (toolRule) return { what: s.subject, note: s.program ?? '' };
  return { what: s.program ?? s.subject, note: s.wouldDo.join(', ') };
}
