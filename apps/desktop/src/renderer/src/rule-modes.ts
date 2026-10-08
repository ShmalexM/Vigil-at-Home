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

const SEVERITY_RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 } as const;
type SeverityName = keyof typeof SEVERITY_RANK;

/**
 * How a rule's new alerts reach the user: a popup, the menu-bar badge, or
 * only the Alerts list. Mirrors notifyLevel in main/alerts.ts (not imported,
 * to keep the main process out of the renderer); a test keeps them in step.
 * A repeat or a burst of the same thing interrupts once either way. While
 * the rule's baseline is still being learned (`learning`), the engine only
 * records its matches, so nothing interrupts.
 */
export function interruptLevel(
  rule: {
    mode: RuleMode;
    fidelity: 'low' | 'medium' | 'high';
    severity: SeverityName;
  },
  learning = false,
): 'popup' | 'badge' | 'silent' | 'none' {
  if (rule.mode === 'disabled' || rule.mode === 'shadow' || learning) return 'none';
  if (rule.mode === 'block') return 'popup';
  const sev = SEVERITY_RANK[rule.severity];
  if (rule.fidelity === 'high' && sev >= SEVERITY_RANK.medium) return 'popup';
  if (rule.fidelity === 'low' && sev < SEVERITY_RANK.medium) return 'silent';
  return 'badge';
}

/** What each interrupt level means, in a word and a sentence. */
export const INTERRUPT_TEXT: Record<'popup' | 'badge' | 'silent', { short: string; long: string }> =
  {
    popup: {
      short: 'Pops up',
      long: 'A new match shows a popup. Repeats of the same thing fold into one.',
    },
    badge: {
      short: 'Badge only',
      long: 'A new match adds to the menu-bar badge, without a popup.',
    },
    silent: {
      short: 'Quiet',
      long: 'A new match only lands in Alerts: no popup, no badge.',
    },
  };

/**
 * The quieter mode to offer on an alert when its rule is too noisy: Alert
 * (Ask) goes to Shadow (Record), which still logs every match in Activity.
 * Undefined when there is nothing safe to offer from the alert itself: a
 * blocking rule is turned down on the Rules page, where the hold and the
 * admin password guard it, and Vigil's own checks only alert.
 */
export function quieterMode(rule: RuleKinds & { mode: RuleMode }): RuleMode | undefined {
  if (RAISED_BY_VIGIL.has(rule.id)) return undefined;
  return rule.mode === 'alert' ? 'shadow' : undefined;
}

export type RuleSort = 'default' | 'matches';

/**
 * The Rules page's list: narrowed by the search text (name, description or
 * id) and the filter, and sorted. `matches` puts the noisiest first, so a
 * rule that keeps interrupting is easy to find; ties keep the original order.
 */
export function visibleRules<
  V extends {
    rule: { id: string; name: string; description: string; mode: RuleMode };
    matches: number;
  },
>(views: readonly V[], opts: { text: string; filter: 'all' | 'review'; sort: RuleSort }): V[] {
  const q = opts.text.trim().toLowerCase();
  const out = views.filter(
    (v) =>
      (opts.filter === 'all' || v.rule.mode === 'shadow') &&
      (!q ||
        v.rule.name.toLowerCase().includes(q) ||
        v.rule.description.toLowerCase().includes(q) ||
        v.rule.id.toLowerCase().includes(q)),
  );
  if (opts.sort === 'matches') {
    return out
      .map((v, i) => ({ v, i }))
      .sort((a, b) => b.v.matches - a.v.matches || a.i - b.i)
      .map(({ v }) => v);
  }
  return out;
}
